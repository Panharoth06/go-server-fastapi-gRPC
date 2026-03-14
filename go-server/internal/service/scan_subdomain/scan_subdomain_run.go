package scansubdomain

import (
	"context"
	"log"
	"sync"
	"sync/atomic"
	"time"

	"go-server/gen/scan_subdomain"

	"github.com/projectdiscovery/goflags"
	httpxrunner "github.com/projectdiscovery/httpx/runner"
	"github.com/projectdiscovery/subfinder/v2/pkg/resolve"
	subfinderrunner"github.com/projectdiscovery/subfinder/v2/pkg/runner"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// This file contains the scan execution pipeline for subdomain scanning.
// It coordinates subfinder discovery, httpx probing, streaming results back
// to the gRPC client, and asynchronous persistence of the discovered data.

const (
	persistQueueSize  = 128
	persistWorkerSize = 8
)

// scanResultPersistTask is the compact work item pushed onto the persistence
// queue after each httpx result is streamed to the client.
type scanResultPersistTask struct {
	subdomain    string
	statusCode   int
	title        string
	ip           string
	isAlive      bool
	technologies []string
}

type streamSender struct {
	cancel context.CancelFunc
	mu     sync.Mutex
	err    error
	stream scan_subdomain.SubdomainScannerService_ScanAndCheckServer
}

// runSubdomainScan executes the full scan lifecycle after the RPC layer has
// already validated input and registered cancellation.
func runSubdomainScan(
	ctx context.Context,
	cancel context.CancelFunc,
	stream scan_subdomain.SubdomainScannerService_ScanAndCheckServer,
	domain string,
	userID string,
	scanID string,
) error {
	subdomains, err := enumerateSubdomains(ctx, domain)
	if err != nil {
		return err
	}
	if len(subdomains) == 0 {
		return nil
	}

	store, err := getStore()
	if err != nil {
		log.Printf("scan_subdomain: database unavailable, skipping persistence: %v", err)
		store = nil
	}

	persistence := newScanPersistence(ctx, store, domain, userID, len(subdomains))
	defer persistence.closeAndWait()

	sender := &streamSender{
		cancel: cancel,
		stream: stream,
	}

	if err := runHTTPXEnumeration(ctx, domain, scanID, subdomains, sender, persistence); err != nil {
		return err
	}

	if err := ctx.Err(); err != nil {
		return canceledScanError()
	}

	if err := sender.finalError(); err != nil {
		if isCanceledError(ctx, err) {
			return canceledScanError()
		}
		return status.Errorf(codes.Internal, "stream send failed: %v", err)
	}

	return nil
}

// enumerateSubdomains runs subfinder for the target domain and deduplicates
// callback results before handing them to the probing stage.
func enumerateSubdomains(ctx context.Context, domain string) ([]string, error) {
	var (
		mu         sync.Mutex
		subdomains []string
		seen       = map[string]struct{}{}
	)

	subfinderOpts := &subfinderrunner.Options{
		Threads:            10,
		Timeout:            30,
		MaxEnumerationTime: 10,
		ResultCallback: func(result *resolve.HostEntry) {
			if result == nil || result.Host == "" {
				return
			}

			mu.Lock()
			if _, ok := seen[result.Host]; !ok {
				seen[result.Host] = struct{}{} //prevent duplicates from multiple subfinder modules
				subdomains = append(subdomains, result.Host)
			}
			mu.Unlock()
		},
	}

	subfinderRunner, err := subfinderrunner.NewRunner(subfinderOpts)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to create subfinder runner: %v", err)
	}

	if _, err := subfinderRunner.EnumerateSingleDomainWithCtx(ctx, domain, nil); err != nil {
		if isCanceledError(ctx, err) {
			return nil, canceledScanError()
		}
		return nil, status.Errorf(codes.Internal, "subfinder failed: %v", err)
	}

	if err := ctx.Err(); err != nil {
		return nil, canceledScanError()
	}

	return subdomains, nil
}

// runHTTPXEnumeration probes each discovered subdomain, streams each response
// back to the caller, and hands successful observations to persistence.
func runHTTPXEnumeration(
	ctx context.Context,
	domain string,
	scanID string,
	subdomains []string,
	sender *streamSender,
	persistence *scanPersistence,
) error {
	httpxOptions := &httpxrunner.Options{
		Methods:         "GET",
		InputTargetHost: goflags.StringSlice(subdomains),
		StatusCode:      true,
		OutputIP:        true,
		TechDetect:      true,
		ExtractTitle:    true,
		Timeout:         10,
		Retries:         2,
		NoColor:         true,
		Silent:          true,
		OnResult: func(r httpxrunner.Result) {
			select {
			case <-ctx.Done():
				return
			default:
			}

			isAlive := !r.Failed && r.StatusCode > 0
			sender.send(&scan_subdomain.ScanAndCheckResponse{
				Subdomain:    r.Input,
				IsAlive:      isAlive,
				StatusCode:   int32(r.StatusCode),
				Title:        r.Title,
				Ip:           r.HostIP,
				Technologies: r.Technologies,
				ScanId:       scanID,
			})
			if sender.finalError() != nil {
				return
			}

			persistence.enqueue(scanResultPersistTask{
				subdomain:    r.Input,
				statusCode:   r.StatusCode,
				title:        r.Title,
				ip:           r.HostIP,
				isAlive:      isAlive,
				technologies: append([]string(nil), r.Technologies...),
			})
		},
	}
	if err := httpxOptions.ValidateOptions(); err != nil {
		return status.Errorf(codes.Internal, "invalid httpx options: %v", err)
	}

	httpxRunner, err := httpxrunner.New(httpxOptions)
	if err != nil {
		return status.Errorf(codes.Internal, "failed to create httpx runner: %v", err)
	}

	var httpxCloseOnce sync.Once
	closeHTTPX := func() {
		httpxCloseOnce.Do(func() {
			httpxRunner.Close()
		})
	}
	defer closeHTTPX()

	httpxStopped := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			closeHTTPX()
		case <-httpxStopped:
		}
	}()

	httpxRunner.RunEnumeration()
	close(httpxStopped)
	return nil
}

// send writes one scan result to the gRPC stream and cancels the scan when the
// stream can no longer accept more messages.
func (s *streamSender) send(resp *scan_subdomain.ScanAndCheckResponse) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.err != nil {
		return
	}

	s.err = s.stream.Send(resp)
	if s.err != nil {
		s.cancel()
	}
}

// finalError returns the first stream send error recorded during enumeration.
func (s *streamSender) finalError() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.err
}

type scanPersistence struct {
	ctx         context.Context
	domain      string
	dropped     uint64
	jobs        chan scanResultPersistTask
	lastDropLog int64
	wg          sync.WaitGroup
}

// newScanPersistence starts the worker pool that saves scan results in the
// background while the main scan keeps streaming data.
func newScanPersistence(
	ctx context.Context,
	store scanResultStore,
	domain string,
	userID string,
	subdomainCount int,
) *scanPersistence {
	p := &scanPersistence{
		ctx:    ctx,
		domain: domain,
	}
	if store == nil {
		return p
	}

	p.jobs = make(chan scanResultPersistTask, persistQueueSize)
	workerCount := persistWorkerSize
	if subdomainCount < workerCount {
		workerCount = subdomainCount
	}
	if workerCount < 1 {
		workerCount = 1
	}

	ensureDomain := newDomainResolver(ctx, store, domain, userID)
	for i := 0; i < workerCount; i++ {
		p.wg.Add(1)
		go func() {
			defer p.wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case task, ok := <-p.jobs:
					if !ok {
						return
					}

					domainID, err := ensureDomain()
					if err != nil {
						log.Printf("scan_subdomain: ensure domain failed (%s): %v", domain, err)
						continue
					}

					if err := saveScanResult(
						ctx,
						store,
						domainID,
						task.subdomain,
						task.statusCode,
						task.title,
						task.ip,
						task.isAlive,
						task.technologies,
					); err != nil && !isCanceledError(ctx, err) {
						log.Printf("scan_subdomain: save result failed (%s): %v", task.subdomain, err)
					}
				}
			}
		}()
	}

	return p
}

// enqueue attempts to queue a persistence task without blocking scan progress;
// when the queue is full it drops work and rate-limits the warning log.
func (p *scanPersistence) enqueue(task scanResultPersistTask) {
	if p.jobs == nil {
		return
	}

	select {
	case <-p.ctx.Done():
		return
	case p.jobs <- task:
	default:
		n := atomic.AddUint64(&p.dropped, 1)
		now := time.Now().UnixNano()
		last := atomic.LoadInt64(&p.lastDropLog)

		if now-last >= int64(2*time.Second) && atomic.CompareAndSwapInt64(&p.lastDropLog, last, now) {
			log.Printf("scan_subdomain: persist queue full, dropped=%d (domain=%s)", n, p.domain)
		}
	}
}

// closeAndWait closes the background queue and waits for persistence workers
// to finish draining accepted tasks.
func (p *scanPersistence) closeAndWait() {
	if p.jobs == nil {
		return
	}
	close(p.jobs)
	p.wg.Wait()
}
