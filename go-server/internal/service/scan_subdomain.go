package service

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"go-server/gen/scan_subdomain"
	"go-server/internal/database"
	dbsqlc "go-server/internal/database/sqlc"

	"github.com/google/uuid"
	"github.com/projectdiscovery/goflags"
	httpxrunner "github.com/projectdiscovery/httpx/runner"
	"github.com/projectdiscovery/subfinder/v2/pkg/resolve"
	"github.com/projectdiscovery/subfinder/v2/pkg/runner"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type scanSubdomainServer struct {
	scan_subdomain.UnimplementedSubdomainScannerServer
}

var (
	dbInitOnce sync.Once
	dbStore    *database.Store
	dbInitErr  error
)

const (
	persistQueueSize  = 128
	persistWorkerSize = 8
)

type scanResultPersistTask struct {
	subdomain    string
	statusCode   int
	title        string
	ip           string
	isAlive      bool
	technologies []string
}

func NewScanSubdomainServer() scan_subdomain.SubdomainScannerServer {
	return &scanSubdomainServer{}
}

func (s *scanSubdomainServer) ScanAndCheck(
	req *scan_subdomain.ScanRequest,
	stream scan_subdomain.SubdomainScanner_ScanAndCheckServer,
) error {
	if req == nil || req.Domain == "" {
		return status.Error(codes.InvalidArgument, "domain cannot be empty")
	}

	ctx := stream.Context()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var (
		mu         sync.Mutex // mu is used because the callback will be called from multiple goroutines inside subfinder.
		subdomains []string
		seen       = map[string]struct{}{} // seen is a set (Go doesn’t have a native set type; map[string]struct{} is the idiom).
	)

	var (
		dropped     uint64
		lastDropLog int64
	)

	subfinderOpts := &runner.Options{
		Threads:            10,
		Timeout:            30,
		MaxEnumerationTime: 10,
		ResultCallback: func(result *resolve.HostEntry) {
			if result == nil || result.Host == "" {
				return
			}

			/*
				Why lock?
				Appending to a slice and writing to a map are not safe concurrently.
				Analogy: seen + subdomains are a shared notebook. mu is the rule: “only one person writes in the notebook at a time.”
			*/
			mu.Lock()
			if _, ok := seen[result.Host]; !ok {
				seen[result.Host] = struct{}{}
				subdomains = append(subdomains, result.Host)
			}
			mu.Unlock()
		},
	}

	subfinderRunner, err := runner.NewRunner(subfinderOpts)
	if err != nil {
		return status.Errorf(codes.Internal, "failed to create subfinder runner: %v", err)
	}
	if _, err := subfinderRunner.EnumerateSingleDomainWithCtx(context.Background(), req.Domain, nil); err != nil {
		return status.Errorf(codes.Internal, "subfinder failed: %v", err)
	}

	if len(subdomains) == 0 {
		return nil
	}

	store, err := getStore()
	if err != nil {
		log.Printf("scan_subdomain: database unavailable, skipping persistence: %v", err)
		store = nil
	}

	// “Create domain once” with another sync.Once
	var (
		domainOnce sync.Once
		domainID   int64
		domainErr  error
	)
	/*
		Why?
		Many results come in (for many subdomains). You only want to upsert the domain row one time.
		Analogy: “Create the folder once; then file many documents into it.”
	*/
	ensureDomain := func() (int64, error) {
		domainOnce.Do(func() {
			domainID, domainErr = getOrCreateDomain(store, req.Domain, req.UserId)
		})
		return domainID, domainErr
	}

	var (
		persistWG   sync.WaitGroup
		persistJobs chan scanResultPersistTask
	)
	//	Persistence worker pool (channels + goroutines + WaitGroup)
	/*
		Only if store != nil:
		- create buffered channel persistJobs
		- start workerCount goroutines
		- each worker reads tasks from the channel and saves to DB
		- later close channel and wait for workers to finish
	*/
	if store != nil {
		persistJobs = make(chan scanResultPersistTask, persistQueueSize)
		workerCount := persistWorkerSize
		if len(subdomains) < workerCount {
			workerCount = len(subdomains)
		}
		if workerCount < 1 {
			workerCount = 1
		}

		for i := 0; i < workerCount; i++ {
			persistWG.Add(1)
			go func() {
				defer persistWG.Done()
				for {
					select {
					case <-ctx.Done():
						return // stop immediately on client cancel
					case task, ok := <-persistJobs:
						if !ok {
							return // channel closed normally
						}

						id, err := ensureDomain()
						if err != nil {
							log.Printf("scan_subdomain: ensure domain failed (%s): %v", req.Domain, err)
							continue
						}

						if err := saveScanResult(
							ctx,
							store,
							id,
							task.subdomain,
							task.statusCode,
							task.title,
							task.ip,
							task.isAlive,
							task.technologies,
						); err != nil {
							log.Printf("scan_subdomain: save result failed (%s): %v", task.subdomain, err)
						}
					}
				}
			}()
		}
	}

	var streamErr error
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
		// Streaming results back to client: httpx OnResult
		OnResult: func(r httpxrunner.Result) {
			select {
			case <-ctx.Done():
				return
			default:
			}

			// Treat only 2xx/3xx responses as alive.
			isAlive := !r.Failed && r.StatusCode > 0
			resp := &scan_subdomain.ScanResponse{
				Subdomain:    r.Input,
				IsAlive:      isAlive,
				StatusCode:   int32(r.StatusCode),
				Title:        r.Title,
				Ip:           r.HostIP,
				Technologies: r.Technologies,
			}

			/*
				Why lock here too?
				Because OnResult can be called concurrently, and:
				we’re updating streamErr
				we’re calling stream.Send, and many gRPC streams are not safe to call concurrently from multiple goroutines.
				So they serialize sending with a mutex.
				- Analogy: one microphone on stage — only one speaker at a time.

				Why store streamErr and stop sending later?
				Once sending fails (client disconnected, network error), continuing to send is pointless and may spam logs.
			*/

			/*
				1. Goroutine A locks mu
				2. checks streamErr (it’s nil)
				3. does stream.Send(...) → suppose it fails → sets streamErr = errA
				4. unlocks

				Then later:

				1. Goroutine B locks mu
				2. checks streamErr (now it’s errA, not nil)
				3. returns immediately and does not call stream.Send and does not overwrite streamErr
				So:
				streamErr becomes non-nil once, on the first failure.
				After that, everyone stops sending.
			*/
			mu.Lock()
			if streamErr != nil {
				mu.Unlock()
				return
			}
			streamErr = stream.Send(resp)
			if streamErr != nil {
				mu.Unlock()
				cancel() // stop workers + stop future work. That makes client disconnect immediately propagate.
				return
			}
			mu.Unlock()

			if persistJobs == nil {
				return
			}

			task := scanResultPersistTask{
				subdomain:    r.Input,
				statusCode:   r.StatusCode,
				title:        r.Title,
				ip:           r.HostIP,
				isAlive:      isAlive,
				technologies: append([]string(nil), r.Technologies...),
			}

			select {
			case <-ctx.Done():
				return
			case persistJobs <- task:
				// queued ()
				//	This guarantees: once cancelled, you never block trying to enqueue.
				// enqueue means: To add an item to a queue.
			default:
				n := atomic.AddUint64(&dropped, 1)

				now := time.Now().UnixNano()
				last := atomic.LoadInt64(&lastDropLog)

				if now-last >= int64(2*time.Second) {
					if atomic.CompareAndSwapInt64(&lastDropLog, last, now) {
						log.Printf("scan_subdomain: persist queue full, dropped=%d (domain=%s)", n, req.Domain)
					}
				}
			}

		},
	}
	if err := httpxOptions.ValidateOptions(); err != nil {
		return status.Errorf(codes.Internal, "invalid httpx options: %v", err)
	}

	httpxRunner, err := httpxrunner.New(httpxOptions)
	if err != nil {
		return status.Errorf(codes.Internal, "failed to create httpx runner: %v", err)
	}
	defer httpxRunner.Close()

	// Run httpx, then shut down cleanly
	/*
		This is orderly shutdown:
		- run scan
		- stop job queue
		- wait for DB workers to finish
		- return stream error if any
	*/
	httpxRunner.RunEnumeration()

	if persistJobs != nil {
		close(persistJobs)
		persistWG.Wait()
	}

	mu.Lock()
	finalStreamErr := streamErr
	mu.Unlock()
	if finalStreamErr != nil {
		return status.Errorf(codes.Internal, "stream send failed: %v", finalStreamErr)
	}
	return nil
}

func getStore() (*database.Store, error) {
	dbInitOnce.Do(func() {
		dbStore, dbInitErr = database.ConnectAndMigrate()
	})
	return dbStore, dbInitErr
}

func getOrCreateDomain(store *database.Store, domainName string, userID string) (int64, error) {
	now := time.Now().UTC()
	userUUID, err := parseUserID(userID)
	if err != nil {
		return 0, err
	}

	return store.Queries.UpsertDomain(
		context.Background(),
		dbsqlc.UpsertDomainParams{
			UserID: userUUID,
			Name:   domainName,
			ScannedAt: sql.NullTime{
				Time:  now,
				Valid: true,
			},
		},
	)
}

func parseUserID(raw string) (uuid.UUID, error) {
	if strings.TrimSpace(raw) == "" {
		return uuid.Nil, nil
	}

	id, err := uuid.Parse(raw)
	if err != nil {
		return uuid.Nil, fmt.Errorf("invalid user_id %q: %w", raw, err)
	}
	return id, nil
}

/*
DB write logic: transaction + upserts + linking tech

saveScanResult does:
- begin transaction
- upsert subdomain row
for each technology string:
- parse name:version
- upsert technology row
- link subdomain ↔ tech (join table)
- refresh domain scan stats
- commit

If any step fails, it rolls back.
*/
func saveScanResult(
	ctx context.Context,
	store *database.Store,
	domainID int64,
	subdomainName string,
	statusCode int,
	title string,
	ip string,
	isAlive bool,
	technologies []string,
) (err error) {
	tx, err := store.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()

	queries := store.Queries.WithTx(tx)

	subdomainID, err := queries.UpsertSubdomain(ctx, dbsqlc.UpsertSubdomainParams{
		DomainID:   domainID,
		Name:       subdomainName,
		StatusCode: int32(statusCode),
		TitlePage:  title,
		Ip:         ip,
		IsAlive:    isAlive,
	})
	if err != nil {
		return err
	}

	for _, rawTech := range technologies {
		name, version := parseTechnology(rawTech)
		if name == "" {
			continue
		}
		technologyID, err := queries.UpsertTechnology(ctx, dbsqlc.UpsertTechnologyParams{
			Name:    name,
			Version: version,
		})
		if err != nil {
			return err
		}

		err = queries.LinkSubdomainTechnology(ctx, dbsqlc.LinkSubdomainTechnologyParams{
			SubdomainID:  subdomainID,
			TechnologyID: technologyID,
		})
		if err != nil {
			return err
		}
	}

	now := time.Now().UTC()
	err = queries.RefreshDomainScanStats(ctx, dbsqlc.RefreshDomainScanStatsParams{
		DomainID: domainID,
		ScannedAt: sql.NullTime{
			Time:  now,
			Valid: true,
		},
	})

	// CRITICAL: don't commit if cancelled
	/*
		Even if the client cancels during the DB work, our queries might still succeed.
		Without this check, we'd still Commit() and persist data — which contradicts “when cancel,
		don’t save anything”.
	*/
	if err := ctx.Err(); err != nil {
		_ = tx.Rollback()
		return err
	}

	err = tx.Commit()
	return err
}

func parseTechnology(raw string) (string, string) {
	clean := strings.TrimSpace(raw)
	if clean == "" {
		return "", ""
	}

	parts := strings.SplitN(clean, ":", 2)
	if len(parts) == 2 {
		return strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
	}
	return clean, ""
}
