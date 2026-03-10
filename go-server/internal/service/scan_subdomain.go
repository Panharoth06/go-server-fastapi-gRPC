package service

import (
	"context"
	"database/sql"
	"errors"
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

type activeScan struct {
	userID     string
	cancel     context.CancelFunc
	cancelOnce sync.Once
}

var (
	dbInitOnce         sync.Once
	dbStore            *database.Store
	dbInitErr          error
	activeSubdomainMap sync.Map
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
	if req == nil {
		return status.Error(codes.InvalidArgument, "request cannot be empty")
	}

	domain := strings.TrimSpace(req.Domain)
	if domain == "" {
		return status.Error(codes.InvalidArgument, "domain cannot be empty")
	}

	userID := strings.TrimSpace(req.UserId)
	scanID := normalizeScanID(req.ScanId)
	if scanID == "" {
		scanID = uuid.NewString()
	}

	ctx := stream.Context()
	ctx, cancel := context.WithCancel(ctx)
	if err := registerActiveScan(scanID, userID, cancel); err != nil {
		cancel()
		return err
	}
	defer func() {
		unregisterActiveScan(scanID)
		cancel()
	}()

	var (
		subdomainsMu sync.Mutex
		streamMu     sync.Mutex
		subdomains   []string
		seen         = map[string]struct{}{}
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

			subdomainsMu.Lock()
			if _, ok := seen[result.Host]; !ok {
				seen[result.Host] = struct{}{}
				subdomains = append(subdomains, result.Host)
			}
			subdomainsMu.Unlock()
		},
	}

	subfinderRunner, err := runner.NewRunner(subfinderOpts)
	if err != nil {
		return status.Errorf(codes.Internal, "failed to create subfinder runner: %v", err)
	}
	if _, err := subfinderRunner.EnumerateSingleDomainWithCtx(ctx, domain, nil); err != nil {
		if isCanceledError(ctx, err) {
			return canceledScanError()
		}
		return status.Errorf(codes.Internal, "subfinder failed: %v", err)
	}
	if err := ctx.Err(); err != nil {
		return canceledScanError()
	}

	if len(subdomains) == 0 {
		return nil
	}

	store, err := getStore()
	if err != nil {
		log.Printf("scan_subdomain: database unavailable, skipping persistence: %v", err)
		store = nil
	}

	var (
		domainOnce sync.Once
		domainID   int64
		domainErr  error
	)
	ensureDomain := func() (int64, error) {
		domainOnce.Do(func() {
			domainID, domainErr = getOrCreateDomain(ctx, store, domain, userID)
		})
		return domainID, domainErr
	}

	var (
		persistWG   sync.WaitGroup
		persistJobs chan scanResultPersistTask
	)
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
						return
					case task, ok := <-persistJobs:
						if !ok {
							return
						}

						id, err := ensureDomain()
						if err != nil {
							log.Printf("scan_subdomain: ensure domain failed (%s): %v", domain, err)
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
						); err != nil && !isCanceledError(ctx, err) {
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
		OnResult: func(r httpxrunner.Result) {
			select {
			case <-ctx.Done():
				return
			default:
			}

			isAlive := !r.Failed && r.StatusCode > 0
			resp := &scan_subdomain.ScanResponse{
				Subdomain:    r.Input,
				IsAlive:      isAlive,
				StatusCode:   int32(r.StatusCode),
				Title:        r.Title,
				Ip:           r.HostIP,
				Technologies: r.Technologies,
				ScanId:       scanID,
			}

			streamMu.Lock()
			if streamErr != nil {
				streamMu.Unlock()
				return
			}
			streamErr = stream.Send(resp)
			if streamErr != nil {
				streamMu.Unlock()
				cancel()
				return
			}
			streamMu.Unlock()

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
			default:
				n := atomic.AddUint64(&dropped, 1)
				now := time.Now().UnixNano()
				last := atomic.LoadInt64(&lastDropLog)

				if now-last >= int64(2*time.Second) && atomic.CompareAndSwapInt64(&lastDropLog, last, now) {
					log.Printf("scan_subdomain: persist queue full, dropped=%d (domain=%s)", n, domain)
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

	if persistJobs != nil {
		close(persistJobs)
		persistWG.Wait()
	}

	if err := ctx.Err(); err != nil {
		return canceledScanError()
	}

	streamMu.Lock()
	finalStreamErr := streamErr
	streamMu.Unlock()
	if finalStreamErr != nil {
		if isCanceledError(ctx, finalStreamErr) {
			return canceledScanError()
		}
		return status.Errorf(codes.Internal, "stream send failed: %v", finalStreamErr)
	}
	return nil
}

func (s *scanSubdomainServer) CancelScan(
	ctx context.Context,
	req *scan_subdomain.CancelScanRequest,
) (*scan_subdomain.CancelScanResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "request cannot be empty")
	}

	scanID := normalizeScanID(req.ScanId)
	if scanID == "" {
		return nil, status.Error(codes.InvalidArgument, "scan_id cannot be empty")
	}

	scan, ok := lookupActiveScan(scanID)
	if !ok {
		return nil, status.Error(codes.NotFound, "scan not found")
	}

	requestUserID := strings.TrimSpace(req.UserId)
	if scan.userID != "" && requestUserID != scan.userID {
		return nil, status.Error(codes.PermissionDenied, "scan belongs to another user")
	}

	scan.cancelOnce.Do(scan.cancel)
	return &scan_subdomain.CancelScanResponse{
		ScanId:    scanID,
		Cancelled: true,
		Message:   "cancel requested",
	}, nil
}

func getStore() (*database.Store, error) {
	dbInitOnce.Do(func() {
		dbStore, dbInitErr = database.ConnectAndMigrate()
	})
	return dbStore, dbInitErr
}

func getOrCreateDomain(ctx context.Context, store *database.Store, domainName string, userID string) (int64, error) {
	now := time.Now().UTC()
	userUUID, err := parseUserID(userID)
	if err != nil {
		return 0, err
	}

	return store.Queries.UpsertDomain(
		ctx,
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

func registerActiveScan(scanID string, userID string, cancel context.CancelFunc) error {
	scan := &activeScan{
		userID: strings.TrimSpace(userID),
		cancel: cancel,
	}
	if _, loaded := activeSubdomainMap.LoadOrStore(scanID, scan); loaded {
		return status.Error(codes.AlreadyExists, "scan_id is already in use")
	}
	return nil
}

func unregisterActiveScan(scanID string) {
	activeSubdomainMap.Delete(scanID)
}

func lookupActiveScan(scanID string) (*activeScan, bool) {
	value, ok := activeSubdomainMap.Load(scanID)
	if !ok {
		return nil, false
	}

	scan, ok := value.(*activeScan)
	return scan, ok
}

func normalizeScanID(raw string) string {
	return strings.TrimSpace(raw)
}

func isCanceledError(ctx context.Context, err error) bool {
	if err == nil {
		return ctx.Err() != nil
	}

	return ctx.Err() != nil ||
		errors.Is(err, context.Canceled) ||
		errors.Is(err, context.DeadlineExceeded)
}

func canceledScanError() error {
	return status.Error(codes.Canceled, "scan canceled")
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
	if err != nil {
		return err
	}

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
