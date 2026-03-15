package scanport

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"go-server/internal/database"
	dbsqlc "go-server/internal/database/sqlc"

	"github.com/google/uuid"
)

// This file contains the database-facing helpers for port scanning.
// It initializes the shared store lazily, resolves the scanned host into
// a domain row, and persists open-port fingerprints in the background.

const (
	portPersistQueueSize  = 128
	portPersistWorkerSize = 4
)

type scanResultStore interface {
	GetDB() *sql.DB
	GetQueries() *dbsqlc.Queries
}

type storeAdapter struct {
	store *database.Store
}

type openPortPersistTask struct {
	port            int
	serviceName     string
	serviceVersion  string
	operatingSystem string
}

type portScanPersistence struct {
	ctx         context.Context
	host        string
	dropped     uint64
	jobs        chan openPortPersistTask
	lastDropLog int64
	wg          sync.WaitGroup
}

var (
	dbInitOnce sync.Once
	dbInitErr  error
	dbStore    *database.Store
)

// getStore initializes the database connection once and returns a narrow
// adapter used by the scan pipeline.
func getStore() (scanResultStore, error) {
	dbInitOnce.Do(func() {
		dbStore, dbInitErr = database.ConnectAndMigrate()
	})
	// Return the init error when the store could not be created.
	if dbStore == nil {
		return nil, dbInitErr
	}
	return storeAdapter{store: dbStore}, dbInitErr
}

// GetDB exposes the underlying sql.DB so persistence helpers can open
// transactions without depending on the full database.Store type.
func (s storeAdapter) GetDB() *sql.DB {
	return s.store.DB
}

// GetQueries exposes the generated sqlc query set used for upserts and joins.
func (s storeAdapter) GetQueries() *dbsqlc.Queries {
	return s.store.Queries
}

// newDomainResolver memoizes domain creation for a single host so concurrent
// persistence workers do not race to create or fetch the same domain row.
func newDomainResolver(
	ctx context.Context,
	store scanResultStore,
	host string,
	userID string,
) func() (int64, error) {
	var (
		once     sync.Once
		domainID int64
		err      error
	)

	return func() (int64, error) {
		once.Do(func() {
			domainID, err = getOrCreateDomain(ctx, store, host, userID)
		})
		return domainID, err
	}
}

// newPortScanPersistence starts a worker pool that saves port-scan results
// without blocking the gRPC stream.
func newPortScanPersistence(
	ctx context.Context,
	store scanResultStore,
	host string,
	userID string,
	expectedResultCount int,
) *portScanPersistence {
	p := &portScanPersistence{
		ctx:  ctx,
		host: host,
	}
	// Persistence is optional; nil store means scan-only mode.
	if store == nil {
		return p
	}

	p.jobs = make(chan openPortPersistTask, portPersistQueueSize)
	workerCount := portPersistWorkerSize
	// Avoid creating more workers than expected tasks.
	if expectedResultCount < workerCount {
		workerCount = expectedResultCount
	}
	// Always keep at least one worker when queue is enabled.
	if workerCount < 1 {
		workerCount = 1
	}

	ensureDomain := newDomainResolver(ctx, store, host, userID)
	for i := 0; i < workerCount; i++ {
		p.wg.Add(1)
		go func() {
			defer p.wg.Done()
			for {
				select {
				// Stop worker when request context is canceled.
				case <-ctx.Done():
					return
				case task, ok := <-p.jobs:
					// Channel close means no more tasks to process.
					if !ok {
						return
					}

					domainID, err := ensureDomain()
					// Skip persistence for this task if host/domain lookup failed.
					if err != nil {
						log.Printf("scan_port: ensure host failed (%s): %v", host, err)
						continue
					}

					// Persist failures are logged but do not stop scanning.
					if err := saveOpenPortResult(ctx, store, domainID, task); err != nil && !isCanceledError(ctx, err) {
						log.Printf("scan_port: save result failed (%s:%d): %v", host, task.port, err)
					}
				}
			}
		}()
	}

	return p
}

// enqueue attempts to queue a persistence task without blocking scan progress;
// when the queue is full it drops work and rate-limits the warning log.
func (p *portScanPersistence) enqueue(task openPortPersistTask) {
	// No queue means persistence was disabled for this run.
	if p.jobs == nil {
		return
	}

	select {
	// Skip enqueue after cancellation.
	case <-p.ctx.Done():
		return
	case p.jobs <- task:
	default:
		// Queue is full; drop task to keep scan stream responsive.
		n := atomic.AddUint64(&p.dropped, 1)
		now := time.Now().UnixNano()
		last := atomic.LoadInt64(&p.lastDropLog)

		if now-last >= int64(2*time.Second) && atomic.CompareAndSwapInt64(&p.lastDropLog, last, now) {
			log.Printf("scan_port: persist queue full, dropped=%d (host=%s)", n, p.host)
		}
	}
}

// closeAndWait closes the background queue and waits for persistence workers
// to finish draining accepted tasks.
func (p *portScanPersistence) closeAndWait() {
	// No queue means there are no background workers to join.
	if p.jobs == nil {
		return
	}
	close(p.jobs)
	p.wg.Wait()
}

// getOrCreateDomain upserts the scanned host as a domain row and stamps the
// last scanned timestamp for the current user/domain pair.
func getOrCreateDomain(ctx context.Context, store scanResultStore, host string, userID string) (int64, error) {
	now := time.Now().UTC()
	userUUID, err := parseUserID(userID)
	// Reject malformed UUIDs before hitting the database.
	if err != nil {
		return 0, err
	}

	return store.GetQueries().UpsertDomain(
		ctx,
		dbsqlc.UpsertDomainParams{
			UserID: userUUID,
			Name:   host,
			ScannedAt: sql.NullTime{
				Time:  now,
				Valid: true,
			},
		},
	)
}

// parseUserID converts the optional user identifier into a UUID while allowing
// empty values for anonymous or system-triggered scans.
func parseUserID(raw string) (uuid.UUID, error) {
	// Empty user ID is allowed for system/anonymous scans.
	if strings.TrimSpace(raw) == "" {
		return uuid.Nil, nil
	}

	id, err := uuid.Parse(raw)
	// Invalid UUID format is returned as a wrapped validation error.
	if err != nil {
		return uuid.Nil, fmt.Errorf("invalid user_id %q: %w", raw, err)
	}
	return id, nil
}

// saveOpenPortResult persists one open-port fingerprint and links it to the
// scanned host inside a single transaction.
func saveOpenPortResult(
	ctx context.Context,
	store scanResultStore,
	domainID int64,
	task openPortPersistTask,
) (err error) {
	tx, err := store.GetDB().BeginTx(ctx, nil)
	// If transaction cannot start, persistence cannot continue.
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()

	queries := store.GetQueries().WithTx(tx)

	openPortID, err := queries.UpsertOpenPort(ctx, dbsqlc.UpsertOpenPortParams{
		Port:            int32(task.port),
		ServiceName:     task.serviceName,
		ServiceVersion:  task.serviceVersion,
		OperatingSystem: task.operatingSystem,
	})
	// Upsert must succeed before relation rows can be created.
	if err != nil {
		return err
	}

	err = queries.LinkDomainOpenPort(ctx, dbsqlc.LinkDomainOpenPortParams{
		DomainID:   domainID,
		OpenPortID: openPortID,
	})
	// Relation link failure aborts the whole transaction.
	if err != nil {
		return err
	}

	// Avoid committing data when the request is already canceled.
	if err := ctx.Err(); err != nil {
		_ = tx.Rollback()
		return err
	}

	err = tx.Commit()
	return err
}
