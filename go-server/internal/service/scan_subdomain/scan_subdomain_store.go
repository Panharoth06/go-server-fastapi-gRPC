package service

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"sync"
	"time"

	"go-server/internal/database"
	dbsqlc "go-server/internal/database/sqlc"

	"github.com/google/uuid"
)

// This file contains the database-facing helpers for subdomain scanning.
// It initializes the shared store lazily, resolves the owning domain row,
// and persists scan results plus detected technologies inside transactions.

type scanResultStore interface {
	GetDB() *sql.DB
	GetQueries() *dbsqlc.Queries
}

type storeAdapter struct {
	store *database.Store
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

// newDomainResolver memoizes domain creation for a single scan so concurrent
// persistence workers do not race to create or fetch the same domain row.
func newDomainResolver(
	ctx context.Context,
	store scanResultStore,
	domainName string,
	userID string,
) func() (int64, error) {
	var (
		once     sync.Once
		domainID int64
		err      error
	)

	return func() (int64, error) {
		once.Do(func() {
			domainID, err = getOrCreateDomain(ctx, store, domainName, userID)
		})
		return domainID, err
	}
}

// getOrCreateDomain upserts the scanned domain and stamps the last scanned
// timestamp for the current user/domain pair.
func getOrCreateDomain(ctx context.Context, store scanResultStore, domainName string, userID string) (int64, error) {
	now := time.Now().UTC()
	userUUID, err := parseUserID(userID)
	if err != nil {
		return 0, err
	}

	return store.GetQueries().UpsertDomain(
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

// parseUserID converts the optional user identifier into a UUID while allowing
// empty values for anonymous or system-triggered scans.
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

// saveScanResult persists one discovered subdomain, links its technologies,
// refreshes the parent domain stats, and commits everything atomically.
func saveScanResult(
	ctx context.Context,
	store scanResultStore,
	domainID int64,
	subdomainName string,
	statusCode int,
	title string,
	ip string,
	isAlive bool,
	technologies []string,
) (err error) {
	tx, err := store.GetDB().BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()

	queries := store.GetQueries().WithTx(tx)

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

// parseTechnology splits "name:version" strings emitted by httpx into the
// columns used by the technology tables.
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
