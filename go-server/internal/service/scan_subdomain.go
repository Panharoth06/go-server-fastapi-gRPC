package service

import (
	"context"
	"errors"
	"fmt"
	"github.com/projectdiscovery/goflags"
	httpxrunner "github.com/projectdiscovery/httpx/runner"
	"github.com/projectdiscovery/subfinder/v2/pkg/resolve"
	"github.com/projectdiscovery/subfinder/v2/pkg/runner"
	"go-server/gen/scan_subdomain"
	"go-server/internal/database"
	"go-server/internal/models"
	"log"
	"strings"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
	"sync"
)

type scanSubdomainServer struct {
	scan_subdomain.UnimplementedSubdomainScannerServer
}

var (
	dbInitOnce sync.Once
	dbInstance *gorm.DB
	dbInitErr  error
)

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

	var (
		mu         sync.Mutex
		subdomains []string
		seen       = map[string]struct{}{}
	)

	subfinderOpts := &runner.Options{
		Threads:            10,
		Timeout:            30,
		MaxEnumerationTime: 10,
		ResultCallback: func(result *resolve.HostEntry) {
			if result == nil || result.Host == "" {
				return
			}
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

	db, err := getDB()
	if err != nil {
		log.Printf("scan_subdomain: database unavailable, skipping persistence: %v", err)
	}

	var (
		domainOnce sync.Once
		domainID   uint
		domainErr  error
	)

	ensureDomain := func() (uint, error) {
		domainOnce.Do(func() {
			domainID, domainErr = getOrCreateDomain(db, req.Domain, req.UserId)
		})
		return domainID, domainErr
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
			mu.Lock()
			defer mu.Unlock()
			if streamErr != nil {
				return
			}
			isAlive := r.StatusCode > 0 && !r.Failed
			resp := &scan_subdomain.ScanResponse{
				Subdomain:    r.Input,
				IsAlive:      isAlive,
				StatusCode:   int32(r.StatusCode),
				Title:        r.Title,
				Ip:           r.HostIP,
				Technologies: r.Technologies,
			}
			streamErr = stream.Send(resp)
			if streamErr != nil || db == nil {
				return
			}

			technologies := append([]string(nil), r.Technologies...)
			subdomain := r.Input
			statusCode := r.StatusCode
			title := r.Title
			ip := r.HostIP

			// Persist each streamed result in a lightweight background task.
			go func() {
				id, err := ensureDomain()
				if err != nil {
					log.Printf("scan_subdomain: ensure domain failed (%s): %v", req.Domain, err)
					return
				}
				if err := saveScanResult(db, id, subdomain, statusCode, title, ip, isAlive, technologies); err != nil {
					log.Printf("scan_subdomain: save result failed (%s): %v", subdomain, err)
				}
			}()
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

	httpxRunner.RunEnumeration()

	if streamErr != nil {
		return status.Errorf(codes.Internal, "stream send failed: %v", streamErr)
	}
	return nil
}

func getDB() (*gorm.DB, error) {
	dbInitOnce.Do(func() {
		dbInstance, dbInitErr = database.ConnectAndMigrate()
	})
	return dbInstance, dbInitErr
}

func getOrCreateDomain(db *gorm.DB, domainName string, userID string) (uint, error) {
	now := time.Now().UTC()
	userUUID, err := parseUserID(userID)
	if err != nil {
		return 0, err
	}

	var domain models.Domain
	err = db.Where("user_id = ? AND name = ?", userUUID, domainName).First(&domain).Error
	if err == nil {
		if err := db.Model(&domain).Update("scanned_at", &now).Error; err != nil {
			return 0, err
		}
		return domain.DomainID, nil
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return 0, err
	}

	domain = models.Domain{
		UserID:          userUUID,
		Name:            domainName,
		ScannedAt:       &now,
		CountSubdomains: 0,
	}
	if err := db.Create(&domain).Error; err != nil {
		return 0, err
	}
	return domain.DomainID, nil
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

func saveScanResult(
	db *gorm.DB,
	domainID uint,
	subdomainName string,
	statusCode int,
	title string,
	ip string,
	isAlive bool,
	technologies []string,
) error {
	return db.Transaction(func(tx *gorm.DB) error {
		var subdomain models.Subdomain
		err := tx.Where("domain_id = ? AND name = ?", domainID, subdomainName).First(&subdomain).Error
		if errors.Is(err, gorm.ErrRecordNotFound) {
			subdomain = models.Subdomain{
				DomainID:   domainID,
				Name:       subdomainName,
				StatusCode: statusCode,
				TitlePage:  title,
				IP:         ip,
				IsAlive:    isAlive,
			}
			if err := tx.Create(&subdomain).Error; err != nil {
				return err
			}
		} else if err != nil {
			return err
		} else {
			if err := tx.Model(&subdomain).Updates(map[string]any{
				"status_code": statusCode,
				"title_page":  title,
				"ip":          ip,
				"is_alive":    isAlive,
			}).Error; err != nil {
				return err
			}
		}

		for _, rawTech := range technologies {
			name, version := parseTechnology(rawTech)
			if name == "" {
				continue
			}

			technology := models.Technology{Name: name, Version: version}
			if err := tx.Where("name = ? AND version = ?", name, version).FirstOrCreate(&technology).Error; err != nil {
				return err
			}

			link := models.SubdomainTechnology{
				SubdomainID:  subdomain.SubdomainID,
				TechnologyID: technology.TechnologyID,
			}
			if err := tx.Clauses(clause.OnConflict{DoNothing: true}).Create(&link).Error; err != nil {
				return err
			}
		}

		now := time.Now().UTC()
		return tx.Model(&models.Domain{}).Where("domain_id = ?", domainID).Updates(map[string]any{
			"scanned_at": &now,
			"count_subdomains": gorm.Expr(
				"(SELECT COUNT(*) FROM subdomains WHERE domain_id = ?)",
				domainID,
			),
		}).Error
	})
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
