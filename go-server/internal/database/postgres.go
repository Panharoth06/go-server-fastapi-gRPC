package database

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/go-gormigrate/gormigrate/v2"
	"go-server/internal/models"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

var (
	initOnce sync.Once
	initDB   *gorm.DB
	initErr  error
)

func ConnectAndMigrate() (*gorm.DB, error) {
	initOnce.Do(func() {
		initDB, initErr = connectAndMigrate()
	})
	return initDB, initErr
}

func connectAndMigrate() (*gorm.DB, error) {
	loadDotEnvIfPresent()

	dsn := postgresDSNFromEnv()
	if dsn == "" {
		return nil, errors.New("database connection is missing: set DATABASE_URL or DB_HOST/DB_PORT/DB_USER/DB_PASSWORD/DB_NAME")
	}

	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{
		DisableForeignKeyConstraintWhenMigrating: true,
	})
	if err != nil {
		return nil, fmt.Errorf("connect postgres: %w", err)
	}

	sqlDB, err := db.DB()
	if err != nil {
		return nil, fmt.Errorf("open sql db: %w", err)
	}
	sqlDB.SetMaxIdleConns(5)
	sqlDB.SetMaxOpenConns(20)
	sqlDB.SetConnMaxLifetime(30 * time.Minute)

	if err := runMigrations(db); err != nil {
		return nil, fmt.Errorf("run migrations: %w", err)
	}

	return db, nil
}

func runMigrations(db *gorm.DB) error {
	migrator := gormigrate.New(db, &gormigrate.Options{
		TableName:                 "schema_migrations",
		IDColumnName:              "version",
		IDColumnSize:              255,
		UseTransaction:            true,
		ValidateUnknownMigrations: true,
	}, []*gormigrate.Migration{
		{
			ID: "202602220001_init_schema",
			Migrate: func(tx *gorm.DB) error {
				if err := tx.SetupJoinTable(&models.Subdomain{}, "Technologies", &models.SubdomainTechnology{}); err != nil {
					return fmt.Errorf("setup join table subdomain->technologies: %w", err)
				}
				if err := tx.SetupJoinTable(&models.Technology{}, "Subdomains", &models.SubdomainTechnology{}); err != nil {
					return fmt.Errorf("setup join table technology->subdomains: %w", err)
				}

				if err := tx.AutoMigrate(
					&models.Domain{},
					&models.Technology{},
					&models.Subdomain{},
					&models.SubdomainTechnology{},
				); err != nil {
					return fmt.Errorf("auto migrate schema: %w", err)
				}
				return nil
			},
			Rollback: func(tx *gorm.DB) error {
				return tx.Migrator().DropTable(
					&models.SubdomainTechnology{},
					&models.Subdomain{},
					&models.Technology{},
					&models.Domain{},
				)
			},
		},
	})

	if err := migrator.Migrate(); err != nil {
		return fmt.Errorf("apply gormigrate migrations: %w", err)
	}
	return nil
}

func postgresDSNFromEnv() string {
	if dsn := os.Getenv("DATABASE_URL"); dsn != "" {
		return dsn
	}

	host := os.Getenv("DB_HOST")
	port := envOrDefault("DB_PORT", "5432")
	user := os.Getenv("DB_USER")
	password := os.Getenv("DB_PASSWORD")
	name := os.Getenv("DB_NAME")
	sslMode := envOrDefault("DB_SSLMODE", "disable")
	timeZone := envOrDefault("DB_TIMEZONE", "UTC")

	if host == "" || user == "" || name == "" {
		return ""
	}

	return fmt.Sprintf(
		"host=%s port=%s user=%s password=%s dbname=%s sslmode=%s TimeZone=%s",
		host,
		port,
		user,
		password,
		name,
		sslMode,
		timeZone,
	)
}

func envOrDefault(key string, defaultValue string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return defaultValue
}

func loadDotEnvIfPresent() {
	paths := []string{
		".env",
		filepath.Join("..", ".env"),
	}

	for _, path := range paths {
		if err := loadEnvFile(path); err == nil {
			return
		}
	}
}

func loadEnvFile(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])
		value = strings.Trim(value, `"'`)
		if key == "" {
			continue
		}
		if _, exists := os.LookupEnv(key); exists {
			continue
		}
		_ = os.Setenv(key, value)
	}

	return scanner.Err()
}
