package database

import (
	"bufio"
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	dbsqlc "go-server/internal/database/sqlc"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

type Store struct {
	DB      *sql.DB
	Queries *dbsqlc.Queries
}

var (
	initOnce  sync.Once
	initStore *Store
	initErr   error
)

func ConnectAndMigrate() (*Store, error) {
	initOnce.Do(func() {
		initStore, initErr = connectAndMigrate()
	})
	return initStore, initErr
}

func connectAndMigrate() (*Store, error) {
	loadDotEnvIfPresent()

	dsn := postgresDSNFromEnv()
	if dsn == "" {
		return nil, errors.New("database connection is missing: set DATABASE_URL or DB_HOST/DB_PORT/DB_USER/DB_PASSWORD/DB_NAME")
	}

	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, fmt.Errorf("connect postgres: %w", err)
	}

	db.SetMaxIdleConns(5)
	db.SetMaxOpenConns(20)
	db.SetConnMaxLifetime(30 * time.Minute)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("ping postgres: %w", err)
	}

	if err := runMigrations(db); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("run migrations: %w", err)
	}

	return &Store{
		DB:      db,
		Queries: dbsqlc.New(db),
	}, nil
}

func runMigrations(db *sql.DB) error {
	goose.SetBaseFS(migrationsFS)
	if err := goose.SetDialect("postgres"); err != nil {
		return fmt.Errorf("set goose dialect: %w", err)
	}
	if err := goose.Up(db, "migrations"); err != nil {
		return fmt.Errorf("apply goose migrations: %w", err)
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
