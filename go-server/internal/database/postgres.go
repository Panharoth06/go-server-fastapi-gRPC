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

	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/postgres"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	_ "github.com/jackc/pgx/v5/stdlib"
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
	sourceDriver, err := iofs.New(migrationsFS, "migrations")
	if err != nil {
		return fmt.Errorf("create iofs migration source: %w", err)
	}

	// Use a dedicated sql.Conn for migrations so closing migrate does not close the shared *sql.DB.
	ctx := context.Background()
	conn, err := db.Conn(ctx)
	if err != nil {
		return fmt.Errorf("create postgres migration connection: %w", err)
	}

	databaseDriver, err := postgres.WithConnection(ctx, conn, &postgres.Config{
		MigrationsTable: "schema_migrations_sqlc",
	})
	if err != nil {
		_ = conn.Close()
		return fmt.Errorf("create postgres migration driver: %w", err)
	}

	m, err := migrate.NewWithInstance("iofs", sourceDriver, "postgres", databaseDriver)
	if err != nil {
		return fmt.Errorf("create migrate instance: %w", err)
	}

	if err := m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		_ = closeMigrator(m)
		return fmt.Errorf("apply migrations: %w", err)
	}

	if err := closeMigrator(m); err != nil {
		return err
	}

	return nil
}

func closeMigrator(m *migrate.Migrate) error {
	srcErr, dbErr := m.Close()
	if srcErr != nil {
		return fmt.Errorf("close migration source: %w", srcErr)
	}
	if dbErr != nil {
		return fmt.Errorf("close migration database driver: %w", dbErr)
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
