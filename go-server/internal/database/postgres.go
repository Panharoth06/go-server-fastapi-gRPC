package database

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"go-server/internal/models"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func ConnectAndMigrate() (*gorm.DB, error) {
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

	if err := db.SetupJoinTable(&models.Subdomain{}, "Technologies", &models.SubdomainTechnology{}); err != nil {
		return nil, fmt.Errorf("setup join table subdomain->technologies: %w", err)
	}
	if err := db.SetupJoinTable(&models.Technology{}, "Subdomains", &models.SubdomainTechnology{}); err != nil {
		return nil, fmt.Errorf("setup join table technology->subdomains: %w", err)
	}

	if err := migrateInOrder(db); err != nil {
		return nil, fmt.Errorf("auto migrate models: %w", err)
	}

	return db, nil
}

func migrateInOrder(db *gorm.DB) error {
	if err := db.AutoMigrate(&models.Domain{}); err != nil {
		return fmt.Errorf("migrate domains: %w", err)
	}
	if err := db.AutoMigrate(&models.Technology{}); err != nil {
		return fmt.Errorf("migrate technologies: %w", err)
	}
	if err := db.AutoMigrate(&models.Subdomain{}); err != nil {
		return fmt.Errorf("migrate subdomains: %w", err)
	}
	if err := db.AutoMigrate(&models.SubdomainTechnology{}); err != nil {
		return fmt.Errorf("migrate subdomain_technologies: %w", err)
	}

	if err := ensureConstraints(db); err != nil {
		return fmt.Errorf("ensure foreign keys: %w", err)
	}
	return nil
}

func ensureConstraints(db *gorm.DB) error {
	stmts := []string{
		`ALTER TABLE domains DROP CONSTRAINT IF EXISTS fk_subdomains_domain;`,
		`DO $$
		BEGIN
			IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_subdomains_domains') THEN
				ALTER TABLE subdomains
					ADD CONSTRAINT fk_subdomains_domains
					FOREIGN KEY (domain_id) REFERENCES domains(domain_id)
					ON UPDATE CASCADE ON DELETE CASCADE;
			END IF;
		END$$;`,
		`DO $$
		BEGIN
			IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_subdomain_technologies_subdomain') THEN
				ALTER TABLE subdomain_technologies
					ADD CONSTRAINT fk_subdomain_technologies_subdomain
					FOREIGN KEY (subdomain_id) REFERENCES subdomains(subdomain_id)
					ON UPDATE CASCADE ON DELETE CASCADE;
			END IF;
		END$$;`,
		`DO $$
		BEGIN
			IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_subdomain_technologies_technology') THEN
				ALTER TABLE subdomain_technologies
					ADD CONSTRAINT fk_subdomain_technologies_technology
					FOREIGN KEY (technology_id) REFERENCES technologies(technology_id)
					ON UPDATE CASCADE ON DELETE CASCADE;
			END IF;
		END$$;`,
	}

	for _, stmt := range stmts {
		if err := db.Exec(stmt).Error; err != nil {
			return err
		}
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
