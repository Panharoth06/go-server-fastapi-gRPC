-- +goose Up
DROP INDEX IF EXISTS idx_scan_tasks_domain_id;
DROP TABLE IF EXISTS scan_tasks;

-- +goose Down
CREATE TABLE IF NOT EXISTS scan_tasks (
    scan_id UUID PRIMARY KEY,
    user_id UUID NOT NULL,
    domain_id BIGINT NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'pending',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT fk_scan_tasks_domain
        FOREIGN KEY (domain_id)
        REFERENCES domains (domain_id)
        ON UPDATE CASCADE
        ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_scan_tasks_domain_id ON scan_tasks (domain_id);
