-- +goose Up
CREATE TABLE IF NOT EXISTS open_ports (
    open_port_id BIGSERIAL PRIMARY KEY,
    domain_id BIGINT,
    subdomain_id BIGINT,
    port INTEGER NOT NULL,
    service_name VARCHAR(255) NOT NULL DEFAULT '',
    service_version VARCHAR(100) NOT NULL DEFAULT '',
    operating_system VARCHAR(255) NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT chk_open_ports_port_range CHECK (port BETWEEN 1 AND 65535),
    CONSTRAINT chk_open_ports_single_owner CHECK (
        ((domain_id IS NOT NULL)::int + (subdomain_id IS NOT NULL)::int) = 1
    ),
    CONSTRAINT fk_open_ports_domain
        FOREIGN KEY (domain_id)
        REFERENCES domains (domain_id)
        ON UPDATE CASCADE
        ON DELETE CASCADE,
    CONSTRAINT fk_open_ports_subdomain
        FOREIGN KEY (subdomain_id)
        REFERENCES subdomains (subdomain_id)
        ON UPDATE CASCADE
        ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_open_ports_domain_id ON open_ports (domain_id);
CREATE INDEX IF NOT EXISTS idx_open_ports_subdomain_id ON open_ports (subdomain_id);
CREATE UNIQUE INDEX IF NOT EXISTS uq_open_ports_domain_port
    ON open_ports (domain_id, port)
    WHERE subdomain_id IS NULL;
CREATE UNIQUE INDEX IF NOT EXISTS uq_open_ports_subdomain_port
    ON open_ports (subdomain_id, port)
    WHERE subdomain_id IS NOT NULL;

-- +goose Down
DROP INDEX IF EXISTS uq_open_ports_subdomain_port;
DROP INDEX IF EXISTS uq_open_ports_domain_port;
DROP INDEX IF EXISTS idx_open_ports_subdomain_id;
DROP INDEX IF EXISTS idx_open_ports_domain_id;
DROP TABLE IF EXISTS open_ports;
