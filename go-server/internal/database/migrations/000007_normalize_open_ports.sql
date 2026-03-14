-- +goose Up
ALTER TABLE open_ports RENAME TO open_ports_legacy;

DROP INDEX IF EXISTS idx_open_ports_domain_id;
DROP INDEX IF EXISTS idx_open_ports_subdomain_id;
DROP INDEX IF EXISTS uq_open_ports_domain_port;
DROP INDEX IF EXISTS uq_open_ports_subdomain_port;

CREATE TABLE IF NOT EXISTS open_ports (
    open_port_id BIGSERIAL PRIMARY KEY,
    port INTEGER NOT NULL,
    service_name VARCHAR(255) NOT NULL DEFAULT '',
    service_version VARCHAR(100) NOT NULL DEFAULT '',
    operating_system VARCHAR(255) NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT chk_open_ports_port_range CHECK (port BETWEEN 1 AND 65535),
    CONSTRAINT uq_open_ports_fingerprint UNIQUE (
        port,
        service_name,
        service_version,
        operating_system
    )
);

CREATE TABLE IF NOT EXISTS domain_open_ports (
    domain_id BIGINT NOT NULL,
    open_port_id BIGINT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (domain_id, open_port_id),
    CONSTRAINT fk_domain_open_ports_domain
        FOREIGN KEY (domain_id)
        REFERENCES domains (domain_id)
        ON UPDATE CASCADE
        ON DELETE CASCADE,
    CONSTRAINT fk_domain_open_ports_open_port
        FOREIGN KEY (open_port_id)
        REFERENCES open_ports (open_port_id)
        ON UPDATE CASCADE
        ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_open_ports_port ON open_ports (port);
CREATE INDEX IF NOT EXISTS idx_domain_open_ports_domain_id ON domain_open_ports (domain_id);
CREATE INDEX IF NOT EXISTS idx_domain_open_ports_open_port_id ON domain_open_ports (open_port_id);

INSERT INTO open_ports (
    port,
    service_name,
    service_version,
    operating_system,
    created_at,
    updated_at
)
SELECT
    port,
    service_name,
    service_version,
    operating_system,
    MIN(created_at) AS created_at,
    MAX(updated_at) AS updated_at
FROM open_ports_legacy
GROUP BY port, service_name, service_version, operating_system;

INSERT INTO domain_open_ports (
    domain_id,
    open_port_id,
    created_at
)
SELECT DISTINCT
    COALESCE(opl.domain_id, s.domain_id) AS domain_id,
    op.open_port_id,
    opl.created_at
FROM open_ports_legacy opl
LEFT JOIN subdomains s
    ON s.subdomain_id = opl.subdomain_id
JOIN open_ports op
    ON op.port = opl.port
   AND op.service_name = opl.service_name
   AND op.service_version = opl.service_version
   AND op.operating_system = opl.operating_system
WHERE COALESCE(opl.domain_id, s.domain_id) IS NOT NULL
ON CONFLICT (domain_id, open_port_id) DO NOTHING;

DROP TABLE open_ports_legacy;

-- +goose Down
ALTER TABLE open_ports RENAME TO open_ports_normalized;

DROP INDEX IF EXISTS idx_domain_open_ports_open_port_id;
DROP INDEX IF EXISTS idx_domain_open_ports_domain_id;
DROP INDEX IF EXISTS idx_open_ports_port;
DROP TABLE IF EXISTS domain_open_ports;

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

INSERT INTO open_ports (
    domain_id,
    subdomain_id,
    port,
    service_name,
    service_version,
    operating_system,
    created_at,
    updated_at
)
SELECT
    dop.domain_id,
    NULL,
    op.port,
    op.service_name,
    op.service_version,
    op.operating_system,
    dop.created_at,
    op.updated_at
FROM domain_open_ports dop
JOIN open_ports_normalized op
    ON op.open_port_id = dop.open_port_id
ON CONFLICT DO NOTHING;

DROP TABLE open_ports_normalized;
