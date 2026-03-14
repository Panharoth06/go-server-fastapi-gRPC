CREATE TABLE IF NOT EXISTS domains (
    domain_id BIGSERIAL PRIMARY KEY,
    user_id UUID NOT NULL,
    name VARCHAR(255) NOT NULL,
    scanned_at TIMESTAMPTZ,
    count_subdomains INTEGER NOT NULL DEFAULT 0,
    CONSTRAINT uq_domains_user_name UNIQUE (user_id, name)
);

CREATE TABLE IF NOT EXISTS technologies (
    technology_id BIGSERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    version VARCHAR(100) NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_technologies_name_version UNIQUE (name, version)
);

CREATE TABLE IF NOT EXISTS subdomains (
    subdomain_id BIGSERIAL PRIMARY KEY,
    domain_id BIGINT NOT NULL,
    name VARCHAR(255) NOT NULL,
    status_code INTEGER NOT NULL DEFAULT 0,
    title_page TEXT NOT NULL DEFAULT '',
    ip VARCHAR(45) NOT NULL DEFAULT '',
    is_alive BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT fk_subdomains_domain
        FOREIGN KEY (domain_id)
        REFERENCES domains (domain_id)
        ON UPDATE CASCADE
        ON DELETE CASCADE,
    CONSTRAINT uq_subdomains_domain_name UNIQUE (domain_id, name)
);

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

CREATE TABLE IF NOT EXISTS subdomain_technologies (
    subdomain_id BIGINT NOT NULL,
    technology_id BIGINT NOT NULL,
    PRIMARY KEY (subdomain_id, technology_id),
    CONSTRAINT fk_subdomain_technologies_subdomain
        FOREIGN KEY (subdomain_id)
        REFERENCES subdomains (subdomain_id)
        ON UPDATE CASCADE
        ON DELETE CASCADE,
    CONSTRAINT fk_subdomain_technologies_technology
        FOREIGN KEY (technology_id)
        REFERENCES technologies (technology_id)
        ON UPDATE CASCADE
        ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_subdomains_domain_id ON subdomains (domain_id);
CREATE INDEX IF NOT EXISTS idx_open_ports_port ON open_ports (port);
CREATE INDEX IF NOT EXISTS idx_domain_open_ports_domain_id ON domain_open_ports (domain_id);
CREATE INDEX IF NOT EXISTS idx_domain_open_ports_open_port_id ON domain_open_ports (open_port_id);
CREATE INDEX IF NOT EXISTS idx_technologies_name_version ON technologies (name, version);
