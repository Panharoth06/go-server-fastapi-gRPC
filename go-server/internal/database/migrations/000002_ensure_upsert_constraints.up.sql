-- Ensure ON CONFLICT targets exist on older local databases where tables
-- may have been created before unique constraints were introduced.
-- This migration also deduplicates existing rows so unique constraints can be added.

-- 1) Merge duplicate domains by (user_id, name) and keep the most recent row.
WITH ranked AS (
    SELECT
        domain_id,
        FIRST_VALUE(domain_id) OVER (
            PARTITION BY user_id, name
            ORDER BY domain_id DESC
        ) AS keep_id,
        ROW_NUMBER() OVER (
            PARTITION BY user_id, name
            ORDER BY domain_id DESC
        ) AS rn
    FROM domains
),
dups AS (
    SELECT domain_id AS dup_id, keep_id
    FROM ranked
    WHERE rn > 1
)
UPDATE subdomains s
SET domain_id = d.keep_id
FROM dups d
WHERE s.domain_id = d.dup_id;

WITH ranked AS (
    SELECT
        domain_id,
        FIRST_VALUE(domain_id) OVER (
            PARTITION BY user_id, name
            ORDER BY domain_id DESC
        ) AS keep_id,
        ROW_NUMBER() OVER (
            PARTITION BY user_id, name
            ORDER BY domain_id DESC
        ) AS rn
    FROM domains
),
dups AS (
    SELECT domain_id AS dup_id
    FROM ranked
    WHERE rn > 1
)
DELETE FROM domains d
USING dups
WHERE d.domain_id = dups.dup_id;

-- 2) Merge duplicate subdomains by (domain_id, name).
WITH ranked AS (
    SELECT
        subdomain_id,
        FIRST_VALUE(subdomain_id) OVER (
            PARTITION BY domain_id, name
            ORDER BY updated_at DESC, created_at DESC, subdomain_id DESC
        ) AS keep_id,
        ROW_NUMBER() OVER (
            PARTITION BY domain_id, name
            ORDER BY updated_at DESC, created_at DESC, subdomain_id DESC
        ) AS rn
    FROM subdomains
),
dups AS (
    SELECT subdomain_id AS dup_id, keep_id
    FROM ranked
    WHERE rn > 1
)
INSERT INTO subdomain_technologies (subdomain_id, technology_id)
SELECT d.keep_id, st.technology_id
FROM dups d
JOIN subdomain_technologies st
  ON st.subdomain_id = d.dup_id
ON CONFLICT (subdomain_id, technology_id) DO NOTHING;

WITH ranked AS (
    SELECT
        subdomain_id,
        FIRST_VALUE(subdomain_id) OVER (
            PARTITION BY domain_id, name
            ORDER BY updated_at DESC, created_at DESC, subdomain_id DESC
        ) AS keep_id,
        ROW_NUMBER() OVER (
            PARTITION BY domain_id, name
            ORDER BY updated_at DESC, created_at DESC, subdomain_id DESC
        ) AS rn
    FROM subdomains
),
dups AS (
    SELECT subdomain_id AS dup_id
    FROM ranked
    WHERE rn > 1
)
DELETE FROM subdomains s
USING dups
WHERE s.subdomain_id = dups.dup_id;

-- 3) Merge duplicate technologies by (name, version).
WITH ranked AS (
    SELECT
        technology_id,
        FIRST_VALUE(technology_id) OVER (
            PARTITION BY name, version
            ORDER BY updated_at DESC, created_at DESC, technology_id DESC
        ) AS keep_id,
        ROW_NUMBER() OVER (
            PARTITION BY name, version
            ORDER BY updated_at DESC, created_at DESC, technology_id DESC
        ) AS rn
    FROM technologies
),
dups AS (
    SELECT technology_id AS dup_id, keep_id
    FROM ranked
    WHERE rn > 1
)
INSERT INTO subdomain_technologies (subdomain_id, technology_id)
SELECT st.subdomain_id, d.keep_id
FROM dups d
JOIN subdomain_technologies st
  ON st.technology_id = d.dup_id
ON CONFLICT (subdomain_id, technology_id) DO NOTHING;

WITH ranked AS (
    SELECT
        technology_id,
        FIRST_VALUE(technology_id) OVER (
            PARTITION BY name, version
            ORDER BY updated_at DESC, created_at DESC, technology_id DESC
        ) AS keep_id,
        ROW_NUMBER() OVER (
            PARTITION BY name, version
            ORDER BY updated_at DESC, created_at DESC, technology_id DESC
        ) AS rn
    FROM technologies
),
dups AS (
    SELECT technology_id AS dup_id
    FROM ranked
    WHERE rn > 1
)
DELETE FROM technologies t
USING dups
WHERE t.technology_id = dups.dup_id;

-- 4) Ensure unique constraints for ON CONFLICT targets.
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'uq_domains_user_name'
          AND conrelid = 'domains'::regclass
    ) THEN
        IF EXISTS (
            SELECT 1
            FROM pg_class idx
            JOIN pg_index i ON i.indexrelid = idx.oid
            JOIN pg_class tbl ON tbl.oid = i.indrelid
            WHERE idx.relname = 'uq_domains_user_name'
              AND idx.relkind = 'i'
              AND tbl.relname = 'domains'
              AND i.indisunique
        ) THEN
            ALTER TABLE domains
                ADD CONSTRAINT uq_domains_user_name UNIQUE USING INDEX uq_domains_user_name;
        ELSE
            ALTER TABLE domains
                ADD CONSTRAINT uq_domains_user_name UNIQUE (user_id, name);
        END IF;
    END IF;
END $$;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'uq_technologies_name_version'
          AND conrelid = 'technologies'::regclass
    ) THEN
        IF EXISTS (
            SELECT 1
            FROM pg_class idx
            JOIN pg_index i ON i.indexrelid = idx.oid
            JOIN pg_class tbl ON tbl.oid = i.indrelid
            WHERE idx.relname = 'uq_technologies_name_version'
              AND idx.relkind = 'i'
              AND tbl.relname = 'technologies'
              AND i.indisunique
        ) THEN
            ALTER TABLE technologies
                ADD CONSTRAINT uq_technologies_name_version UNIQUE USING INDEX uq_technologies_name_version;
        ELSE
            ALTER TABLE technologies
                ADD CONSTRAINT uq_technologies_name_version UNIQUE (name, version);
        END IF;
    END IF;
END $$;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'uq_subdomains_domain_name'
          AND conrelid = 'subdomains'::regclass
    ) THEN
        IF EXISTS (
            SELECT 1
            FROM pg_class idx
            JOIN pg_index i ON i.indexrelid = idx.oid
            JOIN pg_class tbl ON tbl.oid = i.indrelid
            WHERE idx.relname = 'uq_subdomains_domain_name'
              AND idx.relkind = 'i'
              AND tbl.relname = 'subdomains'
              AND i.indisunique
        ) THEN
            ALTER TABLE subdomains
                ADD CONSTRAINT uq_subdomains_domain_name UNIQUE USING INDEX uq_subdomains_domain_name;
        ELSE
            ALTER TABLE subdomains
                ADD CONSTRAINT uq_subdomains_domain_name UNIQUE (domain_id, name);
        END IF;
    END IF;
END $$;
