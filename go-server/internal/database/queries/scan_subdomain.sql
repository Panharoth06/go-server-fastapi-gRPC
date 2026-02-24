-- name: UpsertDomain :one
INSERT INTO domains (
    user_id,
    name,
    scanned_at,
    count_subdomains
) VALUES (
    $1,
    $2,
    $3,
    0
)
ON CONFLICT (user_id, name) DO UPDATE
SET scanned_at = EXCLUDED.scanned_at
RETURNING domain_id;

-- name: UpsertSubdomain :one
INSERT INTO subdomains (
    domain_id,
    name,
    status_code,
    title_page,
    ip,
    is_alive
) VALUES (
    $1,
    $2,
    $3,
    $4,
    $5,
    $6
)
ON CONFLICT (domain_id, name) DO UPDATE
SET status_code = EXCLUDED.status_code,
    title_page = EXCLUDED.title_page,
    ip = EXCLUDED.ip,
    is_alive = EXCLUDED.is_alive,
    updated_at = NOW()
RETURNING subdomain_id;

-- name: UpsertTechnology :one
INSERT INTO technologies (
    name,
    version
) VALUES (
    $1,
    $2
)
ON CONFLICT (name, version) DO UPDATE
SET updated_at = NOW()
RETURNING technology_id;

-- name: LinkSubdomainTechnology :exec
INSERT INTO subdomain_technologies (
    subdomain_id,
    technology_id
) VALUES (
    $1,
    $2
)
ON CONFLICT (subdomain_id, technology_id) DO NOTHING;

-- name: RefreshDomainScanStats :exec
UPDATE domains
SET scanned_at = $2,
    count_subdomains = (
        SELECT COUNT(*)
        FROM subdomains
        WHERE subdomains.domain_id = $1
    )
WHERE domains.domain_id = $1;
