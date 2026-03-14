-- name: UpsertOpenPort :one
INSERT INTO open_ports (
    port,
    service_name,
    service_version,
    operating_system
) VALUES (
    $1,
    $2,
    $3,
    $4
)
ON CONFLICT (port, service_name, service_version, operating_system) DO UPDATE
SET updated_at = NOW()
RETURNING open_port_id;

-- name: LinkDomainOpenPort :exec
INSERT INTO domain_open_ports (
    domain_id,
    open_port_id
) VALUES (
    $1,
    $2
)
ON CONFLICT (domain_id, open_port_id) DO NOTHING;
