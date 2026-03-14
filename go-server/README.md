# Go gRPC Scan Server

This is the core execution engine for the pentest automation tool. It handles incoming gRPC requests to execute security tools.

## 🛠 Features
- **Subdomain scan**: Uses `subfinder` for discovery and `httpx` to probe live hosts.
- **Port scan**: Uses `naabu` for port discovery, then enriches results with direct `nmap` service/version detection.
- **Cancellation support**: Active scans can be cancelled through gRPC.
- **Persistence**: Stores scan results in Postgres using `sqlc` queries and embedded `goose` migrations.

## 🚀 Getting Started
1. Copy `.env.example` to `.env` and adjust the database connection values if needed.
2. Start the server from this directory:

```bash
go run cmd/main.go
```

The server listens on `localhost:50051`.

From the repository root you can also use:
- `make run-go`
- `make run-go-sudo-os`

## 🔎 Port Scan Notes
The port-scan service works in two stages:
- `naabu` finds open ports.
- `nmap` enriches those ports with service and version details.

Host OS detection is optional and requires elevated Nmap execution. To enable the sudo fallback:

1. Set `SCAN_PORT_NMAP_USE_SUDO=true` in `.env`.
2. Grant the server user passwordless sudo for `nmap`, for example:

```sudoers
your_user ALL=(root) NOPASSWD: /usr/bin/nmap
```

3. Restart the Go server.

If sudo is not configured, scans still run and service/version detection still works, but `operating_system` may remain empty.

## 🗄 Database
- Uses `goose` for schema migrations.
- Uses `sqlc` for type-safe query generation.
- Migrations are stored in `internal/database/migrations` and embedded in the Go binary.
- Query definitions are in `internal/database/queries`, generated code is in `internal/database/sqlc`.

### Migration Commands
Run from repository root:
- `make goose-status DATABASE_URL=postgres://...`
- `make goose-up DATABASE_URL=postgres://...`
- `make goose-down DATABASE_URL=postgres://...`
- `make goose-create NAME=add_example_column`

### Regenerate sqlc
Run from repository root:
- `make sqlc`

## 📁 Structure
- `gen/`: Generated gRPC code.
- `internal/service/`: Implementation of the gRPC handlers.
- `internal/database/`: Database connection, migrations, queries, and generated `sqlc` code.
