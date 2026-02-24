# Go gRPC Scan Server

This is the core execution engine for the pentest automation tool. It handles incoming gRPC requests to execute security tools.

## 🛠 Features
- **SubdomainScanner**: Executes automated security tools (subfinder | httpx).

## 🚀 Getting Started
2. **Run Server**: `go run cmd/main.go`
   - Listens on: `localhost:50051`

## 🗄 Database
- Uses `golang-migrate` for schema migrations.
- Uses `sqlc` for type-safe query generation.
- Migrations are stored in `internal/database/migrations` and embedded in the Go binary.
- Query definitions are in `internal/database/queries`, generated code is in `internal/database/sqlc`.

### Regenerate sqlc
Run from repository root:
- `make sqlc`

## 📁 Structure
- `gen/`: Generated gRPC code.
- `internal/service/`: Implementation of the gRPC handlers.
