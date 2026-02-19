# Go gRPC Scan Server

This is the core execution engine for the pentest automation tool. It handles incoming gRPC requests to execute security tools.

## 🛠 Features
- **UserService**: Manages user-related data.
- **ScanService**: Executes automated security tools (e.g., nmap, ping).

## 🚀 Getting Started
1. **Generate Code**: `make proto`
2. **Run Server**: `go run cmd/main.go`
   - Listens on: `localhost:50051`

## 📁 Structure
- `gen/`: Generated gRPC code.
- `internal/service/`: Implementation of the gRPC handlers.