# Multi-Service Pentest Automation Tool

A distributed architecture combining a high-performance **Go gRPC Backend** with a flexible **FastAPI Gateway**.

## 🏗 System Architecture
This project uses a "Brain and Muscle" design:
1. **The Brain (FastAPI)**: Handles user requests, validates input using Pydantic, and routes tasks.
2. **The Muscle (Go)**: Executes low-level system tools and security scans with high concurrency.



## 🔄 The End-to-End Flow
1. **Request**: A user sends a JSON POST request to `FastAPI`.
2. **Translation**: FastAPI validates the data and converts it into a gRPC message.
3. **Execution**: The `Go-server` receives the gRPC call and triggers the specified service.
4. **Response**: Go sends the scan results back to FastAPI, which serves them to the user as JSON.

## 🛠 Available Scans
- **Subdomain scan**: `subfinder` discovery with `httpx` probing and streaming results.
- **Port scan**: `naabu` port discovery with direct `nmap` enrichment for service/version data and optional OS detection.

## 🚀 Quick Start
To get the entire system running:
1. **Prepare environment**: copy `go-server/.env.example` to `go-server/.env` and adjust database values if needed.
2. **Generate Code**: `make proto`
3. **Start Go**: `make run-go`
4. **Start Python**: `cd fastapi-gateway && uv run uvicorn main:app --reload`
5. **Test**: Visit `http://localhost:8000/docs` to trigger your first scan!

If you want the port-scan service to try `sudo -n nmap -O` for host OS detection, start Go with:

```bash
make run-go-sudo-os
```

This requires the Go server user to have passwordless sudo for `/usr/bin/nmap`.


## Project Docs:
- [Go Server Docs](go-server/README.md)
- [FastAPI Gateway Docs](fastapi-gateway/README.md)
