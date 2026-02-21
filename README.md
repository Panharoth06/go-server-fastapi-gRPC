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

## 🚀 Quick Start
To get the entire system running:
1. **Generate Code**: `make proto` 
2. **Start Go**: `cd go-server && go run cmd/main.go`
3. **Start Python**: `cd fastapi-gateway && uv run uvicorn app.main:app`
4. **Test**: Visit `http://localhost:8000/docs` to trigger your first scan!


## Project Docs:
- [Go Server Docs](go-server/README.md)
- [FastAPI Gateway Docs](fastapi-gateway/README.md)