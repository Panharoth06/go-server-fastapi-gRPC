# FastAPI gRPC Gateway

A RESTful API wrapper that translates HTTP requests into gRPC calls for the Go backend.

## 🛠 Features
- **gRPC Client**: Communicates with the Go server via `grpcio`.

## 🚀 Getting Started
1. **Install Dependencies**: `uv sync`
2. **Run API**: `uv run uvicorn app.main:app --reload`
   - Access Swagger UI: `http://localhost:8000/docs`

## 📁 Structure
- `app/gen/`: Python gRPC stubs.
- `app/internal/`: gRPC client wrappers.