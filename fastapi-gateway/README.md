# FastAPI gRPC Gateway

A RESTful API wrapper that translates HTTP requests into gRPC calls for the Go backend.

## 🛠 Features
- **gRPC Client**: Communicates with the Go server via `grpcio`.
- **Subdomain scan endpoints**: Standard, streaming, and cancel flows.
- **Port scan endpoints**: Standard, streaming, and cancel flows.
- **Swagger docs**: Interactive API docs for quick manual testing.

## 🚀 Getting Started
1. **Install Dependencies**: `uv sync`
2. **Run API**: `uv run uvicorn main:app --reload`
   - Access Swagger UI: `http://localhost:8000/docs`

## 📡 Endpoints
- `POST /scan-subdomains/{domain}`
- `POST /scan-subdomains/stream/{domain}`
- `POST /scan-subdomains/{scan_id}/cancel`
- `POST /scan-ports`
- `POST /scan-ports/stream`
- `POST /scan-ports/{scan_id}/cancel`

## 🧾 Port Scan Request Example

```json
{
  "hosts": ["example.com"],
  "ports": ["80", "443"]
}
```

If `ports` is omitted, `null`, or an empty list, the Go backend falls back to scanning its default top-port set.

## 📁 Structure
- `app/gen/`: Python gRPC stubs.
- `app/internal/`: gRPC client wrappers.
- `app/routers/`: FastAPI route handlers for each scan type.
- `app/schema/`: Pydantic request and response models.
