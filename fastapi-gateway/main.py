from fastapi import FastAPI
from app.routers import scan_port, scan_subdomain

app = FastAPI(title="FastAPI Gateway", version="1.0.0")

app.include_router(scan_subdomain.router)
app.include_router(scan_port.router)
