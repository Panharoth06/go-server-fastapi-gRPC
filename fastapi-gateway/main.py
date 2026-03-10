from fastapi import FastAPI
from app.routers import scan_subdomain

app = FastAPI()

app.include_router(scan_subdomain.router)