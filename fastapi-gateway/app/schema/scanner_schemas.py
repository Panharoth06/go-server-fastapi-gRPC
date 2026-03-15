from pydantic import BaseModel, Field

# ------------ Subdomain Scan Schemas ------------
class ScanRequestSchema(BaseModel):
    target: str
    tool_name: str


class SubdomainScanResultSchema(BaseModel):
    scan_id: str
    subdomain: str
    is_alive: bool
    status_code: int
    title: str
    ip: str
    technologies: list[str]


class SubdomainScanResponseSchema(BaseModel):
    scan_id: str
    results: list[SubdomainScanResultSchema]


class CancelSubdomainScanResponseSchema(BaseModel):
    scan_id: str
    cancelled: bool
    message: str


# ------------ Port Scan Schemas ------------
class PortScanRequestSchema(BaseModel):
    hosts: list[str]
    ports: list[str] | None = Field(
        default=None,
        description="Optional port list. When omitted or null, the backend scans the top 1000 ports.",
    )


class PortScanResultSchema(BaseModel):
    scan_id: str
    host: str
    port: str
    service_name: str
    service_version: str
    operating_system: str


class PortScanResponseSchema(BaseModel):
    scan_id: str
    results: list[PortScanResultSchema]


class CancelPortScanResponseSchema(BaseModel):
    scan_id: str
    cancelled: bool
    message: str
