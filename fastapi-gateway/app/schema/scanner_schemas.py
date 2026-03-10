from pydantic import BaseModel


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
