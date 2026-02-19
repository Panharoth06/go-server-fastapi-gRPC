from pydantic import BaseModel

class ScanRequestSchema(BaseModel):
    target: str
    tool_name: str