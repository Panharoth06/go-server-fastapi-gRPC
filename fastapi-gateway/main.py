from fastapi import FastAPI
from app.internal import user_client, scanner_client, scan_subdomain_client
from app.schema import scanner_schemas

from fastapi.responses import StreamingResponse
import json

app = FastAPI()

@app.get("/users/{user_id}", tags=['User'])
def read_user(user_id: str):
    # This triggers the gRPC call to the Go server
    response = user_client.get_user(user_id)
    
    # Return the data as standard JSON
    return {
        "name": response.name, 
        "email": response.email
    }


@app.post("/scanners", tags=['Scanner'])
def run_scan(req: scanner_schemas.ScanRequestSchema):
    
    response = scanner_client.run_scan(
        target=req.target,
        tool_name=req.tool_name
    )
    
    # go to .proto file to view key-pair values
    return {
        "summary" : response.result_summary,
        "is_success": response.success
    }
    

@app.post("/scan-subdomains/{domain}", tags=['ScanSubdomain'])
def scan_and_check(domain: str):
    # Swagger expects application/json for this route.
    return list(scan_subdomain_client.scan_and_check(domain))


@app.post("/scan-subdomains-stream/{domain}", tags=['ScanSubdomain'])
def scan_and_check_stream(domain: str):
    def event_generator():
        # This calls ScanSubdomainClient.scan_and_check generator
        for result in scan_subdomain_client.scan_and_check(domain):
            # Yield each result as a JSON string followed by a newline
            yield json.dumps(result) + "\n"

    return StreamingResponse(event_generator(), media_type="application/x-ndjson")
