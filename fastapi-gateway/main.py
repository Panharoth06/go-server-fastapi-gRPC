from fastapi import FastAPI
from app.internal import user_client, scanner_client
from app.schema import scanner_schemas

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
    