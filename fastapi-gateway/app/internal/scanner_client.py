import os

import grpc 
from app.gen import scan_pb2, scan_pb2_grpc

class ScannerClient:
    def __init__(self):
        grpc_addr = os.getenv("GRPC_SERVER_ADDR", "localhost:50051")
        self.channel = grpc.insecure_channel(grpc_addr)
        self.stub = scan_pb2_grpc.ScanServiceStub(self.channel)
        
    def run_scan(self, target: str, tool_name: str):
        # Map fields specifically to the names in your .proto file
        # 'target' and 'tool_name' must match our ScanRequest message exactly
        request = scan_pb2.ScanRequest(
            target=target, 
            tool_name=tool_name
        )
        
        # Call 'RunTool' because that's what we named it in the .proto
        return self.stub.RunTool(request)
    

scanner_client = ScannerClient()


def run_scan(target: str, tool_name: str):
    return scanner_client.run_scan(target=target, tool_name=tool_name)
