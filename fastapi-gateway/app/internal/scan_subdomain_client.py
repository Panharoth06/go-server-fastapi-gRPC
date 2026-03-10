import os
import grpc 

from app.gen import scan_subdomain_pb2, scan_subdomain_pb2_grpc

class ScanSubdomainClient:
    def __init__(self):
        # Use the address where your Go server is running
        grpc_addr = os.getenv("GRPC_SERVER_ADDR", "localhost:50051")
        self.channel = grpc.insecure_channel(grpc_addr)
        # Match the service name defined in your .proto file
        self.stub = scan_subdomain_pb2_grpc.SubdomainScannerStub(self.channel)
        
    def scan_and_check(self, domain: str, user_id: str = "", scan_id: str = ""):
        request = scan_subdomain_pb2.ScanRequest(domain=domain, user_id=user_id, scan_id=scan_id)
        
        # This returns an iterator. Each 'response' is a ScanResponse object.
        responses = self.stub.ScanAndCheck(request)
        for response in responses:
            yield {
                "scan_id": response.scan_id,
                "subdomain": response.subdomain,
                "is_alive": response.is_alive,
                "status_code": response.status_code,
                "title": response.title,
                "ip": response.ip,
                "technologies": list(response.technologies)
            }

    def cancel_scan(self, scan_id: str, user_id: str = ""):
        request = scan_subdomain_pb2.CancelScanRequest(scan_id=scan_id, user_id=user_id)
        response = self.stub.CancelScan(request)
        return {
            "scan_id": response.scan_id,
            "cancelled": response.cancelled,
            "message": response.message,
        }

scanner_client = ScanSubdomainClient()


def scan_and_check(domain: str, user_id: str = "", scan_id: str = ""):
    return scanner_client.scan_and_check(domain=domain, user_id=user_id, scan_id=scan_id)


def cancel_scan(scan_id: str, user_id: str = ""):
    return scanner_client.cancel_scan(scan_id=scan_id, user_id=user_id)
