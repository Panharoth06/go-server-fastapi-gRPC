import os

import grpc

from app.gen import scan_port_pb2, scan_port_pb2_grpc


class ScanPortClient:
    def __init__(self):
        grpc_addr = os.getenv("GRPC_SERVER_ADDR", "localhost:50051")
        self.channel = grpc.insecure_channel(grpc_addr)
        self.stub = scan_port_pb2_grpc.ScanPortServiceStub(self.channel)

    def scan_ports(
        self,
        hosts: list[str],
        ports: list[str] | None = None,
        user_id: str = "",
        scan_id: str = "",
    ):
        request = scan_port_pb2.ScanPortsRequest(
            hosts=hosts,
            port=ports or [],
            user_id=user_id,
            scan_id=scan_id,
        )

        responses = self.stub.ScanPorts(request)
        for response in responses:
            yield {
                "scan_id": response.scan_id,
                "host": response.host,
                "port": response.port,
                "service_name": response.service_name,
                "service_version": response.service_version,
                "operating_system": response.operating_system,
            }

    def cancel_scan(self, scan_id: str, user_id: str = ""):
        request = scan_port_pb2.CancelScanRequest(scan_id=scan_id, user_id=user_id)
        response = self.stub.CancelScan(request)
        return {
            "scan_id": response.scan_id,
            "cancelled": response.cancelled,
            "message": response.message,
        }


scanner_client = ScanPortClient()


def scan_ports(
    hosts: list[str],
    ports: list[str] | None = None,
    user_id: str = "",
    scan_id: str = "",
):
    return scanner_client.scan_ports(hosts=hosts, ports=ports, user_id=user_id, scan_id=scan_id)


def cancel_scan(scan_id: str, user_id: str = ""):
    return scanner_client.cancel_scan(scan_id=scan_id, user_id=user_id)
