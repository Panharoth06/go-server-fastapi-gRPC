import json
import uuid
from collections.abc import Iterator
from typing import Annotated

import grpc
from fastapi import APIRouter, Depends, Response, status
from fastapi.responses import StreamingResponse
from fastapi_limiter.depends import RateLimiter
from pyrate_limiter import Duration, Limiter, Rate

from app.dependencies.auth import CurrentUser, get_current_user
from app.internal import scan_port_client
from app.schema.scanner_schemas import (
    CancelPortScanResponseSchema,
    PortScanRequestSchema,
    PortScanResponseSchema,
    PortScanResultSchema,
)
from app.utils.grpc_errors import raise_for_grpc_error

router = APIRouter(prefix="/scan-ports", tags=["ScanPort"])
CurrentUserDep = Annotated[CurrentUser, Depends(get_current_user)]
scan_port_rate_limiter = RateLimiter(
    limiter=Limiter(Rate(200, Duration.MINUTE))
)


def build_scan_id() -> str:
    return str(uuid.uuid4())


@router.post("", response_model=PortScanResponseSchema, status_code=status.HTTP_201_CREATED, dependencies=[Depends(scan_port_rate_limiter)])
def scan_ports(
    payload: PortScanRequestSchema,
    # current_user: CurrentUserDep,
    response: Response,
) -> PortScanResponseSchema:
    resolved_scan_id = build_scan_id()
    userID = "6ea2e4fb-651a-476c-886c-4aa51865fff8" 

    try:
        results = [
            PortScanResultSchema.model_validate(result)
            for result in scan_port_client.scan_ports(
                hosts=payload.hosts,
                ports=payload.ports,
                user_id=userID,
                scan_id=resolved_scan_id,
            )
        ]
    except grpc.RpcError as exc:
        raise_for_grpc_error(exc)

    response.headers["X-Scan-ID"] = resolved_scan_id
    return PortScanResponseSchema(scan_id=resolved_scan_id, results=results)


@router.post("/stream", dependencies=[Depends(scan_port_rate_limiter)])
def scan_ports_stream(
    payload: PortScanRequestSchema,
    current_user: CurrentUserDep,
) -> StreamingResponse:
    resolved_scan_id = build_scan_id()

    def event_generator() -> Iterator[str]:
        try:
            for result in scan_port_client.scan_ports(
                hosts=payload.hosts,
                ports=payload.ports,
                user_id=current_user.user_id,
                scan_id=resolved_scan_id,
            ):
                yield json.dumps(result) + "\n"
        except grpc.RpcError as exc:
            error_event = {
                "scan_id": resolved_scan_id,
                "error": exc.details() or "gRPC request failed",
            }
            yield json.dumps(error_event) + "\n"

    return StreamingResponse(
        event_generator(),
        media_type="application/x-ndjson",
        headers={"X-Scan-ID": resolved_scan_id},
    )


@router.post("/{scan_id}/cancel", response_model=CancelPortScanResponseSchema, dependencies=[Depends(scan_port_rate_limiter)])
def cancel_scan(scan_id: str, current_user: CurrentUserDep) -> CancelPortScanResponseSchema:
    try:
        payload = scan_port_client.cancel_scan(
            scan_id=scan_id,
            user_id=current_user.user_id,
        )
    except grpc.RpcError as exc:
        raise_for_grpc_error(exc)

    return CancelPortScanResponseSchema.model_validate(payload)
