import json
import uuid
from collections.abc import Iterator
from typing import Annotated

import grpc
from fastapi import APIRouter, Depends, Response, status
from fastapi.responses import StreamingResponse

from app.dependencies.auth import CurrentUser, get_current_user
from app.internal import scan_subdomain_client
from app.schema.scanner_schemas import (
    CancelSubdomainScanResponseSchema,
    SubdomainScanResponseSchema,
    SubdomainScanResultSchema,
)
from app.utils.grpc_errors import raise_for_grpc_error

router = APIRouter(prefix="/scan-subdomains", tags=["ScanSubdomain"])
CurrentUserDep = Annotated[CurrentUser, Depends(get_current_user)]


def build_scan_id() -> str:
    return str(uuid.uuid4())


@router.post("/{domain}", response_model=SubdomainScanResponseSchema, status_code=status.HTTP_201_CREATED)
def scan_and_check(domain: str, current_user: CurrentUserDep, response: Response) -> SubdomainScanResponseSchema:
    
    resolved_scan_id = build_scan_id()

    try:
        payload = [
            SubdomainScanResultSchema.model_validate(result)
            for result in scan_subdomain_client.scan_and_check(
                domain,
                current_user.user_id,
                resolved_scan_id,
            )
        ]
    except grpc.RpcError as exc:
        raise_for_grpc_error(exc)

    response.headers["X-Scan-ID"] = resolved_scan_id
    return SubdomainScanResponseSchema(
        scan_id=resolved_scan_id,
        results=payload,
    )


@router.post("/stream/{domain}")
def scan_and_check_stream(domain: str, current_user: CurrentUserDep) -> StreamingResponse:
    
    resolved_scan_id = build_scan_id()

    def event_generator() -> Iterator[str]:
        try:
            for result in scan_subdomain_client.scan_and_check(
                domain,
                current_user.user_id,   
                resolved_scan_id,
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


@router.post("/{scan_id}/cancel", response_model=CancelSubdomainScanResponseSchema)
def cancel_scan(scan_id: str, current_user: CurrentUserDep) -> CancelSubdomainScanResponseSchema:
    try:
        payload = scan_subdomain_client.cancel_scan(
            scan_id=scan_id,
            user_id=current_user.user_id,
        )
    except grpc.RpcError as exc:
        raise_for_grpc_error(exc)

    return CancelSubdomainScanResponseSchema.model_validate(payload)
