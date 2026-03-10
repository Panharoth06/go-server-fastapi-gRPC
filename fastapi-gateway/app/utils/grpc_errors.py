import grpc
from fastapi import HTTPException, status


_GRPC_TO_HTTP_STATUS = {
    grpc.StatusCode.INVALID_ARGUMENT: status.HTTP_400_BAD_REQUEST,
    grpc.StatusCode.UNAUTHENTICATED: status.HTTP_401_UNAUTHORIZED,
    grpc.StatusCode.PERMISSION_DENIED: status.HTTP_403_FORBIDDEN,
    grpc.StatusCode.NOT_FOUND: status.HTTP_404_NOT_FOUND,
    grpc.StatusCode.ALREADY_EXISTS: status.HTTP_409_CONFLICT,
    grpc.StatusCode.RESOURCE_EXHAUSTED: status.HTTP_429_TOO_MANY_REQUESTS,
    grpc.StatusCode.FAILED_PRECONDITION: status.HTTP_400_BAD_REQUEST,
    grpc.StatusCode.OUT_OF_RANGE: status.HTTP_400_BAD_REQUEST,
    grpc.StatusCode.CANCELLED: 499,
    grpc.StatusCode.DEADLINE_EXCEEDED: status.HTTP_504_GATEWAY_TIMEOUT,
    grpc.StatusCode.UNIMPLEMENTED: status.HTTP_501_NOT_IMPLEMENTED,
    grpc.StatusCode.UNAVAILABLE: status.HTTP_503_SERVICE_UNAVAILABLE,
}


def raise_for_grpc_error(exc: grpc.RpcError) -> None:
    code = exc.code()
    detail = exc.details() or "gRPC request failed"
    raise HTTPException(
        status_code=_GRPC_TO_HTTP_STATUS.get(
            code,
            status.HTTP_500_INTERNAL_SERVER_ERROR,
        ),
        detail=detail,
    ) from exc
