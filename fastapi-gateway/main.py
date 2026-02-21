import base64
import functools
import json
import os

from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
import jwt
from jwt import PyJWKClient, PyJWTError
from app.internal import user_client, scanner_client, scan_subdomain_client
from app.schema import scanner_schemas

from fastapi.responses import StreamingResponse

try:
    from dotenv import load_dotenv
except Exception:  # pragma: no cover - optional dependency in runtime images
    def load_dotenv(*args, **kwargs):  # type: ignore
        return False

load_dotenv(".env")
load_dotenv(".env.docker")

app = FastAPI()
bearer_scheme = HTTPBearer(auto_error=False)


def get_keycloak_config() -> tuple[str, str, str]:
    keycloak_issuer = os.getenv("KEYCLOAK_ISSUER", "").strip()
    keycloak_audience = os.getenv("KEYCLOAK_AUDIENCE", "").strip()
    keycloak_jwks_url = os.getenv("KEYCLOAK_JWKS_URL", "").strip()

    if keycloak_issuer and not keycloak_jwks_url:
        keycloak_jwks_url = f"{keycloak_issuer.rstrip('/')}/protocol/openid-connect/certs"

    return keycloak_issuer, keycloak_audience, keycloak_jwks_url


@functools.lru_cache(maxsize=4)
def get_jwks_client(jwks_url: str) -> PyJWKClient:
    return PyJWKClient(jwks_url)


def decode_jwt_payload(token: str) -> dict:
    parts = token.split(".")
    if len(parts) != 3:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid JWT format")

    payload_b64 = parts[1]
    padding = "=" * (-len(payload_b64) % 4)
    try:
        payload_bytes = base64.urlsafe_b64decode(payload_b64 + padding)
        claims = json.loads(payload_bytes.decode("utf-8"))
    except (ValueError, json.JSONDecodeError):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid JWT payload")

    if not isinstance(claims, dict):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid JWT claims")
    return claims


def get_user_id_from_bearer(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
) -> str:
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing Bearer token")

    keycloak_issuer, keycloak_audience, keycloak_jwks_url = get_keycloak_config()
    if not keycloak_issuer or not keycloak_jwks_url:
        missing = []
        if not keycloak_issuer:
            missing.append("KEYCLOAK_ISSUER")
        if not keycloak_jwks_url:
            missing.append("KEYCLOAK_JWKS_URL")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Keycloak JWT verifier is not configured. Missing: {', '.join(missing)}.",
        )

    token = credentials.credentials
    decode_jwt_payload(token)
    try:
        jwks_client = get_jwks_client(keycloak_jwks_url)
        signing_key = jwks_client.get_signing_key_from_jwt(token)
        claims = jwt.decode(
            token,
            signing_key.key,
            algorithms=["RS256", "RS384", "RS512"],
            issuer=keycloak_issuer,
            audience=keycloak_audience or None,
            options={"verify_aud": bool(keycloak_audience)},
        )
    except PyJWTError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=f"Invalid token: {exc}") from exc

    user_id = claims.get("sub") or claims.get("user_id") or claims.get("uid")
    if not isinstance(user_id, str) or not user_id.strip():
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="user_id claim not found in token")
    return user_id

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
    

@app.post("/scan-subdomains/{domain}", tags=['ScanSubdomain'], status_code=201)
def scan_and_check(domain: str, user_id: str = Depends(get_user_id_from_bearer)):
    # Swagger expects application/json for this route.
    return list(scan_subdomain_client.scan_and_check(domain, user_id))


@app.post("/scan-subdomains-stream/{domain}", tags=['ScanSubdomain'])
def scan_and_check_stream(domain: str, user_id: str = Depends(get_user_id_from_bearer)):
    def event_generator():
        # This calls ScanSubdomainClient.scan_and_check generator
        for result in scan_subdomain_client.scan_and_check(domain, user_id):
            # Yield each result as a JSON string followed by a newline
            yield json.dumps(result) + "\n"

    return StreamingResponse(event_generator(), media_type="application/x-ndjson")
