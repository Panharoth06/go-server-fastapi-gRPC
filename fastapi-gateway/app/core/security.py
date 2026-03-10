import base64
import functools
import json

import jwt
from fastapi import HTTPException, status
from jwt import PyJWKClient, PyJWTError

from app.core.config import get_settings


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


def verify_access_token(token: str) -> dict:
    settings = get_settings()

    if not settings.keycloak_issuer or not settings.keycloak_jwks_url:
        missing = []
        if not settings.keycloak_issuer:
            missing.append("KEYCLOAK_ISSUER")
        if not settings.keycloak_jwks_url:
            missing.append("KEYCLOAK_JWKS_URL")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"JWT verifier is not configured. Missing: {', '.join(missing)}.",
        )

    decode_jwt_payload(token)

    try:
        jwks_client = get_jwks_client(settings.keycloak_jwks_url)
        signing_key = jwks_client.get_signing_key_from_jwt(token)

        claims = jwt.decode(
            token,
            signing_key.key,
            algorithms=["RS256", "RS384", "RS512"],
            issuer=settings.keycloak_issuer,
            audience=settings.keycloak_audience or None,
            options={"verify_aud": bool(settings.keycloak_audience)},
        )
        return claims

    except PyJWTError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid token: {exc}",
        ) from exc


def extract_user_id(claims: dict) -> str:
    user_id = claims.get("sub") or claims.get("user_id") or claims.get("uid")
    if not isinstance(user_id, str) or not user_id.strip():
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="user_id claim not found in token",
        )
    return user_id