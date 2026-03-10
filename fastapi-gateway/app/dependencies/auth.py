from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from dataclasses import dataclass

from app.core.security import extract_user_id, verify_access_token

bearer_scheme = HTTPBearer(auto_error=False)

@dataclass
class CurrentUser:
    user_id: str
    claims: dict

def get_current_claims(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
) -> dict:
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing Bearer token",
        )

    return verify_access_token(credentials.credentials)


def get_current_user(claims: dict = Depends(get_current_claims)) -> CurrentUser:
    return CurrentUser(
        user_id=extract_user_id(claims),
        claims=claims,
    )