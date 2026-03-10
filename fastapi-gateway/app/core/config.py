import os
from functools import lru_cache

try:
    from dotenv import load_dotenv
except Exception:
    def load_dotenv(*args, **kwargs):
        return False

load_dotenv(".env")
load_dotenv(".env.docker")


class Settings:
    def __init__(self) -> None:
        self.keycloak_issuer = os.getenv("KEYCLOAK_ISSUER", "").strip()
        self.keycloak_audience = os.getenv("KEYCLOAK_AUDIENCE", "").strip()
        self.keycloak_jwks_url = os.getenv("KEYCLOAK_JWKS_URL", "").strip()

        if self.keycloak_issuer and not self.keycloak_jwks_url:
            self.keycloak_jwks_url = (
                f"{self.keycloak_issuer.rstrip('/')}/protocol/openid-connect/certs"
            )


@lru_cache
def get_settings() -> Settings:
    return Settings()