"""
Authentication: only callers that know the shared API key may use the API.
"""
import secrets

from fastapi import HTTPException, Security, status
from fastapi.security import APIKeyHeader

from app import config

# auto_error=False: we raise our own error so we control the message
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


def require_api_key(provided_key: str | None = Security(api_key_header)) -> None:
    # Fail closed: if the server has no key configured, nobody gets in
    if not config.API_KEY:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Server is not configured",
        )

    # compare_digest takes the same time whether the first character or the
    # last one differs, so response timing leaks nothing about the real key
    if provided_key is None or not secrets.compare_digest(
        provided_key.encode(), config.API_KEY.encode()
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing API key",
        )
