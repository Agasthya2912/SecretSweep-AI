"""api/auth/api_key.py

Simple X-API-Key header check, wired in as middleware in api/main.py. If
API_KEY isn't set, every request is allowed through (dev mode). If it is,
the X-API-Key header must match it exactly or the request is rejected with
401 — except for the paths in EXEMPT_PATHS, which never need a key.
"""

from typing import Optional

from fastapi import HTTPException, status

from api.config import get_settings

EXEMPT_PATHS = {"/api/health", "/api/scan/webhook/github"}


def is_exempt(path: str) -> bool:
    """True if path never requires an API key (health check, GitHub webhook)."""
    return path in EXEMPT_PATHS


def check_api_key(provided_key: Optional[str]) -> None:
    """Raise HTTPException(401) if API_KEY is configured and provided_key doesn't match it."""
    settings = get_settings()
    if not settings.api_key:
        return  # no key configured — auth disabled (dev mode)
    if provided_key != settings.api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or missing API key"
        )
