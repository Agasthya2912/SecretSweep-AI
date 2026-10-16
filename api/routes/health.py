"""GET /api/health — liveness + dependency connectivity check. No auth required."""

import logging

from fastapi import APIRouter
from sqlalchemy import text

from api.config import get_settings
from api.db.session import get_engine

logger = logging.getLogger(__name__)

router = APIRouter(tags=["health"])


async def _check_database() -> str:
    try:
        engine = get_engine()
        async with engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
        return "connected"
    except Exception as exc:
        logger.warning("Health check: database unreachable: %s", exc)
        return "disconnected"


async def _check_redis() -> str:
    try:
        import redis.asyncio as redis_async

        # Short timeout: localhost resolves to both ::1 and 127.0.0.1, and when nothing's
        # listening the IPv6 attempt can eat the whole timeout before IPv4 gets tried —
        # keeping this tight bounds each /api/health call even in the worst case.
        client = redis_async.from_url(get_settings().redis_url, socket_connect_timeout=0.5)
        try:
            await client.ping()
            return "connected"
        finally:
            await client.aclose()
    except Exception as exc:
        logger.warning("Health check: redis unreachable: %s", exc)
        return "disconnected"


@router.get("/api/health")
async def health_check() -> dict:
    return {
        "status": "ok",
        "version": "1.0.0",
        "service": "SecretSweep AI",
        "database": await _check_database(),
        "redis": await _check_redis(),
    }
