"""FastAPI application entrypoint: app instance, middleware, and router registration."""

import logging
import time
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from api.auth.api_key import check_api_key, is_exempt
from api.db.session import create_all_tables
from api.routes import dashboard, developers, health, scan, secrets

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
)
logger = logging.getLogger("secretsweep")

ALLOWED_ORIGINS = [
    "http://localhost:3000",
    "http://127.0.0.1:3000",
]


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("SecretSweep AI API starting up")
    try:
        await create_all_tables()
        logger.info("Database connection verified, tables ready")
    except Exception as exc:
        logger.warning("Database unavailable at startup (%s) — continuing anyway", exc)
    yield
    logger.info("SecretSweep AI API shutting down")


app = FastAPI(
    title="SecretSweep AI",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def request_logging_middleware(request: Request, call_next):
    """Log method, path, status, and duration for every request."""
    started_at = time.perf_counter()
    response = await call_next(request)
    duration_ms = round((time.perf_counter() - started_at) * 1000, 2)
    logger.info(
        "%s %s -> %d (%.2fms)", request.method, request.url.path, response.status_code, duration_ms
    )
    return response


@app.middleware("http")
async def api_key_middleware(request: Request, call_next):
    """Reject requests missing/mismatching X-API-Key, except for exempt paths.

    A stand-in for full JWT auth (per Phase 9 scope) — if API_KEY isn't set in
    the environment, every request is allowed through (dev mode).
    """
    if not is_exempt(request.url.path):
        try:
            check_api_key(request.headers.get("X-API-Key"))
        except Exception as exc:
            status_code = getattr(exc, "status_code", 401)
            detail = getattr(exc, "detail", "Unauthorized")
            return JSONResponse(status_code=status_code, content={"error": detail})
    return await call_next(request)


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """Never leak a raw traceback to the client — always {"error": message}."""
    logger.error("Unhandled exception on %s %s: %s", request.method, request.url.path, exc)
    return JSONResponse(status_code=500, content={"error": str(exc)})


app.include_router(health.router)
app.include_router(scan.router)
app.include_router(secrets.router)
app.include_router(developers.router)
app.include_router(dashboard.router)
