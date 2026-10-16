"""SQLAlchemy engine and session factory.

Async throughout (SQLAlchemy's asyncio extension). When DATABASE_URL isn't
set, falls back to a local SQLite file under data/ so the API is runnable
without PostgreSQL installed — that's why api/models/database.py uses the
dialect-agnostic `Uuid` column type instead of `postgresql.UUID`.
"""

from pathlib import Path
from typing import AsyncGenerator

from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker, create_async_engine

from api.config import get_settings
from api.models.database import Base

DEFAULT_SQLITE_PATH = Path("data") / "secretsweep_dev.db"


def _to_async_dsn(url: str) -> str:
    """Rewrite a plain postgresql://, postgres://, or sqlite:// DSN to its async-driver form."""
    if url.startswith(("postgresql+asyncpg://", "sqlite+aiosqlite://")):
        return url
    if url.startswith("postgresql://"):
        return "postgresql+asyncpg://" + url[len("postgresql://") :]
    if url.startswith("postgres://"):
        return "postgresql+asyncpg://" + url[len("postgres://") :]
    if url.startswith("sqlite://"):
        return "sqlite+aiosqlite://" + url[len("sqlite://") :]
    return url


def resolve_database_url() -> str:
    """Return the async DSN to use: DATABASE_URL if set, else the local SQLite fallback."""
    settings = get_settings()
    if settings.database_url:
        return _to_async_dsn(settings.database_url)

    DEFAULT_SQLITE_PATH.parent.mkdir(parents=True, exist_ok=True)
    return f"sqlite+aiosqlite:///{DEFAULT_SQLITE_PATH.as_posix()}"


_engine: AsyncEngine | None = None
_session_factory: async_sessionmaker | None = None


def get_engine() -> AsyncEngine:
    """Return the process-wide async engine, creating it on first use."""
    global _engine
    if _engine is None:
        url = resolve_database_url()
        connect_args = {"check_same_thread": False} if url.startswith("sqlite") else {}
        _engine = create_async_engine(url, connect_args=connect_args)
    return _engine


def get_session_factory() -> async_sessionmaker:
    """Return the process-wide session factory, creating it on first use."""
    global _session_factory
    if _session_factory is None:
        _session_factory = async_sessionmaker(
            bind=get_engine(), expire_on_commit=False, class_=AsyncSession
        )
    return _session_factory


async def create_all_tables(engine: AsyncEngine | None = None) -> None:
    """Create every table declared on Base.metadata if it doesn't already exist."""
    target_engine = engine or get_engine()
    async with target_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """FastAPI dependency yielding one AsyncSession per request."""
    session_factory = get_session_factory()
    async with session_factory() as session:
        yield session


async def dispose_engine() -> None:
    """Dispose the process-wide engine and clear the cached singletons.

    Only needed by callers (Celery tasks) that wrap their work in a fresh
    `asyncio.run()` per invocation rather than running on one persistent loop
    like uvicorn does. asyncpg connections are bound to the loop that opened
    them; reusing the cached engine after that loop closes raises
    `asyncpg.exceptions.InterfaceError: cannot perform operation: another
    operation is in progress`. Must be awaited before the current loop closes.
    """
    global _engine, _session_factory
    if _engine is not None:
        await _engine.dispose()
    _engine = None
    _session_factory = None
