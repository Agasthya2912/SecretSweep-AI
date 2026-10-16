"""Application settings loaded from environment variables."""

from functools import lru_cache
from typing import Optional

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """All API configuration, loaded from environment variables / .env.

    database_url is intentionally Optional: when unset, api/db/session.py falls
    back to a local SQLite file so the API runs without PostgreSQL installed.
    """

    model_config = SettingsConfigDict(env_file=".env", extra="ignore", protected_namespaces=())

    environment: str = "development"

    database_url: Optional[str] = None
    redis_url: str = "redis://localhost:6379/0"

    neo4j_uri: Optional[str] = None
    neo4j_username: Optional[str] = None
    neo4j_password: Optional[str] = None

    api_key: Optional[str] = None  # X-API-Key required value; unset = auth disabled (dev mode)
    github_webhook_secret: Optional[str] = None  # HMAC secret for X-Hub-Signature-256

    model_path: str = "./data/models/codebert-secretsweep"
    onnx_model_path: str = "./data/models/codebert-secretsweep.onnx"


@lru_cache
def get_settings() -> Settings:
    """Cached Settings instance — environment is read once per process."""
    return Settings()
