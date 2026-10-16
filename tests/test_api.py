"""Tests for the FastAPI application endpoints.

Uses an isolated in-memory SQLite DB per test (via FastAPI dependency
override — the real api/db/session.py engine is never touched) and mocks
run_scan_task.delay so no real Celery/Redis broker is required.
"""

import asyncio
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

from api.config import get_settings
from api.db.session import get_db
from api.main import app
from api.models.database import Base, DetectedSecret, Repository, ScanJob


def _run(coro):
    return asyncio.run(coro)


async def _create_tables(engine):
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


@pytest.fixture()
def test_engine():
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    _run(_create_tables(engine))
    yield engine
    _run(engine.dispose())


@pytest.fixture()
def client(test_engine):
    session_factory = async_sessionmaker(bind=test_engine, expire_on_commit=False, class_=AsyncSession)

    async def override_get_db():
        async with session_factory() as session:
            yield session

    app.dependency_overrides[get_db] = override_get_db
    yield TestClient(app)  # no `with` — skips lifespan, which touches the real (non-test) engine
    app.dependency_overrides.clear()


@pytest.fixture()
def with_api_key(monkeypatch):
    """Set API_KEY for the duration of one test, then clear the settings cache both ways."""
    monkeypatch.setenv("API_KEY", "test-secret-key")
    get_settings.cache_clear()
    yield "test-secret-key"
    get_settings.cache_clear()


async def _insert_secrets(engine, severities):
    session_factory = async_sessionmaker(bind=engine, expire_on_commit=False, class_=AsyncSession)
    async with session_factory() as session:
        repo = Repository(url="https://example.com/repo", name="repo")
        session.add(repo)
        await session.flush()
        job = ScanJob(repo_id=repo.id, status="completed")
        session.add(job)
        await session.flush()
        for i, severity in enumerate(severities):
            session.add(
                DetectedSecret(
                    scan_job_id=job.id,
                    secret_hash=f"hash{i}",
                    pattern_name="AWS Access Key ID",
                    file_path="config.py",
                    commit_hash="c1",
                    author_email="dev@example.com",
                    severity_label=severity,
                    severity_score=10.0,
                    is_active=False,
                )
            )
        await session.commit()


# --------------------------------------------------------------------------------------
# Health
# --------------------------------------------------------------------------------------


def test_health_endpoint_returns_ok(client: TestClient) -> None:
    response = client.get("/api/health")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert body["service"] == "SecretSweep AI"
    assert "database" in body
    assert "redis" in body


# --------------------------------------------------------------------------------------
# Scan
# --------------------------------------------------------------------------------------


def test_post_scan_creates_job(client: TestClient) -> None:
    with patch("api.routes.scan.run_scan_task.delay") as mock_delay:
        response = client.post("/api/scan/repo", json={"repo_url": "https://github.com/example/repo"})

    assert response.status_code == 200
    body = response.json()
    assert "scan_job_id" in body
    assert body["status"] == "pending"
    mock_delay.assert_called_once()


def test_get_scan_status_pending(client: TestClient) -> None:
    with patch("api.routes.scan.run_scan_task.delay"):
        create_response = client.post(
            "/api/scan/repo", json={"repo_url": "https://github.com/example/repo2"}
        )
    scan_job_id = create_response.json()["scan_job_id"]

    status_response = client.get(f"/api/scan/{scan_job_id}")

    assert status_response.status_code == 200
    assert status_response.json()["status"] == "pending"


def test_get_scan_status_404(client: TestClient) -> None:
    response = client.get("/api/scan/nonexistent")
    assert response.status_code == 404


def test_webhook_github_returns_200(client: TestClient) -> None:
    payload = {
        "repository": {"html_url": "https://github.com/example/webhook-repo", "name": "webhook-repo"},
    }
    with patch("api.routes.scan.run_scan_task.delay") as mock_delay:
        response = client.post(
            "/api/scan/webhook/github",
            json=payload,
            headers={"X-GitHub-Event": "push"},
        )

    assert response.status_code == 200
    mock_delay.assert_called_once()


# --------------------------------------------------------------------------------------
# Secrets
# --------------------------------------------------------------------------------------


def test_get_secrets_empty(client: TestClient) -> None:
    response = client.get("/api/secrets")
    assert response.status_code == 200
    assert response.json()["total"] == 0


def test_get_secrets_with_filter(client: TestClient, test_engine) -> None:
    _run(_insert_secrets(test_engine, ["HIGH", "HIGH", "LOW", "MEDIUM"]))

    response = client.get("/api/secrets", params={"severity": "HIGH"})

    assert response.status_code == 200
    body = response.json()
    assert body["total"] == 2
    assert all(s["severity_label"] == "HIGH" for s in body["secrets"])


# --------------------------------------------------------------------------------------
# Developers
# --------------------------------------------------------------------------------------


def test_get_developer_profile_404(client: TestClient) -> None:
    response = client.get("/api/developers/unknown@test.com")
    assert response.status_code == 404


# --------------------------------------------------------------------------------------
# Dashboard
# --------------------------------------------------------------------------------------


def test_get_dashboard_summary(client: TestClient) -> None:
    response = client.get("/api/dashboard/summary")
    assert response.status_code == 200
    body = response.json()
    required_fields = {
        "total_repos_scanned",
        "total_secrets_found",
        "critical_count",
        "high_count",
        "medium_count",
        "low_count",
        "high_risk_developers",
        "last_scan_at",
        "most_common_secret_type",
        "average_severity_score",
    }
    assert required_fields <= body.keys()


# --------------------------------------------------------------------------------------
# API key auth
# --------------------------------------------------------------------------------------


def test_api_key_auth_rejected(client: TestClient, with_api_key: str) -> None:
    response = client.get("/api/secrets")
    assert response.status_code == 401


def test_api_key_auth_accepted(client: TestClient, with_api_key: str) -> None:
    response = client.get("/api/secrets", headers={"X-API-Key": with_api_key})
    assert response.status_code == 200


def test_health_no_auth_required(client: TestClient, with_api_key: str) -> None:
    response = client.get("/api/health")
    assert response.status_code == 200
