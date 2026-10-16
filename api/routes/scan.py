"""api/routes/scan.py — trigger scans, check status/results, receive GitHub webhooks."""

import asyncio
import hashlib
import hmac
import logging
import uuid

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from api.config import get_settings
from api.db.session import get_db
from api.models.database import DetectedSecret, DeveloperRiskRecord, Repository, ScanJob
from api.schemas.scan import ScanRequest, ScanResponse, ScanStatusResponse
from api.tasks.scan_task import run_scan_task
from cdfg.cdfg_builder import open_driver_if_reachable

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/scan", tags=["scan"])


DISPATCH_TIMEOUT_SECONDS = 2.0
CLEAR_NEO4J_TIMEOUT_SECONDS = 5.0


async def _dispatch_scan_task(scan_job_id: str, repo_url: str, enable_active_validation: bool, repo_visibility: str) -> None:
    """Hand off to Celery without letting a down broker freeze the whole API.

    .delay() is synchronous and, when the broker is unreachable, can spend
    several seconds on connection retries — calling it directly inside an
    `async def` route would block FastAPI's entire event loop (every other
    request too) for that whole time. Running it in a worker thread off the
    loop, under a short bounded timeout, keeps the response prompt either way:
    the job simply stays "pending" if dispatch fails, rather than the request
    hanging or 500ing.
    """
    try:
        await asyncio.wait_for(
            asyncio.to_thread(
                run_scan_task.delay, scan_job_id, repo_url, enable_active_validation, repo_visibility
            ),
            timeout=DISPATCH_TIMEOUT_SECONDS,
        )
    except Exception as exc:
        logger.warning("Could not dispatch scan task %s for %s: %s", scan_job_id, repo_url, exc)


def _clear_neo4j_graph_sync() -> None:
    """Blocking: best-effort wipe of every CDFG node/edge in Neo4j."""
    settings = get_settings()
    driver = open_driver_if_reachable(settings.neo4j_uri, settings.neo4j_username, settings.neo4j_password)
    if driver is None:
        return
    try:
        with driver.session() as session:
            session.run("MATCH (n) DETACH DELETE n")
    finally:
        driver.close()


async def _clear_neo4j_graph() -> None:
    """Off-loop, bounded — Neo4j being down must not fail the relational-DB clear."""
    try:
        await asyncio.wait_for(
            asyncio.to_thread(_clear_neo4j_graph_sync), timeout=CLEAR_NEO4J_TIMEOUT_SECONDS
        )
    except Exception as exc:
        logger.warning("Could not clear Neo4j graph data: %s", exc)


async def _get_scan_job_or_404(scan_job_id: str, db: AsyncSession) -> ScanJob:
    try:
        job_uuid = uuid.UUID(scan_job_id)
    except ValueError:
        raise HTTPException(status_code=404, detail="Scan job not found")

    scan_job = await db.get(ScanJob, job_uuid)
    if scan_job is None:
        raise HTTPException(status_code=404, detail="Scan job not found")
    return scan_job


async def _get_or_create_repository(repo_url: str, db: AsyncSession) -> Repository:
    result = await db.execute(select(Repository).where(Repository.url == repo_url))
    repository = result.scalar_one_or_none()
    if repository is None:
        repository = Repository(url=repo_url, name=repo_url.rstrip("/").split("/")[-1])
        db.add(repository)
        await db.flush()
    return repository


@router.post("/repo", response_model=ScanResponse)
async def start_scan(payload: ScanRequest, db: AsyncSession = Depends(get_db)) -> ScanResponse:
    """Create a pending ScanJob and hand it off to the Celery worker."""
    repository = await _get_or_create_repository(payload.repo_url, db)

    scan_job = ScanJob(repo_id=repository.id, status="pending")
    db.add(scan_job)
    await db.commit()
    await db.refresh(scan_job)

    await _dispatch_scan_task(
        str(scan_job.id), payload.repo_url, payload.enable_active_validation, payload.repo_visibility
    )

    return ScanResponse(
        scan_job_id=str(scan_job.id), status=scan_job.status, message="Scan queued"
    )


@router.delete("")
async def clear_scan_history(db: AsyncSession = Depends(get_db)) -> dict:
    """Delete every scan job, finding, and developer risk record — a full reset.

    No FK cascade is declared on these tables (see api/models/database.py), so
    children are deleted explicitly before their parents. Repositories are cleared
    too since their denormalized last_scanned/total_secrets_found would otherwise
    go stale. The Neo4j CDFG graph is wiped best-effort: a down Neo4j must not
    block clearing the primary (relational) scan history.
    """
    await db.execute(delete(DetectedSecret))
    await db.execute(delete(DeveloperRiskRecord))
    await db.execute(delete(ScanJob))
    await db.execute(delete(Repository))
    await db.commit()

    await _clear_neo4j_graph()

    return {"status": "cleared"}


@router.get("/{scan_job_id}", response_model=ScanStatusResponse)
async def get_scan_status(scan_job_id: str, db: AsyncSession = Depends(get_db)) -> ScanStatusResponse:
    """Return a ScanJob's current status."""
    scan_job = await _get_scan_job_or_404(scan_job_id, db)
    return ScanStatusResponse(
        scan_job_id=str(scan_job.id),
        status=scan_job.status,
        started_at=scan_job.started_at,
        completed_at=scan_job.completed_at,
        total_commits_scanned=scan_job.total_commits_scanned,
        secrets_found=scan_job.secrets_found,
        error_message=scan_job.error_message,
    )


@router.get("/{scan_job_id}/results")
async def get_scan_results(scan_job_id: str, db: AsyncSession = Depends(get_db)):
    """Return full results once a scan has finished; 202 while still pending/running."""
    scan_job = await _get_scan_job_or_404(scan_job_id, db)

    if scan_job.status in ("pending", "running"):
        return JSONResponse(
            status_code=202, content={"status": scan_job.status, "message": "Scan still in progress"}
        )

    secrets = (
        (await db.execute(select(DetectedSecret).where(DetectedSecret.scan_job_id == scan_job.id)))
        .scalars()
        .all()
    )
    developers = (
        (
            await db.execute(
                select(DeveloperRiskRecord).where(DeveloperRiskRecord.scan_job_id == scan_job.id)
            )
        )
        .scalars()
        .all()
    )

    severity_summary = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for secret in secrets:
        key = secret.severity_label.lower()
        if key in severity_summary:
            severity_summary[key] += 1

    org_summary = {
        "total_developers_with_leaks": len(developers),
        "high_risk_count": sum(1 for d in developers if d.risk_label == "HIGH"),
        "medium_risk_count": sum(1 for d in developers if d.risk_label == "MEDIUM"),
        "low_risk_count": sum(1 for d in developers if d.risk_label == "LOW"),
    }

    return {
        "scan_job_id": str(scan_job.id),
        "status": scan_job.status,
        "total_commits_scanned": scan_job.total_commits_scanned,
        "secrets_found": scan_job.secrets_found,
        "error_message": scan_job.error_message,
        "severity_summary": severity_summary,
        "org_summary": org_summary,
        "secrets": [
            {
                "id": str(s.id),
                "secret_hash": s.secret_hash,
                "pattern_name": s.pattern_name,
                "severity_label": s.severity_label,
                "severity_score": s.severity_score,
            }
            for s in secrets
        ],
        "developers": [
            {
                "developer_email": d.developer_email,
                "risk_score": d.risk_score,
                "risk_label": d.risk_label,
            }
            for d in developers
        ],
    }


@router.post("/webhook/github")
async def github_webhook(request: Request, db: AsyncSession = Depends(get_db)):
    """Trigger a scan on push/pull_request events; verifies X-Hub-Signature-256 when configured."""
    settings = get_settings()
    body = await request.body()

    if settings.github_webhook_secret:
        signature = request.headers.get("X-Hub-Signature-256", "")
        expected = "sha256=" + hmac.new(
            settings.github_webhook_secret.encode("utf-8"), body, hashlib.sha256
        ).hexdigest()
        if not hmac.compare_digest(signature, expected):
            raise HTTPException(status_code=401, detail="Invalid webhook signature")

    payload = await request.json()
    event_type = request.headers.get("X-GitHub-Event", "")
    repo_url = (payload.get("repository") or {}).get("html_url")

    if event_type in ("push", "pull_request") and repo_url:
        repository = await _get_or_create_repository(repo_url, db)
        scan_job = ScanJob(repo_id=repository.id, status="pending")
        db.add(scan_job)
        await db.commit()
        await db.refresh(scan_job)
        await _dispatch_scan_task(str(scan_job.id), repo_url, False, "unknown")
        logger.info("Webhook queued scan %s for %s (%s)", scan_job.id, repo_url, event_type)

    return {"status": "received"}
