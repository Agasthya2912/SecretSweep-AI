"""Celery task: run the full ScanPipeline and persist results to the database.

1. Mark the ScanJob "running".
2. Run the pipeline (network + model — this is the slow part, hence background).
3. Persist DetectedSecret + DeveloperRiskRecord rows and mark the job
   "completed" (or "failed" with error_message, then re-raise for Celery's
   own retry policy on the task decorator).
"""

import asyncio
import logging
import uuid
from datetime import datetime, timezone

from api.celery_app import celery_app
from api.config import get_settings
from api.db.session import dispose_engine, get_session_factory
from api.models.database import DetectedSecret, DeveloperRiskRecord, ScanJob
from scanner.scan_pipeline import ScanPipeline

logger = logging.getLogger(__name__)


@celery_app.task(bind=True, name="run_scan_task", max_retries=3, retry_backoff=True)
def run_scan_task(
    self,
    scan_job_id: str,
    repo_url: str,
    enable_active_validation: bool = False,
    repo_visibility: str = "unknown",
) -> None:
    """Synchronous Celery entrypoint — delegates to the async pipeline + DB work.

    Each call gets its own `asyncio.run()` (a fresh event loop), but this worker
    process is long-lived across many task invocations. The DB engine in
    api/db/session.py is a process-wide singleton — correct for uvicorn's one
    persistent loop, but its asyncpg connections become invalid the moment *this*
    loop closes. Disposing it (inside the loop, before asyncio.run() returns) forces
    the next invocation — a retry of this same task, or an unrelated later scan — to
    lazily build a brand-new engine bound to its own new loop instead of reusing a
    stale one and raising `InterfaceError: another operation is in progress`.
    """
    try:
        asyncio.run(
            _run_scan_job_and_cleanup(scan_job_id, repo_url, enable_active_validation, repo_visibility)
        )
    except Exception as exc:
        logger.error("Scan job %s failed: %s", scan_job_id, exc)
        asyncio.run(_mark_failed_and_cleanup(scan_job_id, str(exc)))
        raise self.retry(exc=exc)


async def _run_scan_job_and_cleanup(
    scan_job_id: str, repo_url: str, enable_active_validation: bool, repo_visibility: str
) -> None:
    try:
        await _run_scan_job(scan_job_id, repo_url, enable_active_validation, repo_visibility)
    finally:
        await dispose_engine()


async def _mark_failed_and_cleanup(scan_job_id: str, error_message: str) -> None:
    try:
        await _mark_failed(scan_job_id, error_message)
    finally:
        await dispose_engine()


async def _run_scan_job(
    scan_job_id: str, repo_url: str, enable_active_validation: bool, repo_visibility: str
) -> None:
    session_factory = get_session_factory()
    job_uuid = uuid.UUID(scan_job_id)

    async with session_factory() as session:
        scan_job = await session.get(ScanJob, job_uuid)
        if scan_job is None:
            logger.error("ScanJob %s not found — nothing to run", scan_job_id)
            return
        scan_job.status = "running"
        await session.commit()

    settings = get_settings()
    pipeline = ScanPipeline(
        neo4j_uri=settings.neo4j_uri,
        neo4j_user=settings.neo4j_username,
        neo4j_password=settings.neo4j_password,
    )
    result = pipeline.run(
        repo_url,
        enable_active_validation=enable_active_validation,
        repo_visibility=repo_visibility,
        scan_job_id=scan_job_id,
    )

    async with session_factory() as session:
        scan_job = await session.get(ScanJob, job_uuid)
        if scan_job is None:
            return

        if result.status != "success":
            scan_job.status = "failed"
            scan_job.error_message = result.error_message
            await session.commit()
            return

        scan_job.status = "completed"
        scan_job.total_commits_scanned = result.total_commits
        scan_job.secrets_found = result.total_secrets_found
        scan_job.completed_at = datetime.now(timezone.utc)

        lifecycle_by_hash = {lc.secret_node.secret_hash: lc for lc in result.lifecycles}
        for score in result.severity_scores:
            lifecycle = lifecycle_by_hash.get(score.secret_hash)
            if lifecycle is None:
                continue
            session.add(
                DetectedSecret(
                    scan_job_id=job_uuid,
                    secret_hash=score.secret_hash,
                    masked_value=lifecycle.secret_node.masked_value,
                    pattern_name=lifecycle.secret_node.pattern_name,
                    file_path=lifecycle.secret_node.first_seen_file,
                    commit_hash=lifecycle.secret_node.first_seen_commit,
                    author_email=lifecycle.secret_node.first_seen_author,
                    severity_label=score.severity_label,
                    severity_score=score.total_score,
                    is_active=lifecycle.secret_node.is_active,
                )
            )

        for profile in result.developer_profiles:
            session.add(
                DeveloperRiskRecord(
                    scan_job_id=job_uuid,
                    developer_email=profile.developer_email,
                    developer_name=profile.developer_name,
                    risk_score=profile.risk_score,
                    risk_label=profile.risk_label,
                    risk_trend=profile.risk_trend,
                    total_leaks=profile.total_leaks,
                    critical_leaks=profile.critical_leaks,
                    high_leaks=profile.high_leaks,
                    medium_leaks=profile.medium_leaks,
                    low_leaks=profile.low_leaks,
                )
            )

        await session.commit()


async def _mark_failed(scan_job_id: str, error_message: str) -> None:
    session_factory = get_session_factory()
    async with session_factory() as session:
        scan_job = await session.get(ScanJob, uuid.UUID(scan_job_id))
        if scan_job is not None:
            scan_job.status = "failed"
            scan_job.error_message = error_message
            await session.commit()
