"""api/routes/dashboard.py — aggregated cross-scan summary, timeline, and CDFG export."""

import asyncio
import logging

from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from api.config import get_settings
from api.db.session import get_db
from api.models.database import DetectedSecret, DeveloperRiskRecord, Repository, ScanJob
from api.schemas.dashboard import DashboardSummaryResponse
from cdfg.cdfg_builder import open_driver_if_reachable
from cdfg.graph_queries import load_d3_format_from_neo4j

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/dashboard", tags=["dashboard"])

GRAPH_QUERY_TIMEOUT_SECONDS = 5.0


@router.get("/summary", response_model=DashboardSummaryResponse)
async def get_dashboard_summary(db: AsyncSession = Depends(get_db)) -> DashboardSummaryResponse:
    """Aggregate counts and averages across every scan ever run."""
    total_repos = (await db.execute(select(func.count()).select_from(Repository))).scalar_one()
    total_secrets = (await db.execute(select(func.count()).select_from(DetectedSecret))).scalar_one()

    severity_result = await db.execute(
        select(DetectedSecret.severity_label, func.count()).group_by(DetectedSecret.severity_label)
    )
    by_severity = {label: count for label, count in severity_result.all()}

    high_risk_developers = (
        await db.execute(
            select(func.count())
            .select_from(DeveloperRiskRecord)
            .where(DeveloperRiskRecord.risk_label == "HIGH")
        )
    ).scalar_one()

    last_scan_at = (await db.execute(select(func.max(ScanJob.completed_at)))).scalar_one()

    top_pattern_row = (
        await db.execute(
            select(DetectedSecret.pattern_name, func.count().label("count"))
            .group_by(DetectedSecret.pattern_name)
            .order_by(func.count().desc())
            .limit(1)
        )
    ).first()
    most_common_secret_type = top_pattern_row[0] if top_pattern_row else ""

    average_severity_score = (await db.execute(select(func.avg(DetectedSecret.severity_score)))).scalar_one() or 0.0

    return DashboardSummaryResponse(
        total_repos_scanned=total_repos,
        total_secrets_found=total_secrets,
        critical_count=by_severity.get("CRITICAL", 0),
        high_count=by_severity.get("HIGH", 0),
        medium_count=by_severity.get("MEDIUM", 0),
        low_count=by_severity.get("LOW", 0),
        high_risk_developers=high_risk_developers,
        last_scan_at=last_scan_at,
        most_common_secret_type=most_common_secret_type,
        average_severity_score=round(float(average_severity_score), 2),
    )


@router.get("/timeline")
async def get_timeline(db: AsyncSession = Depends(get_db)) -> list:
    """Chronological list of scan events: [{date, event_type, repo, count}]."""
    result = await db.execute(select(ScanJob).order_by(ScanJob.started_at))
    scan_jobs = result.scalars().all()

    events = []
    for job in scan_jobs:
        repository = await db.get(Repository, job.repo_id)
        events.append(
            {
                "date": job.started_at,
                "event_type": f"scan_{job.status}",
                "repo": repository.url if repository else None,
                "count": job.secrets_found,
            }
        )
    return events


def _load_graph_sync(scan_job_id: str) -> dict:
    """Blocking: open a one-off Neo4j driver and query scan_job_id's synced subgraph."""
    settings = get_settings()
    driver = open_driver_if_reachable(settings.neo4j_uri, settings.neo4j_username, settings.neo4j_password)
    if driver is None:
        return {"nodes": [], "links": []}
    try:
        return load_d3_format_from_neo4j(driver, scan_job_id)
    finally:
        driver.close()


@router.get("/graph/{scan_job_id}")
async def get_scan_graph(scan_job_id: str) -> dict:
    """CDFG in D3.js format for one scan job, loaded from Neo4j.

    Every scan syncs its in-memory graph to Neo4j tagged with its scan_job_id (see
    ScanPipeline.run() / CDFGBuilder.sync_to_neo4j()); this queries that subgraph back
    out. The neo4j driver is synchronous, so per CLAUDE.md's rule against blocking the
    event loop this runs in a worker thread under a bounded timeout — degrading to an
    empty graph (not a 500) rather than freezing the API if Neo4j is slow or down.
    """
    try:
        return await asyncio.wait_for(
            asyncio.to_thread(_load_graph_sync, scan_job_id), timeout=GRAPH_QUERY_TIMEOUT_SECONDS
        )
    except Exception as exc:
        logger.warning("Graph query failed for scan %s: %s", scan_job_id, exc)
        return {"nodes": [], "links": []}
