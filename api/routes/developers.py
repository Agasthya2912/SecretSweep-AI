"""api/routes/developers.py — list, fetch, and plain-text report developer risk profiles."""

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import PlainTextResponse
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from api.db.session import get_db
from api.models.database import DetectedSecret, DeveloperRiskRecord, Repository, ScanJob
from api.schemas.developers import DeveloperProfileResponse, DevelopersListResponse

router = APIRouter(prefix="/api/developers", tags=["developers"])

_RECOMMENDATIONS = {
    "HIGH": "Immediate security training required. Enforce mandatory pre-commit hook.",
    "MEDIUM": "Schedule security awareness session. Review recent commits.",
    "LOW": "Monitor. No immediate action required.",
}


async def _latest_record_or_404(email: str, db: AsyncSession) -> DeveloperRiskRecord:
    result = await db.execute(
        select(DeveloperRiskRecord)
        .where(DeveloperRiskRecord.developer_email == email)
        .order_by(DeveloperRiskRecord.recorded_at.desc())
    )
    record = result.scalars().first()
    if record is None:
        raise HTTPException(status_code=404, detail="Developer not found")
    return record


async def _build_profile_response(record: DeveloperRiskRecord, db: AsyncSession) -> DeveloperProfileResponse:
    secrets = (
        (
            await db.execute(
                select(DetectedSecret).where(DetectedSecret.author_email == record.developer_email)
            )
        )
        .scalars()
        .all()
    )
    secret_types_leaked = sorted({s.pattern_name for s in secrets})

    repos_result = await db.execute(
        select(Repository.url)
        .join(ScanJob, ScanJob.repo_id == Repository.id)
        .join(DetectedSecret, DetectedSecret.scan_job_id == ScanJob.id)
        .where(DetectedSecret.author_email == record.developer_email)
        .distinct()
    )
    repos_affected = [row[0] for row in repos_result.all()]

    return DeveloperProfileResponse(
        developer_email=record.developer_email,
        developer_name=record.developer_name,
        risk_score=record.risk_score,
        risk_label=record.risk_label,
        risk_trend=record.risk_trend,
        total_leaks=record.total_leaks,
        critical_leaks=record.critical_leaks,
        high_leaks=record.high_leaks,
        medium_leaks=record.medium_leaks,
        low_leaks=record.low_leaks,
        repos_affected=repos_affected,
        secret_types_leaked=secret_types_leaked,
        recommendation=_RECOMMENDATIONS.get(record.risk_label, _RECOMMENDATIONS["LOW"]),
    )


@router.get("", response_model=DevelopersListResponse)
async def list_developers(
    risk_label: Optional[str] = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
) -> DevelopersListResponse:
    """List the latest risk record per developer, optionally filtered by risk_label."""
    # Latest record per developer: max(recorded_at) grouped by email.
    latest_subquery = (
        select(
            DeveloperRiskRecord.developer_email,
            func.max(DeveloperRiskRecord.recorded_at).label("max_recorded_at"),
        )
        .group_by(DeveloperRiskRecord.developer_email)
        .subquery()
    )
    query = select(DeveloperRiskRecord).join(
        latest_subquery,
        (DeveloperRiskRecord.developer_email == latest_subquery.c.developer_email)
        & (DeveloperRiskRecord.recorded_at == latest_subquery.c.max_recorded_at),
    )
    if risk_label:
        query = query.where(DeveloperRiskRecord.risk_label == risk_label.upper())

    total = (await db.execute(select(func.count()).select_from(query.subquery()))).scalar_one()
    paged_query = query.order_by(DeveloperRiskRecord.risk_score.desc()).offset((page - 1) * page_size).limit(page_size)
    records = (await db.execute(paged_query)).scalars().all()

    developers = [await _build_profile_response(record, db) for record in records]
    return DevelopersListResponse(total=total, developers=developers)


@router.get("/{email}", response_model=DeveloperProfileResponse)
async def get_developer(email: str, db: AsyncSession = Depends(get_db)) -> DeveloperProfileResponse:
    """Fetch one developer's latest risk profile, including full leak history."""
    record = await _latest_record_or_404(email, db)
    return await _build_profile_response(record, db)


@router.get("/{email}/report", response_class=PlainTextResponse)
async def get_developer_report(email: str, db: AsyncSession = Depends(get_db)) -> str:
    """Plain-English risk report for one developer."""
    record = await _latest_record_or_404(email, db)
    profile = await _build_profile_response(record, db)
    return (
        f"Developer: {profile.developer_email}\n"
        f"Risk Level: {profile.risk_label} (Score: {profile.risk_score}/100)\n"
        f"Total Leaks: {profile.total_leaks}\n"
        f"Critical: {profile.critical_leaks} | High: {profile.high_leaks} | "
        f"Medium: {profile.medium_leaks} | Low: {profile.low_leaks}\n"
        f"Repos Affected: {len(profile.repos_affected)}\n"
        f"Secret Types: {', '.join(profile.secret_types_leaked)}\n"
        f"Trend: {profile.risk_trend}\n"
        f"Recommendation: {profile.recommendation}"
    )
