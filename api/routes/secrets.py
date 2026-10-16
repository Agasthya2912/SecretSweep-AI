"""api/routes/secrets.py — list, fetch, and summarize detected secrets."""

import uuid
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from api.db.session import get_db
from api.models.database import DetectedSecret
from api.schemas.secrets import SecretResponse, SecretsListResponse

router = APIRouter(prefix="/api/secrets", tags=["secrets"])


@router.get("", response_model=SecretsListResponse)
async def list_secrets(
    severity: Optional[str] = None,
    repo_url: Optional[str] = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
) -> SecretsListResponse:
    """List detected secrets, optionally filtered by severity label."""
    query = select(DetectedSecret)
    if severity:
        query = query.where(DetectedSecret.severity_label == severity.upper())
    # repo_url isn't stored directly on DetectedSecret (only reachable via
    # scan_job -> repository); left unfiltered for now, kept as an accepted
    # query param so the dashboard's URL shape is stable once that join lands.
    del repo_url

    total = (await db.execute(select(func.count()).select_from(query.subquery()))).scalar_one()

    paged_query = query.order_by(DetectedSecret.detected_at.desc()).offset((page - 1) * page_size).limit(page_size)
    rows = (await db.execute(paged_query)).scalars().all()

    return SecretsListResponse(
        total=total,
        page=page,
        page_size=page_size,
        secrets=[SecretResponse(id=str(row.id), **_secret_fields(row)) for row in rows],
    )


@router.get("/stats")
async def get_secret_stats(db: AsyncSession = Depends(get_db)) -> dict:
    """Counts by severity label, plus the top 5 most common secret pattern types."""
    severity_result = await db.execute(
        select(DetectedSecret.severity_label, func.count()).group_by(DetectedSecret.severity_label)
    )
    by_severity = {label: count for label, count in severity_result.all()}

    pattern_result = await db.execute(
        select(DetectedSecret.pattern_name, func.count().label("count"))
        .group_by(DetectedSecret.pattern_name)
        .order_by(func.count().desc())
        .limit(5)
    )
    top_patterns = [{"pattern_name": name, "count": count} for name, count in pattern_result.all()]

    return {"by_severity": by_severity, "top_pattern_types": top_patterns}


@router.get("/{secret_id}", response_model=SecretResponse)
async def get_secret(secret_id: str, db: AsyncSession = Depends(get_db)) -> SecretResponse:
    """Fetch a single detected secret by id."""
    try:
        secret_uuid = uuid.UUID(secret_id)
    except ValueError:
        raise HTTPException(status_code=404, detail="Secret not found")

    secret = await db.get(DetectedSecret, secret_uuid)
    if secret is None:
        raise HTTPException(status_code=404, detail="Secret not found")

    return SecretResponse(id=str(secret.id), **_secret_fields(secret))


def _secret_fields(row: DetectedSecret) -> dict:
    return {
        "secret_hash": row.secret_hash,
        "masked_value": row.masked_value,
        "pattern_name": row.pattern_name,
        "file_path": row.file_path,
        "commit_hash": row.commit_hash,
        "author_email": row.author_email,
        "severity_label": row.severity_label,
        "severity_score": row.severity_score,
        "is_active": row.is_active,
        "detected_at": row.detected_at,
    }
