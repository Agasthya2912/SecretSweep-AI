"""Pydantic response schemas for the dashboard endpoints."""

from typing import Optional
from datetime import datetime

from pydantic import BaseModel


class DashboardSummaryResponse(BaseModel):
    total_repos_scanned: int
    total_secrets_found: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    high_risk_developers: int
    last_scan_at: Optional[datetime] = None
    most_common_secret_type: str
    average_severity_score: float
