"""Pydantic schemas for the `developer_risk_scores` table."""
import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict

from api.models.database import RiskTrend


class DeveloperRiskScoreBase(BaseModel):
    period_start: datetime
    period_end: datetime
    leak_count: int = 0
    avg_response_time_hours: float | None = None
    risk_score: float = 0.0
    trend: RiskTrend = RiskTrend.STABLE


class DeveloperRiskScoreCreate(DeveloperRiskScoreBase):
    developer_id: uuid.UUID


class DeveloperRiskScoreRead(DeveloperRiskScoreBase):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    developer_id: uuid.UUID
    created_at: datetime
