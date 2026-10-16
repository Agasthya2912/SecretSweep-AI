"""Pydantic response schemas for the developers endpoints."""

from typing import List

from pydantic import BaseModel


class DeveloperProfileResponse(BaseModel):
    developer_email: str
    developer_name: str
    risk_score: float
    risk_label: str
    risk_trend: str
    total_leaks: int
    critical_leaks: int
    high_leaks: int
    medium_leaks: int
    low_leaks: int
    repos_affected: List[str]
    secret_types_leaked: List[str]
    recommendation: str


class DevelopersListResponse(BaseModel):
    total: int
    developers: List[DeveloperProfileResponse]
