"""Pydantic response schemas for the secrets endpoints."""

from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, ConfigDict


class SecretResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    secret_hash: str
    masked_value: Optional[str] = None
    pattern_name: str
    file_path: str
    commit_hash: str
    author_email: str
    severity_label: str
    severity_score: float
    is_active: bool
    detected_at: datetime


class SecretsListResponse(BaseModel):
    total: int
    page: int
    page_size: int
    secrets: List[SecretResponse]
