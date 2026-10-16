"""Pydantic schemas for the `scan_jobs` table."""
import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict

from api.models.database import ScanStatus, ScanTrigger


class ScanJobBase(BaseModel):
    triggered_by: ScanTrigger = ScanTrigger.MANUAL


class ScanJobCreate(ScanJobBase):
    repository_id: uuid.UUID


class ScanJobRead(ScanJobBase):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    repository_id: uuid.UUID
    status: ScanStatus
    started_at: datetime | None = None
    completed_at: datetime | None = None
    total_commits_scanned: int
    total_findings: int
    created_at: datetime
