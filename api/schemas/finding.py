"""Pydantic schemas for the `findings` table."""
import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict

from api.models.database import DetectionLayer, FindingStatus, Severity


class FindingBase(BaseModel):
    file_path: str
    line_number: int
    redacted_snippet: str
    detection_layer: DetectionLayer
    confidence_score: float = 0.0
    severity: Severity = Severity.LOW
    is_active_key: bool | None = None
    blast_radius_score: float | None = None
    exposure_duration_days: int | None = None


class FindingCreate(FindingBase):
    scan_job_id: uuid.UUID
    repository_id: uuid.UUID
    commit_id: uuid.UUID
    developer_id: uuid.UUID | None = None
    secret_type_id: uuid.UUID


class FindingUpdate(BaseModel):
    status: FindingStatus | None = None
    severity: Severity | None = None
    is_active_key: bool | None = None


class FindingRead(FindingBase):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    scan_job_id: uuid.UUID
    repository_id: uuid.UUID
    commit_id: uuid.UUID
    developer_id: uuid.UUID | None = None
    secret_type_id: uuid.UUID
    status: FindingStatus
    created_at: datetime
    resolved_at: datetime | None = None
