"""Pydantic schemas for the `alerts` table."""
import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict

from api.models.database import AlertChannel, AlertStatus


class AlertBase(BaseModel):
    channel: AlertChannel


class AlertCreate(AlertBase):
    finding_id: uuid.UUID


class AlertRead(AlertBase):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    finding_id: uuid.UUID
    status: AlertStatus
    external_reference: str | None = None
    sent_at: datetime | None = None
    created_at: datetime
