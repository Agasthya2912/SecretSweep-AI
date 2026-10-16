"""Pydantic schemas for the `secret_types` table."""
import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict


class SecretTypeBase(BaseModel):
    name: str
    category: str
    regex_pattern: str | None = None


class SecretTypeCreate(SecretTypeBase):
    pass


class SecretTypeRead(SecretTypeBase):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    created_at: datetime
