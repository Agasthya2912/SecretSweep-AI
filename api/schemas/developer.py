"""Pydantic schemas for the `developers` table."""
import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, EmailStr


class DeveloperBase(BaseModel):
    name: str
    email: EmailStr
    github_username: str | None = None


class DeveloperCreate(DeveloperBase):
    pass


class DeveloperUpdate(BaseModel):
    name: str | None = None
    github_username: str | None = None


class DeveloperRead(DeveloperBase):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    risk_score: float
    total_leaks: int
    created_at: datetime
    updated_at: datetime
