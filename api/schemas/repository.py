"""Pydantic schemas for the `repositories` table."""
import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict

from api.models.database import RepositoryProvider, RepositoryVisibility


class RepositoryBase(BaseModel):
    name: str
    url: str
    provider: RepositoryProvider = RepositoryProvider.GITHUB
    visibility: RepositoryVisibility = RepositoryVisibility.PRIVATE
    default_branch: str = "main"


class RepositoryCreate(RepositoryBase):
    pass


class RepositoryUpdate(BaseModel):
    name: str | None = None
    visibility: RepositoryVisibility | None = None
    default_branch: str | None = None


class RepositoryRead(RepositoryBase):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    added_by_id: uuid.UUID | None = None
    last_scanned_at: datetime | None = None
    created_at: datetime
