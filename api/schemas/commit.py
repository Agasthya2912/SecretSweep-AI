"""Pydantic schemas for the `commits` table."""
import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict


class CommitBase(BaseModel):
    commit_hash: str
    author_name: str
    author_email: str
    message: str | None = None
    committed_at: datetime


class CommitCreate(CommitBase):
    repository_id: uuid.UUID
    developer_id: uuid.UUID | None = None


class CommitRead(CommitBase):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    repository_id: uuid.UUID
    developer_id: uuid.UUID | None = None
    created_at: datetime
