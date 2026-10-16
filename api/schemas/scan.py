"""Pydantic request/response schemas for the scan endpoints."""

from datetime import datetime
from typing import Optional

from pydantic import BaseModel


class ScanRequest(BaseModel):
    repo_url: str
    enable_active_validation: bool = False
    repo_visibility: str = "unknown"


class ScanResponse(BaseModel):
    scan_job_id: str
    status: str
    message: str


class ScanStatusResponse(BaseModel):
    scan_job_id: str
    status: str
    started_at: datetime
    completed_at: Optional[datetime] = None
    total_commits_scanned: int
    secrets_found: int
    error_message: Optional[str] = None
