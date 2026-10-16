"""SQLAlchemy ORM table models for the SecretSweep AI relational store.

Phase 9 replaced the earlier normalized Phase 1 schema (separate users/
developers/commits/secret_types/findings/alerts tables, PostgreSQL-only
`postgresql.UUID` columns) with this flatter one: it's what the REST API
and Celery scan task actually populate directly from a ScanResult, and it
uses SQLAlchemy's dialect-agnostic `Uuid` type so the same models work
against both PostgreSQL (production) and SQLite (the dev/test fallback in
api/db/session.py — postgresql.UUID has no SQLite equivalent).

The Credential Data Flow Graph (CDFG) itself is persisted in Neo4j via
cdfg/neo4j_client.py, not here.
"""

import uuid

from sqlalchemy import Boolean, Column, DateTime, Float, ForeignKey, Integer, String, Text, Uuid, func
from sqlalchemy.orm import declarative_base, relationship

Base = declarative_base()


def _uuid_pk() -> Column:
    return Column(Uuid, primary_key=True, default=uuid.uuid4)


class Repository(Base):
    """A Git repository that has been (or is being) scanned."""

    __tablename__ = "repositories"

    id = _uuid_pk()
    url = Column(String(1024), nullable=False, unique=True)
    name = Column(String(255), nullable=False)
    is_public = Column(Boolean, nullable=False, default=False)
    last_scanned = Column(DateTime(timezone=True), nullable=True)
    total_secrets_found = Column(Integer, nullable=False, default=0)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    scan_jobs = relationship("ScanJob", back_populates="repository")


class ScanJob(Base):
    """One run of the scan pipeline against a repository."""

    __tablename__ = "scan_jobs"

    id = _uuid_pk()
    repo_id = Column(Uuid, ForeignKey("repositories.id"), nullable=False)
    status = Column(String(20), nullable=False, default="pending")  # pending|running|completed|failed
    started_at = Column(DateTime(timezone=True), server_default=func.now())
    completed_at = Column(DateTime(timezone=True), nullable=True)
    total_commits_scanned = Column(Integer, nullable=False, default=0)
    secrets_found = Column(Integer, nullable=False, default=0)
    error_message = Column(Text, nullable=True)

    repository = relationship("Repository", back_populates="scan_jobs")
    detected_secrets = relationship("DetectedSecret", back_populates="scan_job")
    developer_risk_records = relationship("DeveloperRiskRecord", back_populates="scan_job")


class DetectedSecret(Base):
    """One confirmed secret finding from a scan job.

    Only secret_hash and a truncated masked_value preview (e.g.
    "AKIA****************FXG") are stored — never the raw value — per
    CLAUDE.md's plaintext-secret convention. See cdfg/cdfg_builder.py's
    _mask_secret_value() for where masked_value is computed.
    """

    __tablename__ = "detected_secrets"

    id = _uuid_pk()
    scan_job_id = Column(Uuid, ForeignKey("scan_jobs.id"), nullable=False)
    secret_hash = Column(String(64), nullable=False, index=True)
    masked_value = Column(String(64), nullable=True)
    pattern_name = Column(String(255), nullable=False)
    file_path = Column(String(1024), nullable=False)
    commit_hash = Column(String(64), nullable=False)
    author_email = Column(String(255), nullable=False)
    severity_label = Column(String(20), nullable=False)  # CRITICAL/HIGH/MEDIUM/LOW
    severity_score = Column(Float, nullable=False, default=0.0)
    is_active = Column(Boolean, nullable=False, default=False)
    detected_at = Column(DateTime(timezone=True), server_default=func.now())

    scan_job = relationship("ScanJob", back_populates="detected_secrets")


class DeveloperRiskRecord(Base):
    """A developer's risk snapshot as of one scan job."""

    __tablename__ = "developer_risk_records"

    id = _uuid_pk()
    scan_job_id = Column(Uuid, ForeignKey("scan_jobs.id"), nullable=False)
    developer_email = Column(String(255), nullable=False, index=True)
    developer_name = Column(String(255), nullable=False)
    risk_score = Column(Float, nullable=False, default=0.0)
    risk_label = Column(String(20), nullable=False, default="LOW")  # HIGH/MEDIUM/LOW
    risk_trend = Column(String(20), nullable=False, default="NEW")
    total_leaks = Column(Integer, nullable=False, default=0)
    critical_leaks = Column(Integer, nullable=False, default=0)
    high_leaks = Column(Integer, nullable=False, default=0)
    medium_leaks = Column(Integer, nullable=False, default=0)
    low_leaks = Column(Integer, nullable=False, default=0)
    recorded_at = Column(DateTime(timezone=True), server_default=func.now())

    scan_job = relationship("ScanJob", back_populates="developer_risk_records")
