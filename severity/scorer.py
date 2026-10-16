"""
severity/scorer.py

Computes a CRITICAL/HIGH/MEDIUM/LOW severity rating for a finding using
the 5-factor model: secret type, exposure duration, repository visibility,
active-key status, and blast radius.
"""

import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Dict, List, Optional

from cdfg.models import SecretLifecycle

logger = logging.getLogger(__name__)

CRITICAL_THRESHOLD = 35.0
HIGH_THRESHOLD = 25.0
MEDIUM_THRESHOLD = 15.0

DEFAULT_TYPE_SCORE = 4.0


def _normalize_key(name: str) -> str:
    return name.strip().lower().replace(" ", "_").replace("-", "_")


# Keyed by the spec's literal snake_case category names *and* by the real
# pattern_name strings scanner/patterns/secret_patterns.py actually produces
# (e.g. "AWS Access Key ID"), both normalized the same way, so lookups work
# whether the caller passes a spec-style key or a real SecretNode.pattern_name.
_TYPE_SCORES: Dict[str, float] = {
    # --- spec's literal category keys ---
    "aws_root_key": 10.0,
    "aws_access_key": 9.5,
    "gcp_service_account": 9.5,
    "azure_storage_key": 9.0,
    "rsa_private_key": 9.0,
    "ec_private_key": 9.0,
    "ssh_private_key": 9.0,
    "pgp_private_key": 9.0,
    "stripe_live_secret": 9.0,
    "github_token": 8.5,
    "github_oauth": 8.5,
    "github_app_token": 8.5,
    "gitlab_token": 8.0,
    "sendgrid_api_key": 8.0,
    "jwt_token": 7.5,
    "twilio_account_sid": 7.0,
    "stripe_test_secret": 4.0,
    "generic_api_key": 6.0,
    "generic_secret": 5.0,
    "generic_password": 5.0,
    "generic_token": 5.0,
    "mongodb_uri": 7.0,
    "postgresql_uri": 7.0,
    "mysql_uri": 7.0,
    "redis_uri": 6.0,
    # --- real pattern_name strings from scanner/patterns/secret_patterns.py ---
    "aws_access_key_id": 9.5,
    "aws_secret_access_key": 9.5,  # no structural way to distinguish root vs IAM-user keys
    "google_api_key": 8.0,
    "google_oauth_token": 7.5,
    "gcp_service_account_json": 9.5,
    "github_personal_token": 8.5,
    "github_oauth_token": 8.5,
    "github_app_token_real": 8.5,
    "circleci_token": 7.5,
    "stripe_live_secret_key": 9.0,
    "stripe_test_secret_key": 4.0,
    "twilio_auth_token": 8.0,  # the actual credential, more sensitive than the SID alone
    "sendgrid_api_key_real": 8.0,
    "generic_bearer_token": 5.0,
    "mongodb_uri_real": 7.0,
    "postgresql_uri_real": 7.0,
    "mysql_uri_real": 7.0,
    "redis_uri_with_password": 6.0,
    "generic_db_password": 5.0,
    "generic_api_key_real": 6.0,
    "generic_secret_real": 5.0,
    "generic_password_real": 5.0,
    "generic_token_real": 5.0,
}


@dataclass
class SeverityScore:
    """The 5-factor severity breakdown for a single secret."""

    secret_hash: str
    type_score: float  # 0.0 - 10.0
    duration_score: float  # 0.0 - 10.0
    visibility_score: float  # 0.0 - 10.0
    active_score: float  # 0.0 - 5.0 (bonus)
    blast_radius_score: float  # 0.0 - 10.0
    total_score: float  # sum of all factors
    severity_label: str  # CRITICAL/HIGH/MEDIUM/LOW
    scored_at: datetime


class SeverityScorer:
    """Computes 5-factor severity scores for secrets traced by the CDFG."""

    def __init__(self) -> None:
        """Load the pattern-name -> type-score mapping."""
        self._type_scores = _TYPE_SCORES

    def score_secret(
        self,
        lifecycle: SecretLifecycle,
        active_status: str = "unknown",
        repo_visibility: str = "unknown",
        file_count: int = 1,
    ) -> SeverityScore:
        """Score one secret's lifecycle across all 5 factors and label its severity."""
        type_score = self._type_score(lifecycle.secret_node.pattern_name)
        duration_score = self._duration_score(lifecycle.exposure_duration_days)
        visibility_score = self._visibility_score(repo_visibility)
        active_score = self._active_score(active_status)
        blast_radius_score = self._blast_radius_score(file_count)

        total_score = (
            type_score + duration_score + visibility_score + active_score + blast_radius_score
        )

        return SeverityScore(
            secret_hash=lifecycle.secret_node.secret_hash,
            type_score=type_score,
            duration_score=duration_score,
            visibility_score=visibility_score,
            active_score=active_score,
            blast_radius_score=blast_radius_score,
            total_score=round(total_score, 2),
            severity_label=self._severity_label(total_score),
            scored_at=datetime.now(timezone.utc),
        )

    def score_all(
        self,
        lifecycles: List[SecretLifecycle],
        active_statuses: Dict[str, str],
        repo_visibility: str = "unknown",
        file_counts: Optional[Dict[str, int]] = None,
    ) -> List[SeverityScore]:
        """Score every lifecycle and return the results sorted by total_score descending."""
        file_counts = file_counts or {}
        scores = [
            self.score_secret(
                lifecycle,
                active_status=active_statuses.get(lifecycle.secret_node.secret_hash, "unknown"),
                repo_visibility=repo_visibility,
                file_count=file_counts.get(lifecycle.secret_node.secret_hash, 1),
            )
            for lifecycle in lifecycles
        ]
        scores.sort(key=lambda s: s.total_score, reverse=True)
        return scores

    def get_critical_count(self, scores: List[SeverityScore]) -> int:
        """Return how many scores are labeled CRITICAL."""
        return sum(1 for s in scores if s.severity_label == "CRITICAL")

    def get_summary(self, scores: List[SeverityScore]) -> dict:
        """Return per-label counts plus the highest and average total_score."""
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for score in scores:
            counts[score.severity_label.lower()] += 1

        totals = [s.total_score for s in scores]
        return {
            **counts,
            "highest_score": round(max(totals), 2) if totals else 0.0,
            "average_score": round(sum(totals) / len(totals), 2) if totals else 0.0,
        }

    # ------------------------------------------------------------------ factors

    def _type_score(self, pattern_name: str) -> float:
        return self._type_scores.get(_normalize_key(pattern_name), DEFAULT_TYPE_SCORE)

    def _duration_score(self, exposure_duration_days: int) -> float:
        if exposure_duration_days <= 0:
            return 1.0
        if exposure_duration_days <= 7:
            return 3.0
        if exposure_duration_days <= 30:
            return 5.0
        if exposure_duration_days <= 90:
            return 7.0
        if exposure_duration_days <= 365:
            return 9.0
        return 10.0

    def _visibility_score(self, repo_visibility: str) -> float:
        return {"public": 10.0, "private": 5.0}.get(repo_visibility, 7.0)

    def _active_score(self, active_status: str) -> float:
        return {"active": 5.0, "revoked": 0.0}.get(active_status, 2.5)

    def _blast_radius_score(self, file_count: int) -> float:
        if file_count <= 1:
            return 2.0
        if file_count <= 3:
            return 5.0
        if file_count <= 6:
            return 7.0
        return 10.0

    def _severity_label(self, total_score: float) -> str:
        if total_score >= CRITICAL_THRESHOLD:
            return "CRITICAL"
        if total_score >= HIGH_THRESHOLD:
            return "HIGH"
        if total_score >= MEDIUM_THRESHOLD:
            return "MEDIUM"
        return "LOW"
