"""
profiler/risk_scorer.py

Computes a developer's 0-100 risk score from their leak history: how many
secrets they've leaked, how severe those leaks were, how recently, and
whether they tried to hide any via obfuscation.
"""

from datetime import datetime, timedelta, timezone
from typing import List

from profiler.models import DeveloperProfile, LeakEvent

RISK_LABEL_HIGH_THRESHOLD = 60.0
RISK_LABEL_MEDIUM_THRESHOLD = 30.0

SEVERITY_POINTS = {"CRITICAL": 16, "HIGH": 10, "MEDIUM": 5, "LOW": 2}
SEVERITY_SCORE_CAP = 40.0

RECENCY_WINDOW_DAYS = 90


def _as_utc(dt: datetime) -> datetime:
    """Normalize to timezone-aware UTC so comparisons never raise on mixed naive/aware input."""
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=timezone.utc)


class DeveloperRiskScorer:
    """Turns a developer's LeakEvent history into a 0-100 risk score, label, and trend."""

    def calculate_risk_score(self, leak_events: List[LeakEvent]) -> float:
        """Sum the 4 weighted components (volume + severity + recency + obfuscation)."""
        return round(
            self._volume_score(len(leak_events))
            + self._severity_score(leak_events)
            + self._recency_score(leak_events)
            + self._obfuscation_score(leak_events),
            2,
        )

    def determine_risk_label(self, score: float) -> str:
        """>=60 HIGH, >=30 MEDIUM, else LOW."""
        if score >= RISK_LABEL_HIGH_THRESHOLD:
            return "HIGH"
        if score >= RISK_LABEL_MEDIUM_THRESHOLD:
            return "MEDIUM"
        return "LOW"

    def determine_risk_trend(self, leak_events: List[LeakEvent]) -> str:
        """Compare leak counts in the last 90 days vs the 90 days before that."""
        if not leak_events:
            return "NEW"

        now = datetime.now(timezone.utc)
        recent_cutoff = now - timedelta(days=RECENCY_WINDOW_DAYS)
        previous_cutoff = now - timedelta(days=2 * RECENCY_WINDOW_DAYS)

        recent_count = sum(1 for e in leak_events if _as_utc(e.leaked_at) >= recent_cutoff)
        previous_count = sum(
            1 for e in leak_events if previous_cutoff <= _as_utc(e.leaked_at) < recent_cutoff
        )

        if recent_count == 0 and previous_count == 0:
            return "NEW"  # no data in either comparison window
        if recent_count > previous_count:
            return "WORSENING"
        if recent_count < previous_count:
            return "IMPROVING"
        return "STABLE"

    def score_developer(self, profile: DeveloperProfile) -> DeveloperProfile:
        """Compute and set risk_score, risk_label, and risk_trend on profile, then return it."""
        profile.risk_score = self.calculate_risk_score(profile.leak_events)
        profile.risk_label = self.determine_risk_label(profile.risk_score)
        profile.risk_trend = self.determine_risk_trend(profile.leak_events)
        return profile

    # ------------------------------------------------------------------ components

    def _volume_score(self, leak_count: int) -> float:
        if leak_count == 0:
            return 0.0
        if leak_count == 1:
            return 10.0
        if leak_count <= 3:
            return 20.0
        return 30.0

    def _severity_score(self, leak_events: List[LeakEvent]) -> float:
        total = sum(SEVERITY_POINTS.get(e.severity_label, 0) for e in leak_events)
        return min(float(total), SEVERITY_SCORE_CAP)

    def _recency_score(self, leak_events: List[LeakEvent]) -> float:
        if not leak_events:
            return 0.0
        most_recent = max(_as_utc(e.leaked_at) for e in leak_events)
        days_ago = (datetime.now(timezone.utc) - most_recent).days
        if days_ago <= 30:
            return 20.0
        if days_ago <= 90:
            return 15.0
        if days_ago <= 180:
            return 10.0
        if days_ago <= 365:
            return 5.0
        return 0.0

    def _obfuscation_score(self, leak_events: List[LeakEvent]) -> float:
        return 10.0 if any(e.was_obfuscated for e in leak_events) else 0.0
