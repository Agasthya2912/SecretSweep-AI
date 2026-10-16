"""
profiler/developer_profiler.py

Builds per-developer risk profiles from a completed scan: who introduced
which secrets, how severe they were, and what that developer's overall
risk score/label/trend looks like — the organisational-intelligence layer
on top of Layers 1-5.
"""

import json
import logging
from dataclasses import asdict
from typing import Dict, List, TYPE_CHECKING

from profiler.models import DeveloperProfile, LeakEvent
from profiler.risk_scorer import DeveloperRiskScorer

if TYPE_CHECKING:
    from scanner.models import ScanResult

logger = logging.getLogger(__name__)

_RECOMMENDATIONS = {
    "HIGH": "Immediate security training required. Enforce mandatory pre-commit hook.",
    "MEDIUM": "Schedule security awareness session. Review recent commits.",
    "LOW": "Monitor. No immediate action required.",
}


def _derive_display_name(email: str) -> str:
    """Best-effort human-readable name from an email's local part (no richer author
    metadata reaches this layer — CDFG lifecycles only carry the author's email)."""
    local_part = email.split("@")[0]
    return local_part.replace(".", " ").replace("_", " ").replace("-", " ").title()


class DeveloperProfiler:
    """Aggregates CDFG lifecycles + severity scores into per-developer risk profiles."""

    def __init__(self) -> None:
        """Initialise the risk scorer used to score every built profile."""
        self.risk_scorer = DeveloperRiskScorer()

    def build_profiles(self, scan_result: "ScanResult", repo_url: str) -> List[DeveloperProfile]:
        """Build one DeveloperProfile per author found across scan_result.lifecycles,
        scored and sorted by risk_score descending.
        """
        obfuscated_hashes = {m.decoded_value_hash for m in scan_result.obfuscation_matches}
        severity_by_hash = {s.secret_hash: s for s in scan_result.severity_scores}

        profiles_by_email: Dict[str, DeveloperProfile] = {}

        for lifecycle in scan_result.lifecycles:
            email = lifecycle.authored_by or lifecycle.secret_node.first_seen_author
            if not email:
                continue  # can't attribute a leak without an author

            severity_score = severity_by_hash.get(lifecycle.secret_node.secret_hash)
            event = LeakEvent(
                secret_hash=lifecycle.secret_node.secret_hash,
                pattern_name=lifecycle.secret_node.pattern_name,
                severity_label=severity_score.severity_label if severity_score else "LOW",
                severity_score=severity_score.total_score if severity_score else 0.0,
                commit_hash=lifecycle.secret_node.first_seen_commit,
                file_path=lifecycle.secret_node.first_seen_file,
                leaked_at=lifecycle.secret_node.first_seen_date,
                repo_url=repo_url,
                was_obfuscated=lifecycle.secret_node.secret_hash in obfuscated_hashes,
            )

            profile = profiles_by_email.get(email)
            if profile is None:
                profile = DeveloperProfile(developer_email=email, developer_name=_derive_display_name(email))
                profiles_by_email[email] = profile

            self._apply_leak_event(profile, event)

        profiles = list(profiles_by_email.values())
        for profile in profiles:
            self.risk_scorer.score_developer(profile)

        profiles.sort(key=lambda p: p.risk_score, reverse=True)
        return profiles

    def _apply_leak_event(self, profile: DeveloperProfile, event: LeakEvent) -> None:
        profile.leak_events.append(event)
        profile.total_leaks += 1

        if event.severity_label == "CRITICAL":
            profile.critical_leaks += 1
        elif event.severity_label == "HIGH":
            profile.high_leaks += 1
        elif event.severity_label == "MEDIUM":
            profile.medium_leaks += 1
        elif event.severity_label == "LOW":
            profile.low_leaks += 1

        if event.repo_url not in profile.repos_affected:
            profile.repos_affected.append(event.repo_url)
        if event.pattern_name not in profile.secret_types_leaked:
            profile.secret_types_leaked.append(event.pattern_name)
        if event.was_obfuscated:
            profile.obfuscated_leak_count += 1

        if profile.first_leak_date is None or event.leaked_at < profile.first_leak_date:
            profile.first_leak_date = event.leaked_at
        if profile.last_leak_date is None or event.leaked_at > profile.last_leak_date:
            profile.last_leak_date = event.leaked_at

    def get_high_risk_developers(self, profiles: List[DeveloperProfile]) -> List[DeveloperProfile]:
        """Return only the profiles labeled HIGH risk."""
        return [p for p in profiles if p.risk_label == "HIGH"]

    def get_organisation_summary(self, profiles: List[DeveloperProfile]) -> dict:
        """Return org-wide counts and aggregates across every developer profile."""
        if not profiles:
            return {
                "total_developers_with_leaks": 0,
                "high_risk_count": 0,
                "medium_risk_count": 0,
                "low_risk_count": 0,
                "total_leaks_across_all": 0,
                "most_leaked_secret_type": "",
                "average_risk_score": 0.0,
                "developers_with_obfuscated_leaks": 0,
            }

        type_counts: Dict[str, int] = {}
        for profile in profiles:
            for event in profile.leak_events:
                type_counts[event.pattern_name] = type_counts.get(event.pattern_name, 0) + 1
        most_leaked_secret_type = max(type_counts, key=type_counts.get) if type_counts else ""

        return {
            "total_developers_with_leaks": len(profiles),
            "high_risk_count": sum(1 for p in profiles if p.risk_label == "HIGH"),
            "medium_risk_count": sum(1 for p in profiles if p.risk_label == "MEDIUM"),
            "low_risk_count": sum(1 for p in profiles if p.risk_label == "LOW"),
            "total_leaks_across_all": sum(p.total_leaks for p in profiles),
            "most_leaked_secret_type": most_leaked_secret_type,
            "average_risk_score": round(sum(p.risk_score for p in profiles) / len(profiles), 2),
            "developers_with_obfuscated_leaks": sum(1 for p in profiles if p.obfuscated_leak_count > 0),
        }

    def generate_text_report(self, profile: DeveloperProfile) -> str:
        """Plain-English single-developer report, ending in an actionable recommendation."""
        recommendation = _RECOMMENDATIONS[profile.risk_label]
        return (
            f"Developer: {profile.developer_email}\n"
            f"Risk Level: {profile.risk_label} (Score: {profile.risk_score}/100)\n"
            f"Total Leaks: {profile.total_leaks}\n"
            f"Critical: {profile.critical_leaks} | High: {profile.high_leaks} | "
            f"Medium: {profile.medium_leaks} | Low: {profile.low_leaks}\n"
            f"Repos Affected: {len(profile.repos_affected)}\n"
            f"Secret Types: {', '.join(profile.secret_types_leaked)}\n"
            f"Trend: {profile.risk_trend}\n"
            f"Last Leak: {profile.last_leak_date}\n"
            f"Recommendation: {recommendation}"
        )

    def export_profiles_json(self, profiles: List[DeveloperProfile], output_path: str) -> None:
        """Serialize every profile (including nested leak_events) to a JSON file."""
        payload = [asdict(profile) for profile in profiles]
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2, default=str)
        logger.info("Exported %d developer profiles to %s", len(profiles), output_path)
