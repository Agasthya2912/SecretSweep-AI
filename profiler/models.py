"""Dataclasses for the developer risk profiler: a single leak event and the
aggregated per-developer profile assembled from them.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Optional


@dataclass
class LeakEvent:
    """One secret attributed to one developer at the commit that introduced it."""

    secret_hash: str
    pattern_name: str
    severity_label: str  # CRITICAL/HIGH/MEDIUM/LOW
    severity_score: float
    commit_hash: str
    file_path: str
    leaked_at: datetime
    repo_url: str
    was_obfuscated: bool  # was it hidden via encoding?


@dataclass
class DeveloperProfile:
    """A developer's aggregated leak history and computed risk assessment."""

    developer_email: str
    developer_name: str
    total_leaks: int = 0
    critical_leaks: int = 0
    high_leaks: int = 0
    medium_leaks: int = 0
    low_leaks: int = 0
    leak_events: List[LeakEvent] = field(default_factory=list)
    repos_affected: List[str] = field(default_factory=list)  # unique repo URLs
    secret_types_leaked: List[str] = field(default_factory=list)  # unique pattern names
    obfuscated_leak_count: int = 0  # leaks that were hidden
    first_leak_date: Optional[datetime] = None
    last_leak_date: Optional[datetime] = None
    risk_score: float = 0.0  # 0.0 - 100.0
    risk_label: str = "LOW"  # HIGH/MEDIUM/LOW
    risk_trend: str = "NEW"  # "IMPROVING" | "WORSENING" | "STABLE" | "NEW"
    generated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
