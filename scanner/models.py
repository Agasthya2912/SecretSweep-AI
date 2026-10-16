"""Shared dataclasses passed between the Git extraction engine and the scan pipeline."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import TYPE_CHECKING, Dict, List, Optional

if TYPE_CHECKING:
    # Deferred to avoid circular imports: pattern_scanner.py, obfuscation_scanner.py,
    # cdfg_builder.py, severity/scorer.py, and profiler/developer_profiler.py all
    # import from here.
    from cdfg.models import SecretLifecycle
    from obfuscation.obfuscation_scanner import ObfuscationMatch
    from profiler.models import DeveloperProfile
    from scanner.pattern_scanner import PatternMatch
    from severity.scorer import SeverityScore


@dataclass
class CommitData:
    """A single non-merge commit, extracted chronologically from a repository's history."""

    hash: str
    author_name: str
    author_email: str
    timestamp: datetime
    message: str
    branch: str
    files_changed: List[str] = field(default_factory=list)


@dataclass
class DiffLine:
    """One line of a commit's diff, tagged with whether it was added, deleted, or context.

    Deleted lines are kept (not discarded) because a secret removed from the working
    tree in a later commit still exists in the repository's history.
    """

    file_path: str
    line_number: int
    content: str
    change_type: str  # "added" | "deleted" | "context"
    commit_hash: str
    author_email: str


@dataclass
class SemanticResult:
    """Layer 2 (CodeBERT) verdict on a single Layer 1 PatternMatch.

    context_snippet is the ~20-line window (10 before + flagged + 10 after)
    the model actually saw, kept for auditability of why it classified as it did.
    """

    pattern_match: "PatternMatch"
    is_secret: bool
    confidence: float  # 0.0 to 1.0
    semantic_label: str  # "confirmed_secret" | "false_positive" | "uncertain"
    context_snippet: str
    model_version: str  # "codebert-finetuned" or "codebert-base"


@dataclass
class ScanResult:
    """Outcome of a single ScanPipeline.run() invocation."""

    repo_url: str
    local_path: str
    status: str  # "success" | "failed"
    total_commits: int
    started_at: datetime
    completed_at: datetime
    error_message: Optional[str] = None
    pattern_matches: List["PatternMatch"] = field(default_factory=list)
    total_pattern_matches: int = 0
    semantic_results: List[SemanticResult] = field(default_factory=list)
    confirmed_secrets: List[SemanticResult] = field(default_factory=list)
    uncertain_findings: List[SemanticResult] = field(default_factory=list)
    false_positives_removed: int = 0
    total_secrets_found: int = 0
    obfuscation_matches: List["ObfuscationMatch"] = field(default_factory=list)
    total_obfuscation_findings: int = 0
    lifecycles: List["SecretLifecycle"] = field(default_factory=list)
    graph_summary: dict = field(default_factory=dict)
    high_risk_developers: List[str] = field(default_factory=list)
    severity_scores: List["SeverityScore"] = field(default_factory=list)
    severity_summary: dict = field(default_factory=dict)
    active_statuses: Dict[str, str] = field(default_factory=dict)
    developer_profiles: List["DeveloperProfile"] = field(default_factory=list)
    organisation_summary: dict = field(default_factory=dict)
