"""Dataclasses for the Credential Data Flow Graph: nodes, edges, and the
per-secret lifecycle view assembled from them.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import List


@dataclass
class SecretNode:
    """A unique secret (deduplicated by secret_hash) and where it was first seen."""

    node_id: str  # UUID
    secret_hash: str  # SHA256 of secret value
    pattern_name: str  # "aws_access_key" etc
    severity_hint: str  # CRITICAL/HIGH/MEDIUM/LOW
    first_seen_commit: str  # commit hash
    first_seen_file: str  # file path
    first_seen_line: int  # line number
    first_seen_author: str  # author email
    first_seen_date: datetime
    is_active: bool  # still live in latest commit?
    masked_value: str = ""  # truncated preview e.g. "AKIA****************FXG" — never the full value


@dataclass
class CommitNode:
    """A single commit, as a graph node."""

    node_id: str  # UUID
    commit_hash: str
    author_email: str
    timestamp: datetime
    message: str


@dataclass
class FileNode:
    """A single file path within a repository, as a graph node."""

    node_id: str  # UUID
    file_path: str
    repo_url: str


@dataclass
class CDFGEdge:
    """A directed, timestamped relationship between two CDFG nodes."""

    edge_id: str  # UUID
    source_node_id: str
    target_node_id: str
    edge_type: str  # "defined_in" | "used_in" | "deleted_in" | "propagates_to" | "authored_by" | "found_in"
    commit_hash: str  # which commit created this edge
    timestamp: datetime


@dataclass
class SecretLifecycle:
    """The full birth-to-present history of one secret, assembled from CDFG edges."""

    secret_node: SecretNode
    defined_in: List[CDFGEdge] = field(default_factory=list)  # where secret was introduced
    used_in: List[CDFGEdge] = field(default_factory=list)  # where secret was referenced
    deleted_in: List[CDFGEdge] = field(default_factory=list)  # where secret was removed
    propagates_to: List[CDFGEdge] = field(default_factory=list)  # cross-file propagation
    authored_by: str = ""  # developer email
    exposure_duration_days: int = 0  # days between first seen and now (or final deletion)
    is_resurrected: bool = False  # deleted then reappeared?
    resurrection_commits: List[str] = field(default_factory=list)
