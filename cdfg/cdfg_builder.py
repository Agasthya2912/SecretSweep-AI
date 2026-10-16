"""Builds the Credential Data Flow Graph (CDFG) with NetworkX, tracing every
secret's birth, usage, deletion, and possible re-appearance across a repo's
full commit history. Neo4j persistence is optional — the graph is fully
usable in-memory when no Neo4j server is available.
"""

import json
import logging
import socket
import uuid
from dataclasses import asdict
from datetime import datetime, timezone
from typing import Dict, List, Optional, Set, Tuple, Union
from urllib.parse import urlparse

import networkx as nx

from cdfg.models import CDFGEdge, CommitNode, FileNode, SecretLifecycle, SecretNode
from obfuscation.obfuscation_scanner import ObfuscationMatch
from scanner.models import CommitData, DiffLine, ScanResult, SemanticResult
from scanner.pattern_scanner import PatternMatch

logger = logging.getLogger(__name__)

Finding = Union[PatternMatch, SemanticResult, ObfuscationMatch]

_EDGE_TYPE_BY_CHANGE_TYPE = {
    "added": "defined_in",
    "deleted": "deleted_in",
    "context": "used_in",
}

_NEO4J_LABEL_BY_NODE_TYPE = {"secret": "Secret", "commit": "Commit", "file": "File"}

_NEO4J_CONNECTION_TIMEOUT_SECONDS = 3.0
_NEO4J_DEFAULT_PORT = 7687


def _tcp_reachable(uri: str, timeout: float) -> bool:
    """Raw-socket reachability pre-check for uri's host:port.

    The neo4j driver's own connection_timeout doesn't reliably bound how long
    verify_connectivity() can take when nothing is listening at all (observed
    taking 20+ minutes in this environment instead of the configured 3s) — a
    plain socket connect attempt gives a real, predictable timeout instead.
    """
    try:
        parsed = urlparse(uri)
        host = parsed.hostname
        if not host:
            return False
        port = parsed.port or _NEO4J_DEFAULT_PORT
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def open_driver_if_reachable(
    neo4j_uri: Optional[str], neo4j_user: Optional[str], neo4j_password: Optional[str]
):
    """Return a connected Neo4j driver, or None if unconfigured/unreachable.

    Shared by CDFGBuilder itself and by any other caller that needs a one-off
    Neo4j connection (the dashboard's graph-read route, the clear-history
    route's graph wipe) without duplicating the reachability pre-check and
    graceful-degradation logic. Caller owns the returned driver and must
    close() it.
    """
    if not (neo4j_uri and neo4j_user and neo4j_password):
        return None
    if not _tcp_reachable(neo4j_uri, _NEO4J_CONNECTION_TIMEOUT_SECONDS):
        logger.warning("Neo4j at %s is not reachable", neo4j_uri)
        return None

    driver = None
    try:
        from neo4j import GraphDatabase

        driver = GraphDatabase.driver(
            neo4j_uri,
            auth=(neo4j_user, neo4j_password),
            connection_timeout=_NEO4J_CONNECTION_TIMEOUT_SECONDS,
        )
        driver.verify_connectivity()
        return driver
    except Exception as exc:
        logger.warning("Neo4j unavailable (%s)", exc)
        if driver is not None:
            driver.close()
        return None


def _normalize_finding(finding: Finding) -> Tuple[str, str, str, str, DiffLine]:
    """Return (secret_hash, raw_value, pattern_name, severity_hint, diff_line) for any finding type.

    raw_value is used only to compute a masked preview (see _mask_secret_value) — it is
    never itself stored on the node or persisted anywhere past that computation.
    """
    if isinstance(finding, SemanticResult):
        pm = finding.pattern_match
        return pm.matched_value_hash, pm.matched_value, pm.pattern_name, pm.severity_hint, pm.line
    if isinstance(finding, PatternMatch):
        return finding.matched_value_hash, finding.matched_value, finding.pattern_name, finding.severity_hint, finding.line
    if isinstance(finding, ObfuscationMatch):
        return finding.decoded_value_hash, finding.decoded_value, finding.pattern_name, finding.severity_hint, finding.line
    raise TypeError(f"Unsupported finding type for CDFG: {type(finding)!r}")


def _mask_secret_value(value: str) -> str:
    """Return a truncated preview (e.g. "AKIA****************FXG") — enough to recognize
    which credential this is, never enough to reuse it. This is what gets persisted and
    shown in the dashboard; the raw value itself never reaches the database (see
    CLAUDE.md's never-store-plaintext convention).
    """
    value = value.strip()
    if len(value) <= 8:
        return value[:2] + "*" * max(3, len(value) - 2)
    return f"{value[:4]}{'*' * 12}{value[-4:]}"


class CDFGBuilder:
    """Builds and queries an in-memory Credential Data Flow Graph, with optional Neo4j sync.

    Uses nx.MultiDiGraph (not a plain DiGraph) because the same two nodes can be
    legitimately connected by more than one edge — e.g. the same secret is "used_in"
    the same file across several different commits, and a plain DiGraph would silently
    overwrite each earlier edge, breaking lifecycle/exposure-duration tracking entirely.
    """

    def __init__(
        self,
        neo4j_uri: Optional[str] = None,
        neo4j_user: Optional[str] = None,
        neo4j_password: Optional[str] = None,
    ) -> None:
        """Initialise the in-memory graph and attempt an optional Neo4j connection.

        Neo4j is entirely optional: any failure to import the driver, connect, or
        authenticate is caught and logged as a warning, and the builder continues
        working purely in-memory.
        """
        self.graph = nx.MultiDiGraph()

        self._secret_hash_to_node_id: Dict[str, str] = {}
        self._commit_hash_to_node_id: Dict[str, str] = {}
        self._file_path_to_node_id: Dict[str, str] = {}

        self._edges_by_secret_hash: Dict[str, List[CDFGEdge]] = {}
        self._propagation_edges_by_secret_hash: Dict[str, List[CDFGEdge]] = {}
        self._propagation_seen: Set[Tuple[str, str]] = set()
        self._author_to_secret_hashes: Dict[str, Set[str]] = {}

        self._current_repo_url = ""

        self.neo4j_driver = open_driver_if_reachable(neo4j_uri, neo4j_user, neo4j_password)
        if self.neo4j_driver is not None:
            logger.info("Connected to Neo4j at %s", neo4j_uri)
        elif neo4j_uri and neo4j_user and neo4j_password:
            logger.warning("Neo4j unavailable — continuing with in-memory graph only")
        else:
            logger.info("No Neo4j credentials provided — using in-memory graph only")

    # ------------------------------------------------------------------ node builders

    def add_secret_node(self, finding: Finding, commit: CommitData) -> SecretNode:
        """Create (or return the existing) SecretNode for finding's secret hash.

        If the secret already exists and this commit predates its recorded
        first-seen date, the node's first-seen fields are backdated to this commit.
        """
        secret_hash, raw_value, pattern_name, severity_hint, diff_line = _normalize_finding(finding)

        existing_node_id = self._secret_hash_to_node_id.get(secret_hash)
        if existing_node_id is not None:
            existing_node: SecretNode = self.graph.nodes[existing_node_id]["obj"]
            if commit.timestamp < existing_node.first_seen_date:
                existing_node.first_seen_commit = commit.hash
                existing_node.first_seen_file = diff_line.file_path
                existing_node.first_seen_line = diff_line.line_number
                existing_node.first_seen_author = commit.author_email
                existing_node.first_seen_date = commit.timestamp
                self._sync_node_attrs(existing_node_id, existing_node)
            return existing_node

        node_id = str(uuid.uuid4())
        secret_node = SecretNode(
            node_id=node_id,
            secret_hash=secret_hash,
            masked_value=_mask_secret_value(raw_value),
            pattern_name=pattern_name,
            severity_hint=severity_hint,
            first_seen_commit=commit.hash,
            first_seen_file=diff_line.file_path,
            first_seen_line=diff_line.line_number,
            first_seen_author=commit.author_email,
            first_seen_date=commit.timestamp,
            is_active=True,
        )
        self.graph.add_node(node_id, type="secret", obj=secret_node)
        self._sync_node_attrs(node_id, secret_node)
        self._secret_hash_to_node_id[secret_hash] = node_id
        return secret_node

    def add_commit_node(self, commit: CommitData) -> CommitNode:
        """Create (or return the existing) CommitNode for commit.hash."""
        existing_node_id = self._commit_hash_to_node_id.get(commit.hash)
        if existing_node_id is not None:
            return self.graph.nodes[existing_node_id]["obj"]

        node_id = str(uuid.uuid4())
        commit_node = CommitNode(
            node_id=node_id,
            commit_hash=commit.hash,
            author_email=commit.author_email,
            timestamp=commit.timestamp,
            message=commit.message,
        )
        self.graph.add_node(node_id, type="commit", obj=commit_node)
        self._sync_node_attrs(node_id, commit_node)
        self._commit_hash_to_node_id[commit.hash] = node_id
        return commit_node

    def add_file_node(self, file_path: str, repo_url: str) -> FileNode:
        """Create (or return the existing) FileNode for file_path, deduplicated by path."""
        existing_node_id = self._file_path_to_node_id.get(file_path)
        if existing_node_id is not None:
            return self.graph.nodes[existing_node_id]["obj"]

        node_id = str(uuid.uuid4())
        file_node = FileNode(node_id=node_id, file_path=file_path, repo_url=repo_url)
        self.graph.add_node(node_id, type="file", obj=file_node)
        self._sync_node_attrs(node_id, file_node)
        self._file_path_to_node_id[file_path] = node_id
        return file_node

    def add_edge(
        self,
        source_id: str,
        target_id: str,
        edge_type: str,
        commit_hash: str,
        timestamp: datetime,
    ) -> CDFGEdge:
        """Add a directed edge to the graph and return the CDFGEdge describing it."""
        edge = CDFGEdge(
            edge_id=str(uuid.uuid4()),
            source_node_id=source_id,
            target_node_id=target_id,
            edge_type=edge_type,
            commit_hash=commit_hash,
            timestamp=timestamp,
        )
        self.graph.add_edge(source_id, target_id, key=edge.edge_id, obj=edge, **asdict(edge))
        return edge

    # ------------------------------------------------------------------ finding processing

    def process_finding(
        self, finding: Finding, commit: CommitData, diff_line: DiffLine
    ) -> SecretLifecycle:
        """Turn a single finding into secret/commit/file nodes and the edges linking them.

        Assumes findings are processed in chronological (oldest-first) commit order —
        the same order GitExtractor.extract_all_commits() naturally yields — since
        is_active is set from whichever edge_type was processed most recently.
        """
        secret_node = self.add_secret_node(finding, commit)
        commit_node = self.add_commit_node(commit)
        file_node = self.add_file_node(diff_line.file_path, self._current_repo_url)

        edge_type = _EDGE_TYPE_BY_CHANGE_TYPE.get(diff_line.change_type, "used_in")

        secret_file_edge = self.add_edge(
            secret_node.node_id, file_node.node_id, edge_type, commit.hash, commit.timestamp
        )
        found_in_edge = self.add_edge(
            secret_node.node_id, commit_node.node_id, "found_in", commit.hash, commit.timestamp
        )
        self._edges_by_secret_hash.setdefault(secret_node.secret_hash, []).extend(
            [secret_file_edge, found_in_edge]
        )

        secret_node.is_active = edge_type != "deleted_in"
        self._sync_node_attrs(secret_node.node_id, secret_node)

        first_file = secret_node.first_seen_file
        if diff_line.file_path != first_file:
            first_file_node_id = self._file_path_to_node_id.get(first_file)
            propagation_key = (secret_node.secret_hash, diff_line.file_path)
            if first_file_node_id is not None and propagation_key not in self._propagation_seen:
                propagation_edge = self.add_edge(
                    first_file_node_id, file_node.node_id, "propagates_to", commit.hash, commit.timestamp
                )
                self._propagation_edges_by_secret_hash.setdefault(secret_node.secret_hash, []).append(
                    propagation_edge
                )
                self._propagation_seen.add(propagation_key)

        # "High risk" tracks who *introduces* secrets, not who touches them — a developer
        # who only deletes/uses an existing secret (cleanup, or code that references it)
        # shouldn't be penalized the same as whoever committed it in the first place.
        if edge_type == "defined_in":
            self._author_to_secret_hashes.setdefault(commit.author_email, set()).add(secret_node.secret_hash)

        return self.get_secret_lifecycle(secret_node.secret_hash)

    def process_scan_result(
        self, scan_result: ScanResult, commits: List[CommitData]
    ) -> List[SecretLifecycle]:
        """Process every confirmed, uncertain, and obfuscation finding into the CDFG."""
        self._current_repo_url = scan_result.repo_url
        commits_by_hash = {c.hash: c for c in commits}
        processed_hashes: Set[str] = set()

        for semantic_result in [*scan_result.confirmed_secrets, *scan_result.uncertain_findings]:
            diff_line = semantic_result.pattern_match.line
            commit = commits_by_hash.get(diff_line.commit_hash)
            if commit is None:
                continue
            self.process_finding(semantic_result, commit, diff_line)
            processed_hashes.add(semantic_result.pattern_match.matched_value_hash)

        for obfuscation_match in scan_result.obfuscation_matches:
            commit = commits_by_hash.get(obfuscation_match.line.commit_hash)
            if commit is None:
                continue
            self.process_finding(obfuscation_match, commit, obfuscation_match.line)
            processed_hashes.add(obfuscation_match.decoded_value_hash)

        for secret_hash in processed_hashes:
            self._infer_usage_edges(secret_hash, commits)

        return [
            lifecycle
            for secret_hash in processed_hashes
            if (lifecycle := self.get_secret_lifecycle(secret_hash)) is not None
        ]

    def _infer_usage_edges(self, secret_hash: str, commits: List[CommitData]) -> None:
        """Synthesize used_in edges for commits that touch a secret's file while the
        secret is known to be present in it, without the secret's own line changing.

        Layer 1 only ever reports added/deleted lines as findings — PatternScanner.
        scan_diff_lines() explicitly skips "context" lines — so the used_in edge_type
        process_finding's _EDGE_TYPE_BY_CHANGE_TYPE mapping supports for context lines
        is never actually reached from real findings; "Used" was always empty in
        practice. This fills that gap after the main pass: any other commit that edits
        the same file during a defined-to-deleted (or defined-to-present, if still
        active) window counts as a touch. That's a much weaker signal than "this exact
        secret was referenced," but it's the only usage signal available without full
        data-flow analysis, and resurrection-aware (each defined/deleted window on a
        file is handled separately, so a resurrected secret's used_in edges stay
        correctly scoped to the window they actually occurred in).
        """
        node_id = self._secret_hash_to_node_id.get(secret_hash)
        if node_id is None:
            return

        by_file: Dict[str, List[CDFGEdge]] = {}
        for edge in self._edges_by_secret_hash.get(secret_hash, []):
            if edge.edge_type in ("defined_in", "deleted_in"):
                by_file.setdefault(edge.target_node_id, []).append(edge)

        for file_node_id, file_edges in by_file.items():
            file_path = self.graph.nodes[file_node_id]["obj"].file_path
            file_edges.sort(key=lambda e: e.timestamp)

            window_start: Optional[datetime] = None
            window_start_hash: Optional[str] = None
            for edge in file_edges:
                if edge.edge_type == "defined_in":
                    if window_start is None:
                        window_start = edge.timestamp
                        window_start_hash = edge.commit_hash
                elif edge.edge_type == "deleted_in" and window_start is not None:
                    self._add_used_in_edges_in_window(
                        secret_hash, node_id, file_node_id, file_path, commits,
                        window_start, window_start_hash, edge.timestamp, edge.commit_hash,
                    )
                    window_start = None
                    window_start_hash = None

            if window_start is not None:  # still active in this file through end of history
                self._add_used_in_edges_in_window(
                    secret_hash, node_id, file_node_id, file_path, commits,
                    window_start, window_start_hash, None, None,
                )

    def _add_used_in_edges_in_window(
        self,
        secret_hash: str,
        secret_node_id: str,
        file_node_id: str,
        file_path: str,
        commits: List[CommitData],
        window_start: datetime,
        window_start_hash: Optional[str],
        window_end: Optional[datetime],
        window_end_hash: Optional[str],
    ) -> None:
        for commit in commits:
            if file_path not in commit.files_changed:
                continue
            if commit.hash in (window_start_hash, window_end_hash):
                continue
            if not (window_start < commit.timestamp and (window_end is None or commit.timestamp < window_end)):
                continue
            used_edge = self.add_edge(secret_node_id, file_node_id, "used_in", commit.hash, commit.timestamp)
            self._edges_by_secret_hash.setdefault(secret_hash, []).append(used_edge)

    # ------------------------------------------------------------------ queries

    def detect_resurrection(self, secret_hash: str) -> bool:
        """True if secret_hash was defined, then deleted, then defined again."""
        edges = sorted(
            (e for e in self._edges_by_secret_hash.get(secret_hash, []) if e.edge_type in ("defined_in", "deleted_in")),
            key=lambda e: e.timestamp,
        )
        seen_defined = False
        seen_deleted_after_defined = False
        for edge in edges:
            if edge.edge_type == "defined_in":
                if seen_deleted_after_defined:
                    return True
                seen_defined = True
            elif edge.edge_type == "deleted_in" and seen_defined:
                seen_deleted_after_defined = True
        return False

    def _resurrection_commits(self, secret_hash: str) -> List[str]:
        edges = sorted(
            (e for e in self._edges_by_secret_hash.get(secret_hash, []) if e.edge_type in ("defined_in", "deleted_in")),
            key=lambda e: e.timestamp,
        )
        seen_deleted = False
        commits: List[str] = []
        for edge in edges:
            if edge.edge_type == "defined_in" and seen_deleted:
                commits.append(edge.commit_hash)
            elif edge.edge_type == "deleted_in":
                seen_deleted = True
        return commits

    def get_secret_lifecycle(self, secret_hash: str) -> Optional[SecretLifecycle]:
        """Assemble the full lifecycle (edges, exposure duration, resurrection) for a secret."""
        node_id = self._secret_hash_to_node_id.get(secret_hash)
        if node_id is None:
            return None
        secret_node: SecretNode = self.graph.nodes[node_id]["obj"]

        edges = self._edges_by_secret_hash.get(secret_hash, [])
        defined_in = [e for e in edges if e.edge_type == "defined_in"]
        used_in = [e for e in edges if e.edge_type == "used_in"]
        deleted_in = [e for e in edges if e.edge_type == "deleted_in"]
        propagates_to = self._propagation_edges_by_secret_hash.get(secret_hash, [])

        exposure_end = self._exposure_end(secret_node, deleted_in)
        exposure_duration_days = max(0, (exposure_end - secret_node.first_seen_date).days)

        is_resurrected = self.detect_resurrection(secret_hash)
        resurrection_commits = self._resurrection_commits(secret_hash) if is_resurrected else []

        return SecretLifecycle(
            secret_node=secret_node,
            defined_in=defined_in,
            used_in=used_in,
            deleted_in=deleted_in,
            propagates_to=propagates_to,
            authored_by=secret_node.first_seen_author,
            exposure_duration_days=exposure_duration_days,
            is_resurrected=is_resurrected,
            resurrection_commits=resurrection_commits,
        )

    def _exposure_end(self, secret_node: SecretNode, deleted_in: List[CDFGEdge]) -> datetime:
        """A still-active secret is exposed up to now; a deleted one, up to its last deletion."""
        if secret_node.is_active or not deleted_in:
            now = datetime.now(timezone.utc)
            if secret_node.first_seen_date.tzinfo is None:
                now = now.replace(tzinfo=None)
            return now
        return max(edge.timestamp for edge in deleted_in)

    def get_high_risk_developers(self, min_secrets: int = 2) -> List[str]:
        """Return authors who introduced at least min_secrets distinct secrets, sorted."""
        return sorted(
            author
            for author, secret_hashes in self._author_to_secret_hashes.items()
            if len(secret_hashes) >= min_secrets
        )

    def get_graph_summary(self) -> dict:
        """Return aggregate counts and the high-risk developer list."""
        node_types = [data.get("type") for _, data in self.graph.nodes(data=True)]
        resurrected_secrets = sum(
            1 for secret_hash in self._secret_hash_to_node_id if self.detect_resurrection(secret_hash)
        )
        return {
            "total_secret_nodes": node_types.count("secret"),
            "total_commit_nodes": node_types.count("commit"),
            "total_file_nodes": node_types.count("file"),
            "total_edges": self.graph.number_of_edges(),
            "unique_secret_hashes": len(self._secret_hash_to_node_id),
            "resurrected_secrets": resurrected_secrets,
            "high_risk_developers": self.get_high_risk_developers(),
        }

    # ------------------------------------------------------------------ export / persistence

    def export_to_json(self, output_path: str) -> None:
        """Serialize the full graph (nodes, edges, summary) to a JSON file."""
        nodes = []
        for node_id, data in self.graph.nodes(data=True):
            node_dict = asdict(data["obj"])
            node_dict["type"] = data["type"]
            nodes.append(node_dict)

        edges = [asdict(data["obj"]) for _, _, data in self.graph.edges(data=True)]

        payload = {"nodes": nodes, "edges": edges, "summary": self.get_graph_summary()}
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2, default=str)
        logger.info("Exported CDFG (%d nodes, %d edges) to %s", len(nodes), len(edges), output_path)

    def sync_to_neo4j(self, scan_job_id: Optional[str] = None) -> bool:
        """Idempotently MERGE all in-memory nodes and edges into Neo4j. False if unavailable.

        scan_job_id, when given, is stamped onto every synced node/edge property so the
        API can later query back just this one scan's subgraph (see
        cdfg/graph_queries.py's load_d3_format_from_neo4j) — Neo4j has no other concept
        of "which scan this came from" otherwise, since MERGE is keyed only on node_id/
        edge_id and the same secret can legitimately reappear across separate scans.
        """
        if self.neo4j_driver is None:
            logger.warning("sync_to_neo4j called with no active Neo4j connection — skipping")
            return False

        try:
            with self.neo4j_driver.session() as session:
                for node_id, data in self.graph.nodes(data=True):
                    label = _NEO4J_LABEL_BY_NODE_TYPE[data["type"]]
                    props = asdict(data["obj"])
                    if scan_job_id:
                        props["scan_job_id"] = scan_job_id
                    session.run(
                        f"MERGE (n:{label} {{node_id: $node_id}}) SET n += $props",
                        node_id=node_id,
                        props=props,
                    )
                    logger.debug("Synced %s node %s", label, node_id)

                for source_id, target_id, data in self.graph.edges(data=True):
                    edge: CDFGEdge = data["obj"]
                    props = asdict(edge)
                    if scan_job_id:
                        props["scan_job_id"] = scan_job_id
                    session.run(
                        "MATCH (a {node_id: $source_id}), (b {node_id: $target_id}) "
                        "MERGE (a)-[r:CDFG_EDGE {edge_id: $edge_id}]->(b) SET r += $props",
                        source_id=source_id,
                        target_id=target_id,
                        edge_id=edge.edge_id,
                        props=props,
                    )
                    logger.debug("Synced edge %s (%s)", edge.edge_id, edge.edge_type)

            logger.info(
                "Synced %d nodes and %d edges to Neo4j",
                self.graph.number_of_nodes(),
                self.graph.number_of_edges(),
            )
            return True
        except Exception as exc:
            logger.error("Neo4j sync failed: %s", exc)
            return False

    def close(self) -> None:
        """Release the Neo4j connection, if one is open. Safe to call even without one."""
        if self.neo4j_driver is not None:
            self.neo4j_driver.close()
            self.neo4j_driver = None

    # ------------------------------------------------------------------ internal helpers

    def _sync_node_attrs(self, node_id: str, obj: Union[SecretNode, CommitNode, FileNode]) -> None:
        """Flatten obj's fields onto the networkx node so plain attribute queries work too."""
        self.graph.nodes[node_id].update(asdict(obj))
        self.graph.nodes[node_id]["obj"] = obj
