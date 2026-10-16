"""Read-only helper queries layered on top of a built CDFGBuilder graph —
used by the dashboard API and any ad-hoc reporting.
"""

from typing import Any, List

from cdfg.cdfg_builder import CDFGBuilder
from cdfg.models import CDFGEdge, SecretLifecycle, SecretNode

_D3_NODE_COLORS = {
    "secret": "#DC2626",
    "commit": "#2563EB",
    "file": "#16A34A",
    "developer": "#EA580C",
}

_NODE_TYPE_BY_NEO4J_LABEL = {"Secret": "secret", "Commit": "commit", "File": "file"}


def find_secrets_by_author(builder: CDFGBuilder, author_email: str) -> List[SecretNode]:
    """Return every secret first introduced (first_seen_author) by author_email."""
    return [
        data["obj"]
        for _, data in builder.graph.nodes(data=True)
        if data.get("type") == "secret" and data["obj"].first_seen_author == author_email
    ]


def find_secrets_in_file(builder: CDFGBuilder, file_path: str) -> List[SecretNode]:
    """Return every secret ever defined, used, or deleted in file_path."""
    file_node_id = builder._file_path_to_node_id.get(file_path)
    if file_node_id is None:
        return []

    secret_node_ids = {
        source_id
        for source_id, target_id, data in builder.graph.edges(data=True)
        if target_id == file_node_id and data.get("edge_type") in ("defined_in", "used_in", "deleted_in")
    }
    return [
        builder.graph.nodes[node_id]["obj"]
        for node_id in secret_node_ids
        if builder.graph.nodes[node_id].get("type") == "secret"
    ]


def find_long_lived_secrets(builder: CDFGBuilder, min_days: int = 30) -> List[SecretLifecycle]:
    """Return the lifecycle of every secret exposed for more than min_days."""
    lifecycles = []
    for secret_hash in builder._secret_hash_to_node_id:
        lifecycle = builder.get_secret_lifecycle(secret_hash)
        if lifecycle is not None and lifecycle.exposure_duration_days > min_days:
            lifecycles.append(lifecycle)
    return lifecycles


def find_cross_file_propagation(builder: CDFGBuilder) -> List[CDFGEdge]:
    """Return every propagates_to edge — secrets spreading from one file to another."""
    return [
        data["obj"]
        for _, _, data in builder.graph.edges(data=True)
        if data.get("edge_type") == "propagates_to"
    ]


def get_timeline(builder: CDFGBuilder) -> List[dict]:
    """Return a chronological list of secret define/use/delete events, oldest first."""
    events = []
    for source_id, target_id, data in builder.graph.edges(data=True):
        edge = data["obj"]
        if edge.edge_type not in ("defined_in", "used_in", "deleted_in"):
            continue

        source_data = builder.graph.nodes[source_id]
        if source_data.get("type") != "secret":
            continue
        secret_node: SecretNode = source_data["obj"]

        target_data = builder.graph.nodes[target_id]
        file_path = target_data["obj"].file_path if target_data.get("type") == "file" else None

        commit_node_id = builder._commit_hash_to_node_id.get(edge.commit_hash)
        author = builder.graph.nodes[commit_node_id]["obj"].author_email if commit_node_id else None

        events.append(
            {
                "timestamp": edge.timestamp,
                "event_type": edge.edge_type,
                "secret_hash": secret_node.secret_hash,
                "author": author,
                "file": file_path,
                "commit": edge.commit_hash,
            }
        )

    events.sort(key=lambda event: event["timestamp"])
    return events


def _d3_label(node_type: str, obj) -> str:
    if node_type == "secret":
        return f"{obj.pattern_name} ({obj.secret_hash[:8]})"
    if node_type == "commit":
        return obj.commit_hash[:8]
    if node_type == "file":
        return obj.file_path
    return getattr(obj, "node_id", "")


def _d3_extra_node_fields(node_type: str, obj) -> dict:
    """Filter/lifecycle-relevant fields the dashboard needs beyond id/label/type/color —
    severity + author + active-status for the severity/developer/deleted-secret filters
    and the Secret Lifecycle tab; file_path so the file filter doesn't have to parse it
    back out of the label.
    """
    if node_type == "secret":
        return {
            "secret_hash": obj.secret_hash,
            "pattern_name": obj.pattern_name,
            "severity": obj.severity_hint,
            "author": obj.first_seen_author,
            "is_active": obj.is_active,
            "first_seen_date": str(obj.first_seen_date),
        }
    if node_type == "commit":
        return {"commit_hash": obj.commit_hash, "author": obj.author_email, "timestamp": str(obj.timestamp)}
    if node_type == "file":
        return {"file_path": obj.file_path}
    return {}


def export_d3_format(builder: CDFGBuilder) -> dict:
    """Format the graph as {nodes: [{id, label, type, color, ...}], links: [{source,
    target, type, timestamp, commit_hash}]} for a D3.js force-directed visualization —
    the extra per-type node fields and per-link timestamp/commit_hash back the
    dashboard's CDFG filter panel and Secret Lifecycle tab (see CDFGGraph.jsx).
    """
    nodes = [
        {
            "id": node_id,
            "label": _d3_label(data.get("type"), data["obj"]),
            "type": data.get("type"),
            "color": _D3_NODE_COLORS.get(data.get("type"), "#6B7280"),
            **_d3_extra_node_fields(data.get("type"), data["obj"]),
        }
        for node_id, data in builder.graph.nodes(data=True)
    ]

    links = [
        {
            "source": source_id,
            "target": target_id,
            "type": data["obj"].edge_type,
            "timestamp": str(data["obj"].timestamp),
            "commit_hash": data["obj"].commit_hash,
        }
        for source_id, target_id, data in builder.graph.edges(data=True)
    ]

    return {"nodes": nodes, "links": links}


def _neo4j_d3_label(node_type: str, node: Any) -> str:
    """Same labeling scheme as _d3_label, but reading a Neo4j Node's flat properties
    (SET n += $props merged every dataclass field on directly) instead of a dataclass.
    """
    if node_type == "secret":
        return f"{node.get('pattern_name', '?')} ({node.get('secret_hash', '')[:8]})"
    if node_type == "commit":
        return node.get("commit_hash", "")[:8]
    if node_type == "file":
        return node.get("file_path", "")
    return node.get("node_id", "")


def _neo4j_extra_node_fields(node_type: str, node: Any) -> dict:
    """Same fields as _d3_extra_node_fields, read from a Neo4j Node's properties instead
    of a dataclass. Temporal properties come back as neo4j.time.DateTime, not stdlib
    datetime — str() on either produces the same ISO-8601 text a JS `new Date(...)` can
    parse, so this stays type-agnostic rather than importing the driver's time module
    just to convert.
    """
    if node_type == "secret":
        first_seen_date = node.get("first_seen_date")
        return {
            "secret_hash": node.get("secret_hash"),
            "pattern_name": node.get("pattern_name"),
            "severity": node.get("severity_hint"),
            "author": node.get("first_seen_author"),
            "is_active": node.get("is_active"),
            "first_seen_date": str(first_seen_date) if first_seen_date is not None else None,
        }
    if node_type == "commit":
        timestamp = node.get("timestamp")
        return {
            "commit_hash": node.get("commit_hash"),
            "author": node.get("author_email"),
            "timestamp": str(timestamp) if timestamp is not None else None,
        }
    if node_type == "file":
        return {"file_path": node.get("file_path")}
    return {}


def load_d3_format_from_neo4j(driver: Any, scan_job_id: str) -> dict:
    """Query Neo4j directly for one scan job's CDFG subgraph, in the same D3 format
    export_d3_format() produces from an in-memory builder.

    Every node/edge synced via CDFGBuilder.sync_to_neo4j(scan_job_id=...) carries that
    id as a plain property, so this is a straight property filter — no in-memory
    CDFGBuilder needs to be reconstructed (and couldn't be; raw commit/diff data isn't
    persisted anywhere once a scan finishes).
    """
    with driver.session() as session:
        node_records = session.run(
            "MATCH (n) WHERE n.scan_job_id = $scan_job_id RETURN n, labels(n) AS labels",
            scan_job_id=scan_job_id,
        )
        nodes = []
        for record in node_records:
            node = record["n"]
            labels = record["labels"]
            node_type = _NODE_TYPE_BY_NEO4J_LABEL.get(labels[0] if labels else None, "unknown")
            nodes.append(
                {
                    "id": node.get("node_id"),
                    "label": _neo4j_d3_label(node_type, node),
                    "type": node_type,
                    "color": _D3_NODE_COLORS.get(node_type, "#6B7280"),
                    **_neo4j_extra_node_fields(node_type, node),
                }
            )

        edge_records = session.run(
            "MATCH (a)-[r:CDFG_EDGE]->(b) WHERE r.scan_job_id = $scan_job_id "
            "RETURN a.node_id AS source, b.node_id AS target, r.edge_type AS type, "
            "r.timestamp AS timestamp, r.commit_hash AS commit_hash",
            scan_job_id=scan_job_id,
        )
        links = [
            {
                "source": record["source"],
                "target": record["target"],
                "type": record["type"],
                "timestamp": str(record["timestamp"]) if record["timestamp"] is not None else None,
                "commit_hash": record["commit_hash"],
            }
            for record in edge_records
        ]

    return {"nodes": nodes, "links": links}
