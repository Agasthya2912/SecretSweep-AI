"""Tests for the Credential Data Flow Graph (cdfg/models.py, cdfg_builder.py,
graph_queries.py) and its integration into ScanPipeline as Layer 4.

Primary fixture (3 commits, oldest to newest):
  commit_1: developer A adds an AWS key to config.py
  commit_2: developer A uses the same key in api.py
  commit_3: developer B deletes the key from config.py (still exists in history)
"""

import hashlib
import json
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Tuple

import pytest

from cdfg.cdfg_builder import CDFGBuilder
from cdfg.graph_queries import export_d3_format, find_long_lived_secrets
from scanner.models import CommitData, DiffLine
from scanner.pattern_scanner import PatternMatch

AWS_KEY = "AKIAIOSFODNN7EXAMPLE"
AWS_HASH = hashlib.sha256(AWS_KEY.encode()).hexdigest()
DEV_A = "devA@example.com"
DEV_B = "devB@example.com"
BASE_TIME = datetime(2024, 1, 1, tzinfo=timezone.utc)


def mk_commit(commit_hash: str, author: str, timestamp: datetime, message: str) -> CommitData:
    return CommitData(
        hash=commit_hash,
        author_name=author.split("@")[0],
        author_email=author,
        timestamp=timestamp,
        message=message,
        branch="main",
        files_changed=[],
    )


def mk_line(file_path: str, line_number: int, content: str, change_type: str, commit_hash: str, author: str) -> DiffLine:
    return DiffLine(
        file_path=file_path,
        line_number=line_number,
        content=content,
        change_type=change_type,
        commit_hash=commit_hash,
        author_email=author,
    )


def mk_pattern_match(line: DiffLine, value: str = AWS_KEY) -> PatternMatch:
    return PatternMatch(
        line=line,
        pattern_name="AWS Access Key ID",
        matched_value=value,
        matched_value_hash=hashlib.sha256(value.encode()).hexdigest(),
        entropy_score=3.7,
        severity_hint="CRITICAL",
        confidence=0.95,
    )


@pytest.fixture()
def three_commit_scenario() -> Tuple[CDFGBuilder, str]:
    """Build the primary add/use/delete-across-two-files-and-two-developers fixture."""
    builder = CDFGBuilder()

    commit_1 = mk_commit("c1", DEV_A, BASE_TIME, "add AWS key")
    commit_2 = mk_commit("c2", DEV_A, BASE_TIME + timedelta(days=5), "use AWS key")
    commit_3 = mk_commit("c3", DEV_B, BASE_TIME + timedelta(days=10), "delete AWS key")

    line_1 = mk_line("config.py", 10, f'aws_key = "{AWS_KEY}"', "added", "c1", DEV_A)
    line_2 = mk_line("api.py", 20, f'client.connect("{AWS_KEY}")', "context", "c2", DEV_A)
    line_3 = mk_line("config.py", 10, f'aws_key = "{AWS_KEY}"', "deleted", "c3", DEV_B)

    builder.process_finding(mk_pattern_match(line_1), commit_1, line_1)
    builder.process_finding(mk_pattern_match(line_2), commit_2, line_2)
    builder.process_finding(mk_pattern_match(line_3), commit_3, line_3)

    return builder, AWS_HASH


# --------------------------------------------------------------------------------------
# Node / edge construction
# --------------------------------------------------------------------------------------


def test_secret_node_created_from_finding() -> None:
    builder = CDFGBuilder()
    commit = mk_commit("c1", DEV_A, BASE_TIME, "add key")
    line = mk_line("config.py", 1, f'k = "{AWS_KEY}"', "added", "c1", DEV_A)

    secret_node = builder.add_secret_node(mk_pattern_match(line), commit)

    assert secret_node.secret_hash == AWS_HASH
    assert secret_node.pattern_name == "AWS Access Key ID"
    assert secret_node.severity_hint == "CRITICAL"
    assert secret_node.first_seen_commit == "c1"
    assert secret_node.first_seen_file == "config.py"


def test_commit_node_created() -> None:
    builder = CDFGBuilder()
    commit = mk_commit("c1", DEV_A, BASE_TIME, "add key")

    commit_node = builder.add_commit_node(commit)

    assert commit_node.commit_hash == "c1"
    assert commit_node.author_email == DEV_A
    node_types = [data.get("type") for _, data in builder.graph.nodes(data=True)]
    assert node_types.count("commit") == 1


def test_file_node_deduplicated() -> None:
    builder = CDFGBuilder()

    first = builder.add_file_node("config.py", "https://example.com/repo")
    second = builder.add_file_node("config.py", "https://example.com/repo")

    assert first.node_id == second.node_id
    node_types = [data.get("type") for _, data in builder.graph.nodes(data=True)]
    assert node_types.count("file") == 1


def test_defined_in_edge_for_added_line(three_commit_scenario: Tuple[CDFGBuilder, str]) -> None:
    builder, secret_hash = three_commit_scenario
    lifecycle = builder.get_secret_lifecycle(secret_hash)

    assert len(lifecycle.defined_in) == 1
    assert lifecycle.defined_in[0].commit_hash == "c1"


def test_deleted_in_edge_for_deleted_line(three_commit_scenario: Tuple[CDFGBuilder, str]) -> None:
    builder, secret_hash = three_commit_scenario
    lifecycle = builder.get_secret_lifecycle(secret_hash)

    assert len(lifecycle.deleted_in) == 1
    assert lifecycle.deleted_in[0].commit_hash == "c3"


# --------------------------------------------------------------------------------------
# Resurrection
# --------------------------------------------------------------------------------------


def test_resurrection_detected() -> None:
    builder = CDFGBuilder()
    commit_1 = mk_commit("r1", DEV_A, BASE_TIME, "add")
    commit_2 = mk_commit("r2", DEV_A, BASE_TIME + timedelta(days=1), "delete")
    commit_3 = mk_commit("r3", DEV_A, BASE_TIME + timedelta(days=2), "re-add")
    line_1 = mk_line("f.py", 1, f'k = "{AWS_KEY}"', "added", "r1", DEV_A)
    line_2 = mk_line("f.py", 1, f'k = "{AWS_KEY}"', "deleted", "r2", DEV_A)
    line_3 = mk_line("f.py", 1, f'k = "{AWS_KEY}"', "added", "r3", DEV_A)

    builder.process_finding(mk_pattern_match(line_1), commit_1, line_1)
    builder.process_finding(mk_pattern_match(line_2), commit_2, line_2)
    builder.process_finding(mk_pattern_match(line_3), commit_3, line_3)

    assert builder.detect_resurrection(AWS_HASH) is True
    lifecycle = builder.get_secret_lifecycle(AWS_HASH)
    assert lifecycle.is_resurrected is True
    assert lifecycle.resurrection_commits == ["r3"]


def test_no_resurrection_when_only_deleted() -> None:
    builder = CDFGBuilder()
    commit_1 = mk_commit("n1", DEV_A, BASE_TIME, "add")
    commit_2 = mk_commit("n2", DEV_A, BASE_TIME + timedelta(days=1), "delete")
    line_1 = mk_line("f.py", 1, f'k = "{AWS_KEY}"', "added", "n1", DEV_A)
    line_2 = mk_line("f.py", 1, f'k = "{AWS_KEY}"', "deleted", "n2", DEV_A)

    builder.process_finding(mk_pattern_match(line_1), commit_1, line_1)
    builder.process_finding(mk_pattern_match(line_2), commit_2, line_2)

    assert builder.detect_resurrection(AWS_HASH) is False


def test_get_secret_lifecycle_returns_full_history(three_commit_scenario: Tuple[CDFGBuilder, str]) -> None:
    builder, secret_hash = three_commit_scenario
    lifecycle = builder.get_secret_lifecycle(secret_hash)

    assert len(lifecycle.defined_in) >= 1
    assert len(lifecycle.deleted_in) >= 1
    assert lifecycle.exposure_duration_days > 0


# --------------------------------------------------------------------------------------
# Developer risk
# --------------------------------------------------------------------------------------


def test_get_high_risk_developers() -> None:
    builder = CDFGBuilder()
    for i in range(3):
        key = f"AKIA{i}EXAMPLEKEY{i}XYZW"
        commit = mk_commit(f"h{i}", DEV_A, BASE_TIME + timedelta(days=i), "add")
        line = mk_line(f"f{i}.py", 1, f'k = "{key}"', "added", f"h{i}", DEV_A)
        builder.process_finding(mk_pattern_match(line, value=key), commit, line)

    # Developer B only ever deletes — never introduces a secret.
    delete_commit = mk_commit("hd", DEV_B, BASE_TIME + timedelta(days=10), "cleanup")
    delete_line = mk_line("f0.py", 1, 'k = "AKIA0EXAMPLEKEY0XYZW"', "deleted", "hd", DEV_B)
    builder.process_finding(mk_pattern_match(delete_line, value="AKIA0EXAMPLEKEY0XYZW"), delete_commit, delete_line)

    high_risk = builder.get_high_risk_developers(min_secrets=2)

    assert DEV_A in high_risk
    assert DEV_B not in high_risk


# --------------------------------------------------------------------------------------
# Graph summary / export
# --------------------------------------------------------------------------------------


def test_graph_summary_counts_correct(three_commit_scenario: Tuple[CDFGBuilder, str]) -> None:
    builder, _ = three_commit_scenario
    summary = builder.get_graph_summary()

    assert summary["total_secret_nodes"] == 1
    assert summary["total_commit_nodes"] == 3
    assert summary["total_file_nodes"] == 2  # config.py, api.py
    assert summary["total_edges"] > 0
    assert summary["unique_secret_hashes"] == 1


def test_export_to_json_creates_file(three_commit_scenario: Tuple[CDFGBuilder, str], tmp_path: Path) -> None:
    builder, _ = three_commit_scenario
    output_path = tmp_path / "graph.json"

    builder.export_to_json(str(output_path))

    assert output_path.exists()
    with output_path.open() as f:
        data = json.load(f)
    assert set(data.keys()) == {"nodes", "edges", "summary"}
    assert len(data["nodes"]) > 0
    assert len(data["edges"]) > 0


def test_d3_format_has_required_fields(three_commit_scenario: Tuple[CDFGBuilder, str]) -> None:
    builder, _ = three_commit_scenario
    d3 = export_d3_format(builder)

    assert "nodes" in d3
    assert "links" in d3
    assert len(d3["nodes"]) > 0
    for node in d3["nodes"]:
        assert {"id", "label", "type", "color"} <= node.keys()


def test_find_long_lived_secrets() -> None:
    builder = CDFGBuilder()
    now = datetime.now(timezone.utc)
    old_key = "AKIAOLDOLDOLDOLDOLDX"
    new_key = "AKIANEWNEWNEWNEWNEWX"

    old_commit = mk_commit("o1", DEV_A, now - timedelta(days=60), "add old")
    new_commit = mk_commit("o2", DEV_A, now - timedelta(days=5), "add new")
    old_line = mk_line("old.py", 1, f'k = "{old_key}"', "added", "o1", DEV_A)
    new_line = mk_line("new.py", 1, f'k = "{new_key}"', "added", "o2", DEV_A)

    builder.process_finding(mk_pattern_match(old_line, value=old_key), old_commit, old_line)
    builder.process_finding(mk_pattern_match(new_line, value=new_key), new_commit, new_line)

    long_lived_hashes = {lc.secret_node.secret_hash for lc in find_long_lived_secrets(builder, min_days=30)}

    assert hashlib.sha256(old_key.encode()).hexdigest() in long_lived_hashes
    assert hashlib.sha256(new_key.encode()).hexdigest() not in long_lived_hashes


# --------------------------------------------------------------------------------------
# Neo4j optional dependency
# --------------------------------------------------------------------------------------


def test_neo4j_graceful_fallback() -> None:
    start = time.monotonic()
    builder = CDFGBuilder(
        neo4j_uri="bolt://localhost:9999", neo4j_user="wrong", neo4j_password="wrong"
    )
    elapsed = time.monotonic() - start

    assert builder.neo4j_driver is None
    assert builder.sync_to_neo4j() is False
    assert elapsed < 30  # fails fast, doesn't hang


# --------------------------------------------------------------------------------------
# Pipeline integration
# --------------------------------------------------------------------------------------


def test_pipeline_layer4_produces_graph_summary() -> None:
    import shutil
    import tempfile

    from scanner.scan_pipeline import ScanPipeline

    tmp_dir = tempfile.mkdtemp()
    try:
        pipeline = ScanPipeline(clone_base_dir=tmp_dir)
        result = pipeline.run("https://github.com/trufflesecurity/test_keys")

        assert result.status == "success"
        assert set(result.graph_summary.keys()) == {
            "total_secret_nodes",
            "total_commit_nodes",
            "total_file_nodes",
            "total_edges",
            "unique_secret_hashes",
            "resurrected_secrets",
            "high_risk_developers",
        }
        assert isinstance(result.lifecycles, list)
        assert isinstance(result.high_risk_developers, list)
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)
