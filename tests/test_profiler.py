"""Tests for the developer risk profiler (profiler/models.py, risk_scorer.py,
developer_profiler.py) and its integration into ScanPipeline as Layer 6.

Synthetic scenario (matches the spec's own worked examples):
  developer_a@company.com: 3 leaks — CRITICAL (20d ago), HIGH (60d ago), MEDIUM (200d ago)
  developer_b@company.com: 1 leak  — LOW (400d ago)
  developer_c@company.com: 2 leaks — both HIGH (15d ago), 1 obfuscated
"""

import json
import uuid
from datetime import datetime, timedelta, timezone
from typing import List, Tuple

import pytest

from cdfg.models import SecretLifecycle, SecretNode
from obfuscation.obfuscation_scanner import ObfuscationMatch
from profiler.developer_profiler import DeveloperProfiler
from profiler.models import DeveloperProfile, LeakEvent
from profiler.risk_scorer import DeveloperRiskScorer
from scanner.models import DiffLine, ScanResult
from severity.scorer import SeverityScore

NOW = datetime.now(timezone.utc)
REPO_URL = "https://example.com/repo"


def mk_lifecycle(
    secret_hash: str,
    pattern_name: str,
    author: str,
    days_ago: int,
    file_path: str = "config.py",
    commit_hash: str = "c1",
) -> SecretLifecycle:
    node = SecretNode(
        node_id=str(uuid.uuid4()),
        secret_hash=secret_hash,
        pattern_name=pattern_name,
        severity_hint="HIGH",
        first_seen_commit=commit_hash,
        first_seen_file=file_path,
        first_seen_line=1,
        first_seen_author=author,
        first_seen_date=NOW - timedelta(days=days_ago),
        is_active=True,
    )
    return SecretLifecycle(secret_node=node, authored_by=author, exposure_duration_days=days_ago)


def mk_severity(secret_hash: str, label: str, total: float = 0.0) -> SeverityScore:
    return SeverityScore(
        secret_hash=secret_hash,
        type_score=0.0,
        duration_score=0.0,
        visibility_score=0.0,
        active_score=0.0,
        blast_radius_score=0.0,
        total_score=total,
        severity_label=label,
        scored_at=NOW,
    )


def mk_leak_event(days_ago: int, severity_label: str = "HIGH", was_obfuscated: bool = False) -> LeakEvent:
    return LeakEvent(
        secret_hash=str(uuid.uuid4()),
        pattern_name="GitHub Personal Token",
        severity_label=severity_label,
        severity_score=0.0,
        commit_hash="c1",
        file_path="config.py",
        leaked_at=NOW - timedelta(days=days_ago),
        repo_url=REPO_URL,
        was_obfuscated=was_obfuscated,
    )


def build_three_developer_scenario() -> Tuple[List[SecretLifecycle], List[SeverityScore], List[ObfuscationMatch]]:
    lifecycles = [
        mk_lifecycle("a1", "AWS Access Key ID", "developer_a@company.com", 20),
        mk_lifecycle("a2", "GitHub Personal Token", "developer_a@company.com", 60),
        mk_lifecycle("a3", "Generic Secret", "developer_a@company.com", 200),
        mk_lifecycle("b1", "Stripe Test Secret Key", "developer_b@company.com", 400),
        mk_lifecycle("c1", "GitHub Personal Token", "developer_c@company.com", 15),
        mk_lifecycle("c2", "GitHub Personal Token", "developer_c@company.com", 15),
    ]
    severities = [
        mk_severity("a1", "CRITICAL", 40),
        mk_severity("a2", "HIGH", 28),
        mk_severity("a3", "MEDIUM", 18),
        mk_severity("b1", "LOW", 10),
        mk_severity("c1", "HIGH", 28),
        mk_severity("c2", "HIGH", 28),
    ]
    obf_line = DiffLine(
        file_path="config.py", line_number=1, content="x", change_type="added",
        commit_hash="c1", author_email="developer_c@company.com",
    )
    obfuscation_matches = [
        ObfuscationMatch(
            line=obf_line, obfuscation_type="base64", original_value="xx", decoded_value="yy",
            decoded_value_hash="c1", pattern_name="GitHub Personal Token", severity_hint="HIGH",
            confidence=0.9,
        )
    ]
    return lifecycles, severities, obfuscation_matches


@pytest.fixture()
def profiler() -> DeveloperProfiler:
    return DeveloperProfiler()


@pytest.fixture()
def profiles(profiler: DeveloperProfiler) -> List[DeveloperProfile]:
    lifecycles, severities, obfuscation_matches = build_three_developer_scenario()
    scan_result = ScanResult(
        repo_url=REPO_URL, local_path="x", status="success", total_commits=6,
        started_at=NOW, completed_at=NOW, lifecycles=lifecycles, severity_scores=severities,
        obfuscation_matches=obfuscation_matches,
    )
    return profiler.build_profiles(scan_result, REPO_URL)


def get_profile(profiles: List[DeveloperProfile], email: str) -> DeveloperProfile:
    return next(p for p in profiles if p.developer_email == email)


# --------------------------------------------------------------------------------------
# Profile building
# --------------------------------------------------------------------------------------


def test_profile_created_per_developer(profiles: List[DeveloperProfile]) -> None:
    assert len(profiles) == 3
    emails = {p.developer_email for p in profiles}
    assert emails == {"developer_a@company.com", "developer_b@company.com", "developer_c@company.com"}


def test_total_leaks_counted_correctly(profiles: List[DeveloperProfile]) -> None:
    dev_a = get_profile(profiles, "developer_a@company.com")
    assert dev_a.total_leaks == 3


def test_severity_breakdown_correct(profiles: List[DeveloperProfile]) -> None:
    dev_a = get_profile(profiles, "developer_a@company.com")
    assert dev_a.critical_leaks == 1
    assert dev_a.high_leaks == 1
    assert dev_a.medium_leaks == 1
    assert dev_a.low_leaks == 0


# --------------------------------------------------------------------------------------
# Risk scoring
# --------------------------------------------------------------------------------------


def test_risk_score_developer_a(profiles: List[DeveloperProfile]) -> None:
    dev_a = get_profile(profiles, "developer_a@company.com")
    assert dev_a.risk_score >= 60.0
    assert dev_a.risk_label == "HIGH"


def test_risk_score_developer_b(profiles: List[DeveloperProfile]) -> None:
    dev_b = get_profile(profiles, "developer_b@company.com")
    assert dev_b.risk_score == 12.0
    assert dev_b.risk_label == "LOW"


def test_obfuscation_penalty_applied(profiles: List[DeveloperProfile]) -> None:
    dev_c = get_profile(profiles, "developer_c@company.com")
    assert dev_c.obfuscated_leak_count == 1

    scorer = DeveloperRiskScorer()
    without_obfuscation = [mk_leak_event(15, "HIGH", was_obfuscated=False) for _ in range(2)]
    with_obfuscation = [mk_leak_event(15, "HIGH", was_obfuscated=True) for _ in range(2)]
    assert scorer.calculate_risk_score(with_obfuscation) == scorer.calculate_risk_score(without_obfuscation) + 10.0


def test_risk_trend_worsening(profiles: List[DeveloperProfile]) -> None:
    dev_c = get_profile(profiles, "developer_c@company.com")
    assert dev_c.risk_trend == "WORSENING"


def test_risk_trend_improving() -> None:
    scorer = DeveloperRiskScorer()
    events = [mk_leak_event(120, "MEDIUM") for _ in range(3)]  # all in the 91-180d window, none recent
    assert scorer.determine_risk_trend(events) == "IMPROVING"


# --------------------------------------------------------------------------------------
# Filtering / aggregation
# --------------------------------------------------------------------------------------


def test_high_risk_developers_filtered(profiler: DeveloperProfiler, profiles: List[DeveloperProfile]) -> None:
    high_risk = profiler.get_high_risk_developers(profiles)
    emails = {p.developer_email for p in high_risk}
    assert emails == {"developer_a@company.com", "developer_c@company.com"}


def test_organisation_summary_correct(profiler: DeveloperProfiler, profiles: List[DeveloperProfile]) -> None:
    summary = profiler.get_organisation_summary(profiles)
    assert summary["total_developers_with_leaks"] == 3
    assert summary["high_risk_count"] == 2
    assert summary["low_risk_count"] == 1


# --------------------------------------------------------------------------------------
# Reporting
# --------------------------------------------------------------------------------------


def test_text_report_contains_required_fields(profiler: DeveloperProfiler, profiles: List[DeveloperProfile]) -> None:
    dev_a = get_profile(profiles, "developer_a@company.com")
    report = profiler.generate_text_report(dev_a)

    assert dev_a.developer_email in report
    assert dev_a.risk_label in report
    assert str(dev_a.total_leaks) in report
    assert dev_a.risk_trend in report
    assert "Recommendation:" in report


def test_high_risk_recommendation_text(profiler: DeveloperProfiler, profiles: List[DeveloperProfile]) -> None:
    dev_a = get_profile(profiles, "developer_a@company.com")
    report = profiler.generate_text_report(dev_a)
    assert "security training" in report.lower()


def test_export_profiles_json_valid(
    profiler: DeveloperProfiler, profiles: List[DeveloperProfile], tmp_path
) -> None:
    output_path = tmp_path / "profiles.json"
    profiler.export_profiles_json(profiles, str(output_path))

    assert output_path.exists()
    with output_path.open() as f:
        data = json.load(f)

    assert len(data) == 3
    emails = {entry["developer_email"] for entry in data}
    assert emails == {"developer_a@company.com", "developer_b@company.com", "developer_c@company.com"}


# --------------------------------------------------------------------------------------
# Pipeline integration (real repo)
# --------------------------------------------------------------------------------------


@pytest.fixture(scope="module")
def pipeline_result():
    import shutil
    import tempfile

    from scanner.scan_pipeline import ScanPipeline

    tmp_dir = tempfile.mkdtemp()
    try:
        pipeline = ScanPipeline(clone_base_dir=tmp_dir)
        result = pipeline.run("https://github.com/trufflesecurity/test_keys", enable_active_validation=False)
        yield result
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


def test_pipeline_profiles_populated(pipeline_result) -> None:
    assert pipeline_result.status == "success"
    assert len(pipeline_result.developer_profiles) > 0
    for profile in pipeline_result.developer_profiles:
        assert isinstance(profile.risk_score, float)
        assert profile.risk_label in {"HIGH", "MEDIUM", "LOW"}


def test_pipeline_org_summary_present(pipeline_result) -> None:
    required_keys = {
        "total_developers_with_leaks",
        "high_risk_count",
        "medium_risk_count",
        "low_risk_count",
        "total_leaks_across_all",
        "most_leaked_secret_type",
        "average_risk_score",
        "developers_with_obfuscated_leaks",
    }
    assert required_keys <= pipeline_result.organisation_summary.keys()
