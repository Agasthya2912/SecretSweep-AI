"""Tests for the severity engine (severity/scorer.py) and active validator
(severity/active_validator.py), plus their integration into ScanPipeline as Layer 5.

Active validator tests always mock requests.get/post — no real network calls
are made, and enable_active_validation is never set True against a live repo.
"""

import uuid
from datetime import datetime, timezone
from typing import List
from unittest.mock import MagicMock, patch

import pytest
import requests

from cdfg.models import SecretLifecycle, SecretNode
from severity.active_validator import ActiveValidator
from severity.scorer import SeverityScore, SeverityScorer


def mk_lifecycle(
    pattern_name: str = "aws_access_key",
    secret_hash: str = "hash1",
    exposure_duration_days: int = 10,
) -> SecretLifecycle:
    node = SecretNode(
        node_id=str(uuid.uuid4()),
        secret_hash=secret_hash,
        pattern_name=pattern_name,
        severity_hint="CRITICAL",
        first_seen_commit="c1",
        first_seen_file="config.py",
        first_seen_line=1,
        first_seen_author="dev@example.com",
        first_seen_date=datetime.now(timezone.utc),
        is_active=True,
    )
    return SecretLifecycle(secret_node=node, exposure_duration_days=exposure_duration_days)


def mk_score(total_score: float, severity_label: str, secret_hash: str = "h") -> SeverityScore:
    return SeverityScore(
        secret_hash=secret_hash,
        type_score=0.0,
        duration_score=0.0,
        visibility_score=0.0,
        active_score=0.0,
        blast_radius_score=0.0,
        total_score=total_score,
        severity_label=severity_label,
        scored_at=datetime.now(timezone.utc),
    )


@pytest.fixture()
def scorer() -> SeverityScorer:
    return SeverityScorer()


# --------------------------------------------------------------------------------------
# Individual factors
# --------------------------------------------------------------------------------------


def test_aws_key_gets_high_type_score(scorer: SeverityScorer) -> None:
    score = scorer.score_secret(mk_lifecycle(pattern_name="aws_access_key"))
    assert score.type_score == 9.5


def test_stripe_test_key_gets_low_type_score(scorer: SeverityScorer) -> None:
    score = scorer.score_secret(mk_lifecycle(pattern_name="stripe_test_secret"))
    assert score.type_score == 4.0


def test_old_secret_gets_high_duration_score(scorer: SeverityScorer) -> None:
    score = scorer.score_secret(mk_lifecycle(exposure_duration_days=400))
    assert score.duration_score == 10.0


def test_new_secret_gets_low_duration_score(scorer: SeverityScorer) -> None:
    score = scorer.score_secret(mk_lifecycle(exposure_duration_days=3))
    assert score.duration_score == 3.0


def test_active_key_gets_bonus_score(scorer: SeverityScorer) -> None:
    score = scorer.score_secret(mk_lifecycle(), active_status="active")
    assert score.active_score == 5.0


def test_revoked_key_gets_zero_active_score(scorer: SeverityScorer) -> None:
    score = scorer.score_secret(mk_lifecycle(), active_status="revoked")
    assert score.active_score == 0.0


def test_blast_radius_single_file(scorer: SeverityScorer) -> None:
    score = scorer.score_secret(mk_lifecycle(), file_count=1)
    assert score.blast_radius_score == 2.0


def test_blast_radius_many_files(scorer: SeverityScorer) -> None:
    score = scorer.score_secret(mk_lifecycle(), file_count=8)
    assert score.blast_radius_score == 10.0


# --------------------------------------------------------------------------------------
# Severity label thresholds
# --------------------------------------------------------------------------------------


def test_critical_threshold(scorer: SeverityScorer) -> None:
    score = scorer.score_secret(
        mk_lifecycle(pattern_name="aws_access_key", exposure_duration_days=400),
        active_status="active",
        repo_visibility="public",
        file_count=8,
    )
    assert score.total_score >= 35.0
    assert score.severity_label == "CRITICAL"


def test_high_threshold(scorer: SeverityScorer) -> None:
    score = scorer.score_secret(
        mk_lifecycle(pattern_name="github_token", exposure_duration_days=60),
        active_status="unknown",
        repo_visibility="unknown",
        file_count=1,
    )
    assert 25.0 <= score.total_score < 35.0
    assert score.severity_label == "HIGH"


def test_medium_threshold(scorer: SeverityScorer) -> None:
    score = scorer.score_secret(
        mk_lifecycle(pattern_name="generic_secret", exposure_duration_days=20),
        active_status="unknown",
        repo_visibility="private",
        file_count=1,
    )
    assert 15.0 <= score.total_score < 25.0
    assert score.severity_label == "MEDIUM"


def test_low_threshold(scorer: SeverityScorer) -> None:
    score = scorer.score_secret(
        mk_lifecycle(pattern_name="stripe_test_secret", exposure_duration_days=0),
        active_status="revoked",
        repo_visibility="private",
        file_count=1,
    )
    assert score.total_score < 15.0
    assert score.severity_label == "LOW"


# --------------------------------------------------------------------------------------
# score_all / summary
# --------------------------------------------------------------------------------------


def test_score_all_sorted_by_total_descending(scorer: SeverityScorer) -> None:
    lifecycles = [
        mk_lifecycle(pattern_name="generic_secret", secret_hash="low", exposure_duration_days=0),
        mk_lifecycle(pattern_name="aws_access_key", secret_hash="critical", exposure_duration_days=400),
        mk_lifecycle(pattern_name="github_token", secret_hash="high", exposure_duration_days=60),
    ]
    scores = scorer.score_all(lifecycles, active_statuses={})

    totals = [s.total_score for s in scores]
    assert totals == sorted(totals, reverse=True)
    assert scores[0].secret_hash == "critical"


def test_get_summary_counts_correct(scorer: SeverityScorer) -> None:
    scores = (
        [mk_score(40.0, "CRITICAL", f"c{i}") for i in range(2)]
        + [mk_score(28.0, "HIGH", "h0")]
        + [mk_score(18.0, "MEDIUM", f"m{i}") for i in range(3)]
        + [mk_score(5.0, "LOW", "l0")]
    )

    summary = scorer.get_summary(scores)

    assert summary["critical"] == 2
    assert summary["high"] == 1
    assert summary["medium"] == 3
    assert summary["low"] == 1
    assert summary["highest_score"] == 40.0


# --------------------------------------------------------------------------------------
# Active validator — mocked, no real network calls
# --------------------------------------------------------------------------------------


@pytest.fixture()
def validator() -> ActiveValidator:
    v = ActiveValidator()
    v._min_interval = 0.0  # don't slow tests down with real rate limiting
    return v


def test_validate_returns_unknown_for_generic(validator: ActiveValidator) -> None:
    assert validator.validate("generic_secret", "some-value") == "unknown"


def test_validate_aws_active_on_200(validator: ActiveValidator) -> None:
    with patch("severity.active_validator.requests.post") as mock_post:
        mock_post.return_value = MagicMock(status_code=200, text="")
        assert validator.validate("aws_access_key", "AKIAFAKEFAKEFAKEFAK") == "active"


def test_validate_aws_revoked_on_invalid_token(validator: ActiveValidator) -> None:
    with patch("severity.active_validator.requests.post") as mock_post:
        mock_post.return_value = MagicMock(status_code=403, text="...InvalidClientTokenId...")
        assert validator.validate("aws_access_key", "AKIAFAKEFAKEFAKEFAK") == "revoked"


def test_validate_github_active_on_200(validator: ActiveValidator) -> None:
    with patch("severity.active_validator.requests.get") as mock_get:
        mock_get.return_value = MagicMock(status_code=200)
        assert validator.validate("github_token", "ghp_fake") == "active"


def test_validate_github_revoked_on_401(validator: ActiveValidator) -> None:
    with patch("severity.active_validator.requests.get") as mock_get:
        mock_get.return_value = MagicMock(status_code=401)
        assert validator.validate("github_token", "ghp_fake") == "revoked"


def test_validate_timeout_returns_unknown(validator: ActiveValidator) -> None:
    with patch("severity.active_validator.requests.get") as mock_get:
        mock_get.side_effect = requests.Timeout("timed out")
        assert validator.validate("github_token", "ghp_fake") == "unknown"


def test_validate_never_logs_secret_value(validator: ActiveValidator, caplog: pytest.LogCaptureFixture) -> None:
    secret_marker = "SUPER_SECRET_VALUE_XYZ123"
    with caplog.at_level("DEBUG"):
        with patch("severity.active_validator.requests.get") as mock_get:
            mock_get.side_effect = requests.Timeout("timed out")
            validator.validate("github_token", secret_marker)
        with patch("severity.active_validator.requests.post") as mock_post:
            mock_post.return_value = MagicMock(status_code=200, text="")
            validator.validate("aws_access_key", secret_marker)

    for record in caplog.records:
        assert secret_marker not in record.getMessage()


def test_validate_batch_deduplicates(validator: ActiveValidator) -> None:
    with patch("severity.active_validator.requests.post") as mock_post:
        mock_post.return_value = MagicMock(status_code=200, text="")
        findings = [
            ("aws_access_key", "AKIAFAKEFAKEFAKEFAK", "same_hash"),
            ("aws_access_key", "AKIAFAKEFAKEFAKEFAK", "same_hash"),
        ]
        results = validator.validate_batch(findings)

    assert mock_post.call_count == 1
    assert results == {"same_hash": "active"}


# --------------------------------------------------------------------------------------
# Pipeline integration (real repo, active validation always off)
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


def test_pipeline_severity_scores_populated(pipeline_result) -> None:
    assert pipeline_result.status == "success"
    assert len(pipeline_result.severity_scores) > 0
    for score in pipeline_result.severity_scores:
        assert score.severity_label in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}


def test_pipeline_severity_summary_correct(pipeline_result) -> None:
    assert set(pipeline_result.severity_summary.keys()) >= {
        "critical",
        "high",
        "medium",
        "low",
        "highest_score",
        "average_score",
    }
    total_labeled = (
        pipeline_result.severity_summary["critical"]
        + pipeline_result.severity_summary["high"]
        + pipeline_result.severity_summary["medium"]
        + pipeline_result.severity_summary["low"]
    )
    assert total_labeled == len(pipeline_result.severity_scores)
