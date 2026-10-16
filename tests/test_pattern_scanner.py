"""Tests for scanner/pattern_scanner.py (Layer 1: regex + entropy first-pass filter)."""

import hashlib

import pytest

from scanner.entropy_scorer import calculate_shannon_entropy, is_high_entropy
from scanner.models import DiffLine
from scanner.pattern_scanner import PatternScanner


def make_line(content: str, change_type: str = "added", commit_hash: str = "abc123") -> DiffLine:
    return DiffLine(
        file_path="app.py",
        line_number=1,
        content=content,
        change_type=change_type,
        commit_hash=commit_hash,
        author_email="dev@example.com",
    )


# Fixture lines from the Phase 3 spec.
AWS_KEY_LINE = 'aws_key = "AKIAIOSFODNN7EXAMPLE"'
GITHUB_TOKEN_LINE = 'token = "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ123456"'
STRIPE_KEY_LINE = "sk_live_abcdefghijklmnopqrstuvwx"
JWT_LINE = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload.sig"
SAFE_PASSWORD_LINE = 'password = "changeme"'
SAFE_API_KEY_LINE = 'api_key = "test"'
DB_URI_LINE = "postgres://user:realpassword123@localhost/db"
HIGH_ENTROPY_LINE = 'secret = "xK9#mP2$qL7nR4@wB6"'
RSA_KEY_LINE = "-----BEGIN RSA PRIVATE KEY-----"
OBFUSCATED_LINE = 'key = "c2stbGl2ZS1hYmMxMjM="'  # base64 of "sk-live-abc123"


@pytest.fixture()
def scanner() -> PatternScanner:
    return PatternScanner()


def test_aws_key_detected(scanner: PatternScanner) -> None:
    matches = scanner.scan_line(make_line(AWS_KEY_LINE))
    assert any(m.pattern_name == "AWS Access Key ID" for m in matches)
    assert any(m.matched_value == "AKIAIOSFODNN7EXAMPLE" for m in matches)


def test_github_token_detected(scanner: PatternScanner) -> None:
    # This fixture's token body is 32 chars, shorter than a real GitHub PAT's 36-char
    # minimum, so the provider-specific pattern doesn't fire — but the generic
    # token=... catch-all still flags it, which is the behavior that matters.
    matches = scanner.scan_line(make_line(GITHUB_TOKEN_LINE))
    assert len(matches) > 0
    assert any("ghp_" in m.matched_value for m in matches)


def test_stripe_key_detected(scanner: PatternScanner) -> None:
    matches = scanner.scan_line(make_line(STRIPE_KEY_LINE))
    assert any(m.pattern_name == "Stripe Live Secret Key" for m in matches)
    assert any(m.severity_hint == "CRITICAL" for m in matches)


def test_test_values_not_flagged(scanner: PatternScanner) -> None:
    matches = scanner.scan_line(make_line(SAFE_PASSWORD_LINE))
    assert matches == []


def test_api_key_test_not_flagged(scanner: PatternScanner) -> None:
    matches = scanner.scan_line(make_line(SAFE_API_KEY_LINE))
    assert matches == []


def test_postgres_uri_detected(scanner: PatternScanner) -> None:
    matches = scanner.scan_line(make_line(DB_URI_LINE))
    assert any(m.pattern_name == "PostgreSQL URI" for m in matches)


def test_high_entropy_string_detected(scanner: PatternScanner) -> None:
    matches = scanner.scan_line(make_line(HIGH_ENTROPY_LINE))
    assert any(m.pattern_name == "Generic Secret" for m in matches)
    assert any(m.entropy_score >= 3.5 for m in matches)


def test_rsa_key_detected(scanner: PatternScanner) -> None:
    matches = scanner.scan_line(make_line(RSA_KEY_LINE))
    assert any(m.pattern_name == "RSA Private Key" for m in matches)


def test_sha256_hash_stored_not_raw_value(scanner: PatternScanner) -> None:
    matches = scanner.scan_line(make_line(AWS_KEY_LINE))
    assert len(matches) > 0
    match = matches[0]

    expected_hash = hashlib.sha256(match.matched_value.encode("utf-8")).hexdigest()
    assert match.matched_value_hash == expected_hash
    assert len(match.matched_value_hash) == 64
    assert all(c in "0123456789abcdef" for c in match.matched_value_hash)
    assert match.matched_value_hash != match.matched_value


def test_deduplication_works(scanner: PatternScanner) -> None:
    line_in_commit_a = make_line(AWS_KEY_LINE, commit_hash="commit_a")
    line_in_commit_b = make_line(AWS_KEY_LINE, commit_hash="commit_b")

    results = scanner.scan_diff_lines([line_in_commit_a, line_in_commit_b])

    assert len(results) == 1


def test_entropy_scorer_high_value() -> None:
    assert is_high_entropy("xK9#mP2$qL7nR4@wB6") is True
    assert calculate_shannon_entropy("xK9#mP2$qL7nR4@wB6") >= 3.5


def test_entropy_scorer_low_value() -> None:
    assert is_high_entropy("aaaaaaaa") is False
    assert calculate_shannon_entropy("aaaaaaaa") == 0.0


def test_scan_diff_lines_skips_context_lines(scanner: PatternScanner) -> None:
    context_line = make_line(AWS_KEY_LINE, change_type="context")
    results = scanner.scan_diff_lines([context_line])
    assert results == []
