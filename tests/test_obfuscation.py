"""Tests for the Layer 3 obfuscation detection module: decoders, the
concatenation reassembler, and the combined ObfuscationScanner.

Fixture encoded/reassembled values are constructed from real secrets that
match scanner/patterns/secret_patterns.py (AWS AKIA keys need exactly 16
trailing alphanumerics with real entropy; Stripe keys need exactly 24
trailing chars) so each test genuinely exercises detection rather than
assuming an encoded string decodes and matches on faith.
"""

import base64
import codecs
import hashlib

import pytest

from obfuscation.concat_reassembler import ConcatReassembler
from obfuscation.decoder import decode_base64, decode_hex, decode_rot13, decode_unicode_escape
from obfuscation.obfuscation_scanner import ObfuscationScanner
from scanner.models import DiffLine

AWS_KEY = "AKIAIOSFODNN7EXAMPLE"
STRIPE_SUFFIX = "abcdefghijklmnopqrstuvwx"  # exactly 24 chars, as the Stripe pattern requires
STRIPE_KEY = "sk_live_" + STRIPE_SUFFIX
UNICODE_AWS_KEY = "AKIA" + "Q7W3E9RTY2UIOPA5"  # 20 chars total, real entropy (not repetitive)


def make_line(content: str, line_number: int = 1, commit_hash: str = "c1") -> DiffLine:
    return DiffLine(
        file_path="app.py",
        line_number=line_number,
        content=content,
        change_type="added",
        commit_hash=commit_hash,
        author_email="dev@example.com",
    )


@pytest.fixture()
def scanner() -> ObfuscationScanner:
    return ObfuscationScanner()


@pytest.fixture()
def reassembler() -> ConcatReassembler:
    return ConcatReassembler()


# --------------------------------------------------------------------------------------
# Core decoders
# --------------------------------------------------------------------------------------


def test_decode_base64_roundtrip() -> None:
    encoded = base64.b64encode(b"sk-live-abc123").decode()
    assert decode_base64(encoded) == "sk-live-abc123"


def test_decode_base64_rejects_non_base64() -> None:
    assert decode_base64("not base64 at all!!") is None


def test_decode_hex_roundtrip() -> None:
    assert decode_hex("736b2d6c6976652d616263") == "sk-live-abc"


def test_decode_hex_rejects_too_short() -> None:
    assert decode_hex("6161") is None  # only 2 bytes, below the 4-byte minimum


def test_decode_unicode_escape_roundtrip() -> None:
    escaped = "".join("\\u%04x" % ord(c) for c in "secret")
    assert decode_unicode_escape(escaped) == "secret"


def test_decode_rot13_always_returns() -> None:
    assert decode_rot13("hello") == "uryyb"


# --------------------------------------------------------------------------------------
# STEP 1-3 fixtures
# --------------------------------------------------------------------------------------


def test_base64_aws_key_detected(scanner: ObfuscationScanner) -> None:
    encoded = base64.b64encode(AWS_KEY.encode()).decode()
    line = make_line(f'encoded = "{encoded}"')

    matches = scanner.scan_line_for_encoding(line)

    assert len(matches) == 1
    assert matches[0].obfuscation_type == "base64"
    assert matches[0].pattern_name == "AWS Access Key ID"
    assert matches[0].decoded_value == AWS_KEY


def test_hex_password_detected(scanner: ObfuscationScanner) -> None:
    encoded = STRIPE_KEY.encode().hex()
    line = make_line(f'pwd = "{encoded}"')

    matches = scanner.scan_line_for_encoding(line)

    assert len(matches) == 1
    assert matches[0].obfuscation_type == "hex"
    assert matches[0].pattern_name == "Stripe Live Secret Key"
    assert matches[0].decoded_value == STRIPE_KEY


def test_unicode_secret_detected(scanner: ObfuscationScanner) -> None:
    escaped = "".join("\\u%04x" % ord(c) for c in UNICODE_AWS_KEY)
    line = make_line(f'token = "{escaped}"')

    matches = scanner.scan_line_for_encoding(line)

    assert len(matches) == 1
    assert matches[0].obfuscation_type == "unicode"
    assert matches[0].pattern_name == "AWS Access Key ID"
    assert matches[0].decoded_value == UNICODE_AWS_KEY


def test_concat_stripe_key_detected(reassembler: ConcatReassembler) -> None:
    lines = [
        make_line('part1 = "sk_live_"', line_number=1),
        make_line(f'part2 = "{STRIPE_SUFFIX}"', line_number=2),
        make_line("key = part1 + part2", line_number=3),
    ]

    results = reassembler.scan(lines)

    assert len(results) == 1
    assert results[0].reassembled_value == STRIPE_KEY
    assert results[0].pattern_name == "Stripe Live Secret Key"
    assert results[0].lines_involved == [1, 2, 3]
    assert results[0].components == ["sk_live_", STRIPE_SUFFIX]


def test_join_pattern_detected(reassembler: ConcatReassembler) -> None:
    line = make_line(f'key = "".join(["sk_live_", "{STRIPE_SUFFIX}"])')

    results = reassembler.scan([line])

    assert len(results) == 1
    assert results[0].reassembled_value == STRIPE_KEY
    assert results[0].pattern_name == "Stripe Live Secret Key"


def test_accumulation_pattern_detected(reassembler: ConcatReassembler) -> None:
    lines = [
        make_line('token = ""', line_number=1),
        make_line('token += "eyJhbGci"', line_number=2),
        make_line('token += "OiJIUzI1"', line_number=3),
        make_line('token += "NiIsInR5"', line_number=4),
    ]

    results = reassembler.scan(lines)

    final_values = [r.reassembled_value for r in results]
    assert "eyJhbGciOiJIUzI1NiIsInR5" in final_values
    final = next(r for r in results if r.reassembled_value == "eyJhbGciOiJIUzI1NiIsInR5")
    assert final.lines_involved == [1, 2, 3, 4]


def test_safe_base64_not_flagged(scanner: ObfuscationScanner) -> None:
    encoded = base64.b64encode(b"hello world").decode()
    line = make_line(f'data = "{encoded}"')

    matches = scanner.scan_line_for_encoding(line)

    assert matches == []


def test_rot13_encoded_detected(scanner: ObfuscationScanner) -> None:
    encoded = codecs.encode(STRIPE_KEY, "rot_13")
    line = make_line(f'val = "{encoded}"')

    matches = scanner.scan_line_for_encoding(line)

    assert len(matches) == 1
    assert matches[0].obfuscation_type == "rot13"
    assert matches[0].pattern_name == "Stripe Live Secret Key"
    assert matches[0].decoded_value == STRIPE_KEY


# --------------------------------------------------------------------------------------
# Combined scanner behavior
# --------------------------------------------------------------------------------------


def test_deduplication_by_hash(scanner: ObfuscationScanner) -> None:
    # hex and rot13 encodings of the *same* underlying secret should collapse to one match.
    hex_line = make_line(f'pwd = "{STRIPE_KEY.encode().hex()}"', line_number=1)
    rot13_line = make_line(f'val = "{codecs.encode(STRIPE_KEY, "rot_13")}"', line_number=2)

    results = scanner.scan_lines([hex_line, rot13_line])

    assert len(results) == 1
    assert results[0].decoded_value == STRIPE_KEY


def test_obfuscation_scanner_combines_all(scanner: ObfuscationScanner) -> None:
    b64_line = make_line(f'encoded = "{base64.b64encode(AWS_KEY.encode()).decode()}"', line_number=1)
    concat_lines = [
        make_line('cpart1 = "sk_live_"', line_number=2),
        make_line(f'cpart2 = "{STRIPE_SUFFIX}"', line_number=3),
        make_line("full_key = cpart1 + cpart2", line_number=4),
    ]
    safe_encoded = base64.b64encode(b"hello world").decode()
    safe_line = make_line(f'data = "{safe_encoded}"', line_number=5)

    results = scanner.scan_lines([b64_line, *concat_lines, safe_line])

    types_found = {m.obfuscation_type for m in results}
    assert "base64" in types_found
    assert "concat" in types_found
    assert len(results) == 2  # AWS key (base64) + Stripe key (concat), safe line excluded


def test_pipeline_includes_obfuscation_layer() -> None:
    from datetime import datetime, timezone

    from obfuscation.obfuscation_scanner import ObfuscationScanner as OS
    from scanner.models import ScanResult
    from scanner.scan_pipeline import ScanPipeline

    pipeline = ScanPipeline()
    assert isinstance(pipeline.obfuscation_scanner, OS)

    now = datetime.now(timezone.utc)
    empty_result = ScanResult(
        repo_url="x",
        local_path="y",
        status="success",
        total_commits=0,
        started_at=now,
        completed_at=now,
    )
    assert empty_result.obfuscation_matches == []
    assert empty_result.total_obfuscation_findings == 0


def test_decoded_values_never_stored_raw(scanner: ObfuscationScanner) -> None:
    encoded = base64.b64encode(AWS_KEY.encode()).decode()
    line = make_line(f'encoded = "{encoded}"')

    matches = scanner.scan_line_for_encoding(line)
    assert len(matches) == 1
    match = matches[0]

    expected_hash = hashlib.sha256(match.decoded_value.encode("utf-8")).hexdigest()
    assert match.decoded_value_hash == expected_hash
    assert len(match.decoded_value_hash) == 64
    assert all(c in "0123456789abcdef" for c in match.decoded_value_hash)
    assert match.decoded_value_hash != match.decoded_value
