"""Layer 1 scanner: fast regex + entropy first-pass filter run before the
expensive Layer 2 CodeBERT semantic classifier ever sees a line.
"""

import hashlib
import logging
import re
from dataclasses import dataclass
from typing import List, Set

from scanner.entropy_scorer import calculate_shannon_entropy
from scanner.models import DiffLine
from scanner.patterns.secret_patterns import SECRET_PATTERNS

logger = logging.getLogger(__name__)

LOW_ENTROPY_SKIP_THRESHOLD = 2.5

_SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}

_TEST_VALUE_MARKERS = {
    "password",
    "123456",
    "test",
    "example",
    "changeme",
    "your_api_key",
    "xxxx",
    "placeholder",
    "dummy",
    "secret",
    "abc123",
    "foo",
    "bar",
    "todo",
}


@dataclass
class PatternMatch:
    """A single regex hit against a diff line, plus its entropy and confidence.

    matched_value holds the raw secret text transiently in memory so the
    caller (Layer 2, redaction) can still see what was found. Per CLAUDE.md
    convention, only matched_value_hash — never matched_value — may reach
    persistent storage (findings.redacted_snippet must be masked/truncated).
    """

    line: DiffLine
    pattern_name: str
    matched_value: str
    matched_value_hash: str  # SHA256, never store raw
    entropy_score: float
    severity_hint: str
    confidence: float  # 0.0 to 1.0


class PatternScanner:
    """Runs the 30+ regex secret patterns and an entropy filter over diff lines."""

    def __init__(self) -> None:
        """Compile all patterns from secret_patterns.py and prepare the entropy scorer."""
        self._patterns = [
            {**entry, "regex": re.compile(entry["pattern"])} for entry in SECRET_PATTERNS
        ]
        logger.info("PatternScanner initialised with %d patterns", len(self._patterns))

    def scan_line(self, line: DiffLine) -> List[PatternMatch]:
        """Run every regex pattern against line.content and return the surviving matches.

        A match is dropped if its value is an obvious placeholder (is_test_value)
        or if its Shannon entropy falls below LOW_ENTROPY_SKIP_THRESHOLD (2.5),
        since low-entropy strings are unlikely to be real secrets.
        """
        matches: List[PatternMatch] = []

        for pattern in self._patterns:
            regex = pattern["regex"]
            for match in regex.finditer(line.content):
                matched_value = match.group(1) if regex.groups >= 1 else match.group(0)
                if not matched_value:
                    continue
                if self.is_test_value(matched_value):
                    continue

                entropy_score = calculate_shannon_entropy(matched_value)
                if entropy_score < LOW_ENTROPY_SKIP_THRESHOLD:
                    continue

                matches.append(
                    PatternMatch(
                        line=line,
                        pattern_name=pattern["name"],
                        matched_value=matched_value,
                        matched_value_hash=hashlib.sha256(
                            matched_value.encode("utf-8")
                        ).hexdigest(),
                        entropy_score=entropy_score,
                        severity_hint=pattern["severity_hint"],
                        confidence=self._compute_confidence(pattern, entropy_score),
                    )
                )

        return matches

    def scan_diff_lines(self, lines: List[DiffLine]) -> List[PatternMatch]:
        """Scan every added/deleted line, deduplicate by secret hash, and sort by severity.

        Context lines are skipped — they're unchanged code, already covered by whichever
        commit originally added or will eventually delete them. The same secret hash
        appearing across multiple commits is reported only once.
        """
        seen_hashes: Set[str] = set()
        results: List[PatternMatch] = []

        for line in lines:
            if line.change_type == "context":
                continue

            for match in self.scan_line(line):
                if match.matched_value_hash in seen_hashes:
                    continue
                seen_hashes.add(match.matched_value_hash)
                results.append(match)

        return sorted(results, key=lambda m: _SEVERITY_ORDER.get(m.severity_hint, 99))

    def is_test_value(self, value: str) -> bool:
        """Return True if value is an obvious placeholder/fake secret (case-insensitive)."""
        return value.strip().lower() in _TEST_VALUE_MARKERS

    def _compute_confidence(self, pattern: dict, entropy_score: float) -> float:
        """Blend pattern specificity with entropy into a 0.0-1.0 confidence score.

        Well-formed, provider-specific patterns (cloud/scm_ci/payment/auth_crypto/database)
        are inherently high-confidence signals; the generic catch-all patterns
        (api_key=/secret=/password=/token=) are more prone to false positives, so they
        start lower and lean more heavily on entropy to earn extra confidence.
        """
        base_confidence = 0.9 if pattern["group"] != "generic" else 0.55
        entropy_bonus = min(0.1, max(0.0, (entropy_score - LOW_ENTROPY_SKIP_THRESHOLD) / 20))
        return round(min(1.0, base_confidence + entropy_bonus), 2)
