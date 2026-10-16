"""
obfuscation/obfuscation_scanner.py

Scans source files and diffs for obfuscated secret candidates, delegating
to decoder.py to reverse Base64/hex/ROT13/string-concatenation encodings
before handing decoded content to the regex and entropy scanners.

This is Layer 3: everything here is missed by Layer 1 (regex on raw text)
and Layer 2 (semantic classification of raw text) because the secret
literally isn't present in the diff in its recognizable form.
"""

import hashlib
import logging
import re
from dataclasses import dataclass
from typing import List, Optional, Set

from obfuscation.concat_reassembler import ConcatReassembler
from obfuscation.decoder import decode_all
from scanner.entropy_scorer import calculate_shannon_entropy
from scanner.models import DiffLine
from scanner.pattern_scanner import PatternScanner

logger = logging.getLogger(__name__)

MIN_DECODED_LENGTH = 8
DECODED_ENTROPY_THRESHOLD = 2.5

_QUOTED_STRING_RE = re.compile(r"""(["'])((?:(?!\1).)*)\1""")


@dataclass
class ObfuscationMatch:
    """A secret recovered only after decoding or reassembling — never visible as-is."""

    line: DiffLine  # original line
    obfuscation_type: str  # "base64" | "hex" | "unicode" | "rot13" | "reversed" | "concat"
    original_value: str  # encoded/split form
    decoded_value: str  # what it decodes to
    decoded_value_hash: str  # SHA256 of decoded — never store the raw decoded secret
    pattern_name: str  # secret type matched
    severity_hint: str
    confidence: float


def _extract_quoted_strings(content: str) -> List[str]:
    return [match.group(2) for match in _QUOTED_STRING_RE.finditer(content)]


class ObfuscationScanner:
    """Layer 3: orchestrates the decoders and the concat reassembler into one scan."""

    def __init__(self) -> None:
        """Initialise the pattern scanner and concat reassembler used to judge decodes."""
        self._pattern_scanner = PatternScanner()
        self._concat_reassembler = ConcatReassembler()

    def scan_line_for_encoding(self, line: DiffLine) -> List[ObfuscationMatch]:
        """Decode every quoted string on line every way possible, and flag any decode
        that (a) is at least MIN_DECODED_LENGTH chars, (b) has entropy above
        DECODED_ENTROPY_THRESHOLD, and (c) matches a known secret pattern once decoded.
        """
        matches: List[ObfuscationMatch] = []

        for quoted in _extract_quoted_strings(line.content):
            for decoded_result in decode_all(quoted):
                decoded = decoded_result.decoded
                if len(decoded) < MIN_DECODED_LENGTH:
                    continue
                if calculate_shannon_entropy(decoded) <= DECODED_ENTROPY_THRESHOLD:
                    continue

                synthetic_line = DiffLine(
                    file_path=line.file_path,
                    line_number=line.line_number,
                    content=decoded,
                    change_type=line.change_type,
                    commit_hash=line.commit_hash,
                    author_email=line.author_email,
                )
                pattern_matches = self._pattern_scanner.scan_line(synthetic_line)
                if not pattern_matches:
                    continue

                best = pattern_matches[0]
                matches.append(
                    ObfuscationMatch(
                        line=line,
                        obfuscation_type=decoded_result.encoding_type,
                        original_value=quoted,
                        decoded_value=decoded,
                        decoded_value_hash=hashlib.sha256(decoded.encode("utf-8")).hexdigest(),
                        pattern_name=best.pattern_name,
                        severity_hint=best.severity_hint,
                        confidence=round(decoded_result.confidence * best.confidence, 4),
                    )
                )

        return matches

    def scan_lines(self, lines: List[DiffLine]) -> List[ObfuscationMatch]:
        """Run per-line encoding detection plus cross-line concat reassembly, and
        deduplicate the combined results by decoded value hash.
        """
        results: List[ObfuscationMatch] = []

        for line in lines:
            results.extend(self.scan_line_for_encoding(line))

        for reassembled in self._concat_reassembler.scan(lines):
            results.append(
                ObfuscationMatch(
                    line=self._origin_line(lines, reassembled.lines_involved),
                    obfuscation_type="concat",
                    original_value=" + ".join(reassembled.components),
                    decoded_value=reassembled.reassembled_value,
                    decoded_value_hash=reassembled.reassembled_hash,
                    pattern_name=reassembled.pattern_name,
                    severity_hint=reassembled.severity_hint,
                    confidence=reassembled.confidence,
                )
            )

        seen_hashes: Set[str] = set()
        deduplicated: List[ObfuscationMatch] = []
        for match in results:
            if match.decoded_value_hash in seen_hashes:
                continue
            seen_hashes.add(match.decoded_value_hash)
            deduplicated.append(match)

        return deduplicated

    def _origin_line(self, lines: List[DiffLine], lines_involved: List[int]) -> Optional[DiffLine]:
        return next((l for l in lines if l.line_number in lines_involved), lines[0] if lines else None)
