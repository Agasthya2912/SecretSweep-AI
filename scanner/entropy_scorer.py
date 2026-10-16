"""Layer 1 scanner: Shannon entropy scoring for high-randomness strings."""

import math
import re
from collections import Counter
from typing import List

GENERAL_SECRET_ENTROPY_THRESHOLD = 3.5
CRYPTO_KEY_ENTROPY_THRESHOLD = 4.5
MIN_CANDIDATE_LENGTH = 8

_QUOTED_STRING_RE = re.compile(r"""['"]([^'"]{8,})['"]""")
_ASSIGNED_VALUE_RE = re.compile(r"[:=]\s*([A-Za-z0-9+/\-_.]{8,})")


def calculate_shannon_entropy(text: str) -> float:
    """Compute the Shannon entropy (bits per character) of text.

    Returns 0.0 for empty input, otherwise a value bounded to [0.0, 8.0].
    """
    if not text:
        return 0.0

    length = len(text)
    frequencies = Counter(text)
    entropy = -sum(
        (count / length) * math.log2(count / length) for count in frequencies.values()
    )
    return round(min(entropy, 8.0), 4)


def is_high_entropy(text: str, threshold: float = GENERAL_SECRET_ENTROPY_THRESHOLD) -> bool:
    """Return True if text's Shannon entropy meets or exceeds threshold.

    Use the default 3.5 threshold for general secrets, or pass
    CRYPTO_KEY_ENTROPY_THRESHOLD (4.5) when checking cryptographic key material.
    """
    return calculate_shannon_entropy(text) >= threshold


def extract_strings_for_entropy(line: str) -> List[str]:
    """Extract candidate secret strings from a line of code for entropy checking.

    Pulls quoted string literals and the values on the right-hand side of
    `key = value` / `key: value` assignments, keeping only candidates of at
    least MIN_CANDIDATE_LENGTH characters and preserving first-seen order.
    """
    candidates: List[str] = []
    candidates.extend(_QUOTED_STRING_RE.findall(line))
    candidates.extend(_ASSIGNED_VALUE_RE.findall(line))

    seen = set()
    unique_candidates = []
    for candidate in candidates:
        if len(candidate) >= MIN_CANDIDATE_LENGTH and candidate not in seen:
            seen.add(candidate)
            unique_candidates.append(candidate)
    return unique_candidates
