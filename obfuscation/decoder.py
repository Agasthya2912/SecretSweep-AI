"""
obfuscation/decoder.py

Detects and decodes obfuscated secrets encoded in Base64, hexadecimal,
ROT13, or split across string concatenation chains.

Each decoder here only *decodes* — it makes no judgment about whether the
result is actually a secret. That judgment belongs to whoever calls
decode_all() and then checks the result against known secret patterns
(see obfuscation/obfuscation_scanner.py), matching how ROT13/reversed text
are explicitly documented: "only flag if decoded string matches known
secret patterns."
"""

import base64
import binascii
import codecs
import re
from dataclasses import dataclass
from typing import List, Optional

MIN_HEX_CHARS = 8  # 4 bytes

_BASE64_RE = re.compile(r"^[A-Za-z0-9+/\-_]+={0,2}$")
_HEX_ESCAPE_RE = re.compile(r"\\x([0-9a-fA-F]{2})")
_HEX_PLAIN_RE = re.compile(r"^(?:0[xX])?[0-9a-fA-F]+$")
_UNICODE_ESCAPE_RE = re.compile(r"\\u([0-9a-fA-F]{4})|\\U([0-9a-fA-F]{8})")


@dataclass
class DecodedResult:
    """One successful decode of a candidate string."""

    original: str
    decoded: str
    encoding_type: str  # "base64" | "hex" | "unicode" | "rot13" | "reversed"
    confidence: float  # how confident we are this is real encoding (not coincidence)


def _is_printable_text(text: str) -> bool:
    """True if text looks like real human-readable content, not decode noise."""
    if not text:
        return False
    return all(c.isprintable() or c in "\t\n\r" for c in text)


def decode_base64(text: str) -> Optional[str]:
    """Decode text as Base64 (standard or URL-safe, padded or not) if it validly is.

    Returns None if text doesn't look like Base64, or decodes to bytes that
    aren't valid printable UTF-8 text.
    """
    candidate = text.strip()
    if len(candidate) < 4 or not _BASE64_RE.match(candidate):
        return None

    normalized = candidate.replace("-", "+").replace("_", "/")
    padded = normalized + "=" * (-len(normalized) % 4)

    try:
        decoded_bytes = base64.b64decode(padded, validate=True)
    except (binascii.Error, ValueError):
        return None

    try:
        decoded_text = decoded_bytes.decode("utf-8")
    except UnicodeDecodeError:
        return None

    return decoded_text if _is_printable_text(decoded_text) else None


def decode_hex(text: str) -> Optional[str]:
    """Decode a hex-encoded string: '\\xNN' escape sequences, '0x'-prefixed, or plain hex.

    Requires at least MIN_HEX_CHARS (8) hex digits (4 bytes) and returns None
    if the text isn't validly hex-shaped or doesn't decode to printable UTF-8.
    """
    candidate = text.strip()

    escape_matches = _HEX_ESCAPE_RE.findall(candidate)
    if escape_matches:
        reconstructed = "".join(f"\\x{h}" for h in escape_matches)
        if reconstructed.lower() != candidate.lower():
            return None  # stray characters outside the \xNN sequences — don't guess
        hex_digits = "".join(escape_matches)
    else:
        if not _HEX_PLAIN_RE.match(candidate):
            return None
        hex_digits = candidate[2:] if candidate.lower().startswith("0x") else candidate
        if len(hex_digits) % 2 != 0:
            return None

    if len(hex_digits) < MIN_HEX_CHARS:
        return None

    try:
        decoded_bytes = bytes.fromhex(hex_digits)
    except ValueError:
        return None

    try:
        decoded_text = decoded_bytes.decode("utf-8")
    except UnicodeDecodeError:
        return None

    return decoded_text if _is_printable_text(decoded_text) else None


def decode_unicode_escape(text: str) -> Optional[str]:
    """Decode a string made entirely of \\uXXXX / \\UXXXXXXXX escape sequences."""
    candidate = text.strip()
    matches = list(_UNICODE_ESCAPE_RE.finditer(candidate))
    if not matches:
        return None

    reconstructed = "".join(m.group(0) for m in matches)
    if reconstructed != candidate:
        return None  # stray non-escape characters present — don't guess

    decoded_text = "".join(chr(int(m.group(1) or m.group(2), 16)) for m in matches)
    return decoded_text if _is_printable_text(decoded_text) else None


def decode_rot13(text: str) -> str:
    """Always returns the ROT13 transform of text — callers decide if it's meaningful."""
    return codecs.decode(text, "rot_13")


def reverse_string(text: str) -> str:
    """Always returns text reversed — callers decide if it's meaningful."""
    return text[::-1]


def decode_all(text: str) -> List[DecodedResult]:
    """Try every decoder against text and return a DecodedResult for each that produced
    something. Base64/hex/unicode only appear here when they're structurally valid
    (i.e. decode_base64 etc. didn't return None); ROT13/reversed always "succeed" since
    they're defined for any input, so they carry lower confidence and rely entirely on
    the caller's pattern check to decide whether the result means anything.
    """
    results: List[DecodedResult] = []

    base64_decoded = decode_base64(text)
    if base64_decoded is not None:
        results.append(DecodedResult(text, base64_decoded, "base64", confidence=0.9))

    hex_decoded = decode_hex(text)
    if hex_decoded is not None:
        results.append(DecodedResult(text, hex_decoded, "hex", confidence=0.85))

    unicode_decoded = decode_unicode_escape(text)
    if unicode_decoded is not None:
        results.append(DecodedResult(text, unicode_decoded, "unicode", confidence=0.9))

    rot13_decoded = decode_rot13(text)
    if rot13_decoded and rot13_decoded != text:
        results.append(DecodedResult(text, rot13_decoded, "rot13", confidence=0.4))

    reversed_text = reverse_string(text)
    if reversed_text and reversed_text != text:
        results.append(DecodedResult(text, reversed_text, "reversed", confidence=0.3))

    return results
