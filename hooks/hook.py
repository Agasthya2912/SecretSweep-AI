"""Git pre-commit hook: fast local scan of staged changes, blocking the commit
on CRITICAL/HIGH findings and warning (but allowing) on MEDIUM/LOW.

Deliberately avoids importing anything heavy (torch, transformers) at module
load time — ONNXClassifier is lazy-loaded only if an exported ONNX model is
actually found on disk, and only once scan_staged_content() needs it. If no
ONNX model is available, the hook falls back to Layer 1 (pattern + entropy)
only, which has zero heavy imports and is effectively instant.
"""

import logging
import subprocess
import sys
from pathlib import Path
from typing import List, Optional

from scanner.models import DiffLine
from scanner.pattern_scanner import PatternScanner

# Windows consoles often default to cp1252, which can't encode the emoji used below.
try:
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")
except (AttributeError, ValueError):
    pass

logger = logging.getLogger(__name__)

# Resolved relative to this package's own location, not the caller's cwd — git
# invokes pre-commit hooks with cwd set to whichever repo is being committed to,
# which is almost never this SecretsweepAI checkout itself once the hook is
# installed into a developer's project.
DEFAULT_ONNX_PATH = str(Path(__file__).resolve().parent.parent / "ml" / "models" / "secret_classifier.onnx")
MAX_FILE_SIZE_BYTES = 1 * 1024 * 1024  # 1MB

RED = "\033[91m"
YELLOW = "\033[93m"
WHITE = "\033[97m"
BOLD = "\033[1m"
RESET = "\033[0m"

_SEVERITY_COLOR = {
    "CRITICAL": RED,
    "HIGH": RED,
    "MEDIUM": YELLOW,
    "LOW": WHITE,
}

_BOX_WIDTH = 45  # inner content width, between the │ borders


class PreCommitHook:
    """Scans staged changes for secrets before a commit is allowed to complete."""

    def __init__(self) -> None:
        """Check for an ONNX model on disk; fall back to pattern-only scanning if absent."""
        self.pattern_scanner = PatternScanner()
        self._classifier = None  # lazy-loaded by _get_classifier()

        onnx_path = Path(DEFAULT_ONNX_PATH)
        self.onnx_available = onnx_path.exists()
        self.fast_mode = not self.onnx_available
        if self.fast_mode:
            logger.info("No ONNX model found at %s — running pattern-only scan.", onnx_path)

    def _get_classifier(self):
        """Lazily import and construct ONNXClassifier the first time it's actually needed."""
        if self._classifier is None:
            from ml.onnx_export import ONNXClassifier

            self._classifier = ONNXClassifier(DEFAULT_ONNX_PATH)
        return self._classifier

    def get_staged_files(self) -> List[str]:
        """Return staged (added/copied/modified) files, skipping binary and >1MB files."""
        result = subprocess.run(
            ["git", "diff", "--cached", "--name-only", "--diff-filter=ACM"],
            capture_output=True,
            text=True,
            check=True,
        )

        staged_files: List[str] = []
        for file_path in result.stdout.splitlines():
            file_path = file_path.strip()
            if not file_path:
                continue

            path = Path(file_path)
            if not path.is_file():
                continue
            if path.stat().st_size > MAX_FILE_SIZE_BYTES:
                continue
            if self._is_binary(path):
                continue

            staged_files.append(file_path)

        return staged_files

    def _is_binary(self, path: Path) -> bool:
        """Heuristic: a null byte in the first 8KB means the file is binary."""
        try:
            with open(path, "rb") as f:
                chunk = f.read(8192)
        except OSError:
            return True
        return b"\x00" in chunk

    def get_staged_diff(self, file_path: str) -> List[str]:
        """Return the added (+prefixed) lines of file_path's staged diff, prefix stripped."""
        result = subprocess.run(
    ["git", "diff", "--cached", "--", file_path],
    capture_output=True,
    text=True,
    encoding="utf-8",
    errors="replace",
    check=True,
)

        added_lines: List[str] = []
        for line in result.stdout.splitlines():
            if line.startswith("+++"):
                continue
            if line.startswith("+"):
                added_lines.append(line[1:])

        return added_lines

    def scan_staged_content(self, file_path: str, lines: List[str]) -> List[dict]:
        """Run Layer 1 (and Layer 2 if available) over a file's newly-added lines."""
        diff_lines = [
            DiffLine(
                file_path=file_path,
                line_number=idx,
                content=content,
                change_type="added",
                commit_hash="staged",
                author_email="",
            )
            for idx, content in enumerate(lines, start=1)
        ]

        matches = self.pattern_scanner.scan_diff_lines(diff_lines)
        if not matches:
            return []

        classifier = None
        if not self.fast_mode:
            try:
                classifier = self._get_classifier()
            except Exception:
                logger.warning("ONNXClassifier unavailable — falling back to pattern-only results.", exc_info=True)
                classifier = None

        findings: List[dict] = []
        for match in matches:
            semantic_label: Optional[str] = None
            confidence: Optional[float] = None
            if classifier is not None:
                try:
                    semantic_result = classifier.classify(match, diff_lines)
                    semantic_label = semantic_result.semantic_label
                    confidence = semantic_result.confidence
                except Exception:
                    logger.warning("Semantic classification failed for a match — keeping the pattern-only result.", exc_info=True)

            if semantic_label == "false_positive":
                continue

            findings.append(
                {
                    "file": file_path,
                    "line": match.line.line_number,
                    "pattern": match.pattern_name,
                    "severity": match.severity_hint,
                    "message": self._build_message(match, semantic_label, confidence),
                }
            )

        return findings

    def _build_message(self, match, semantic_label: Optional[str], confidence: Optional[float]) -> str:
        base = f"Detected {match.pattern_name} (pattern confidence: {match.confidence:.0%})."
        if semantic_label == "uncertain":
            base += f" Semantic review: uncertain (confidence: {confidence:.0%})."
        elif semantic_label == "confirmed_secret":
            base += f" Semantic review: confirmed (confidence: {confidence:.0%})."
        return base

    def format_finding(self, finding: dict) -> str:
        """Format a finding as a bordered terminal block with fix steps, ANSI-colored by severity."""
        color = _SEVERITY_COLOR.get(finding["severity"], WHITE)
        top = "┌" + "─" * (_BOX_WIDTH + 2) + "┐"
        mid = "├" + "─" * (_BOX_WIDTH + 2) + "┤"
        bottom = "└" + "─" * (_BOX_WIDTH + 2) + "┘"

        def row(text: str) -> str:
            text = text[:_BOX_WIDTH]
            return "│ " + text.ljust(_BOX_WIDTH) + " │"

        lines = [
            top,
            row("🚨 SECRET DETECTED"),
            mid,
            row(f"File     : {finding['file']}"),
            row(f"Line     : {finding['line']}"),
            row(f"Type     : {finding['pattern']}"),
            row(f"Severity : {finding['severity']}"),
            row(""),
            row("How to fix:"),
            row("1. Remove this value from the file"),
            row("2. Add it to your .env file instead"),
            row('3. Use os.environ.get("VAR_NAME") in code'),
            row("4. Add .env to .gitignore"),
            mid,
            row(
                "Commit has been BLOCKED."
                if finding["severity"] in ("CRITICAL", "HIGH")
                else "Commit allowed — please review."
            ),
            bottom,
        ]
        return color + "\n".join(lines) + RESET

    def run(self) -> int:
        """Scan all staged files and block/warn/pass the commit based on severity."""
        all_findings: List[dict] = []
        for file_path in self.get_staged_files():
            lines = self.get_staged_diff(file_path)
            if not lines:
                continue
            all_findings.extend(self.scan_staged_content(file_path, lines))

        if not all_findings:
            print(f"{WHITE}✅ SecretSweep AI: No secrets detected.{RESET}")
            return 0

        blocking = [f for f in all_findings if f["severity"] in ("CRITICAL", "HIGH")]

        for finding in all_findings:
            print(self.format_finding(finding))

        if blocking:
            print(f"{RED}{BOLD}{len(all_findings)} secret(s) found. Commit blocked.{RESET}")
            return 1

        print(
            f"{YELLOW}⚠️  {len(all_findings)} potential secret(s) found (low confidence). "
            f"Review before pushing.{RESET}"
        )
        return 0


if __name__ == "__main__":
    logging.basicConfig(level=logging.WARNING)
    sys.exit(PreCommitHook().run())
