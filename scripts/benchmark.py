"""Benchmarks SecretSweep AI against GitLeaks and TruffleHog on the same
repositories: True/False Positives, False Negatives, Precision, Recall, F1,
and runtime per tool.

Ground truth (both the trufflesecurity/test_keys real-world secrets and the
synthetic repo's fixtures) was empirically verified against the actual
PatternScanner/ObfuscationScanner before being hardcoded here, following this
project's established practice of never trusting hand-typed fixture data on
faith (see CLAUDE.md Phase 12).

GitLeaks/TruffleHog binaries are resolved from GITLEAKS_BIN/TRUFFLEHOG_BIN
(defaulting to whatever's on PATH) since this environment has no Docker.
"""

import hashlib
import json
import logging
import os
import shutil
import subprocess
import time
from pathlib import Path
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

BENCHMARK_DIR = Path("data/benchmark_repos")
TEST_KEYS_LOCAL_PATH = BENCHMARK_DIR / "test_keys"
TEST_KEYS_REPO_URL = "https://github.com/trufflesecurity/test_keys.git"
SYNTHETIC_REPO_PATH = BENCHMARK_DIR / "synthetic_repo"
PIPELINE_CLONE_DIR = BENCHMARK_DIR / "_secretsweep_clones"

GITLEAKS_BIN = os.environ.get("GITLEAKS_BIN", "gitleaks")
TRUFFLEHOG_BIN = os.environ.get("TRUFFLEHOG_BIN", "trufflehog")

RESULTS_PATH = "benchmark_results.json"


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _git(*args: str, cwd: Path) -> None:
    subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True, text=True)


def _to_file_uri(path: Path) -> str:
    """TruffleHog on Windows expects `file://C:/...` (two slashes) — `file:///C:/...`
    (the textbook-correct three-slash form) makes it double the drive letter and fail.
    Empirically verified against trufflehog 3.97.4 on this machine; see CLAUDE.md Phase 12.
    """
    return "file://" + path.resolve().as_posix()


# ---------------------------------------------------------------------------
# Ground truth: trufflesecurity/test_keys — 6 real credentials confirmed by
# reading its actual git history (git log -p --all), not assumed from the spec.
# ---------------------------------------------------------------------------
TEST_KEYS_GROUND_TRUTH: List[str] = [
    "AKIAYVP4CIPPERUVIFXG",
    "Zt2U1h267eViPnuSA+JO5ABhiu4T7XUMSZ+Y2Oth",
    "AKIAQYLPMN5HHHFPZAM2",
    "1tUm636uS1yOEcfP5pvfqJ/ml36mF7AkyHsEU0IU",
    "admin:admin",
    "-----BEGIN OPENSSH PRIVATE KEY-----",
]
TEST_KEYS_FALSE_POSITIVE_TRAPS: List[str] = []


# ---------------------------------------------------------------------------
# Synthetic repo fixtures — each verified via scripts/benchmark.py's own
# build_synthetic_repo() against the real PatternScanner/ObfuscationScanner
# with hard assertions (see _verify_fixtures below), not hand-counted regex math.
# ---------------------------------------------------------------------------
SYNTHETIC_OBVIOUS_FILES: Dict[str, str] = {
    "obvious_aws_key.py": "AKIAHBRPOIG8F1CBFNO6",
    "obvious_aws_secret.py": 'aws_secret_access_key = "dz1C5Jau2RJtBRnlWmTSHf6pWkLUyifDLkDmWJ6U"',
    "obvious_google_key.py": "AIzakxwnQrS7RPeMOkIUpkDyr7OSJoRu1XXdo0c",
    "obvious_github_pat.py": "ghp_Zuzren68K4TunPFz46PDjqipVJIqVLB5Lzxo",
    "obvious_gitlab_token.py": "glpat-iGFfWd3hjOkYRBMeyyMD",
    "obvious_stripe_key.py": "sk_live_HqJ38aRUhR4IWrXPvhsBkDa9",
    "obvious_twilio_sid.py": "ACU4UqGWlG6g3Ot1OGMmjxWkI9X7H6aMuF",
    "obvious_sendgrid_key.py": "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",
    "obvious_generic_token.py": 'token = "eTOdoe5c3veGprQFnIiU74KKEpYEZA"',
    "obvious_mongodb_uri.py": "mongodb://admin:mggQBwBAD3UdRPPg@cluster0.example.mongodb.net",
}

SYNTHETIC_OBFUSCATED_FILES: Dict[str, str] = {
    "obf_base64_aws.py": 'encoded_key = "QUtJQUNTSjNYRzM1QjYxWDkxWkw="',
    "obf_hex_stripe.py": 'pwd_hex = "736b5f6c6976655f6432673068796a676b4731466958794d47724b6c7965644c"',
    "obf_unicode_aws.py": (
        'utoken = "\\u0041\\u004b\\u0049\\u0041\\u0044\\u004c\\u0044\\u004b\\u0053\\u0052'
        '\\u0045\\u0037\\u0047\\u0044\\u0047\\u0033\\u0056\\u0056\\u0037\\u0032"'
    ),
    "obf_rot13_stripe.py": 'val = "fx_yvir_xv2sKhq4YekHyEZrWDugS5KH"',
}
SYNTHETIC_CONCAT_LINES: List[str] = [
    'cpart1 = "ghp_"',
    'cpart2 = "9xTBcE9AMXfwiPf3QUjKZtgSIBCLcjag5Y0h"',
    "full_token = cpart1 + cpart2",
]

SYNTHETIC_FP_TRAP_FILES: Dict[str, str] = {
    "trap_commit_sha.py": 'commit_sha = "a94a8fe5ccb19ba61c4c0873d391e987982fbbd3"',
    "trap_uuid_session.py": 'session_id = "550e8400-e29b-41d4-a716-446655440000"',
    "trap_base64_config.py": 'chart_theme_data = "eyJ0aGVtZSI6ImRhcmsiLCJmb250IjoiSW50ZXIifQ=="',
    "trap_cache_bust.py": 'cache_bust = "iVbX504XvhTIFq7WSD1v28yfTcfTn27R"',
    "trap_ssh_pubkey.py": (
        'ssh_pubkey = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDe3Al0EMPzutVNk5DixaYrGMK56RqU'
        'oqGBinke6SWVWmqom1lBcJWzor6Hln"'
    ),
    "trap_submodule_commit.py": 'submodule_commit = "1a410eeb99fbd5636cbba21c5a53ba1f95d2b4d3"',
    "trap_npm_integrity.py": "# integrity sha256-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/uxy9rx7HNQ=",
    "trap_request_trace_id.py": 'x_request_id = "7f3e9a2b8c1d4e6f0a5b9c2d8e1f4a7b"',
    "trap_build_hash.py": 'APP_BUILD_HASH = "8f14e45fceea167a5a36dedd4bea2543"',
    "trap_image_digest.py": 'image_digest = "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"',
}

SYNTHETIC_GROUND_TRUTH_OBVIOUS: List[str] = [
    "AKIAHBRPOIG8F1CBFNO6",
    "dz1C5Jau2RJtBRnlWmTSHf6pWkLUyifDLkDmWJ6U",
    "AIzakxwnQrS7RPeMOkIUpkDyr7OSJoRu1XXdo0c",
    "ghp_Zuzren68K4TunPFz46PDjqipVJIqVLB5Lzxo",
    "glpat-iGFfWd3hjOkYRBMeyyMD",
    "sk_live_HqJ38aRUhR4IWrXPvhsBkDa9",
    "ACU4UqGWlG6g3Ot1OGMmjxWkI9X7H6aMuF",
    "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",
    "eTOdoe5c3veGprQFnIiU74KKEpYEZA",
    "mongodb://admin:mggQBwBAD3UdRPPg@",
]
SYNTHETIC_GROUND_TRUTH_OBFUSCATED: List[str] = [
    "AKIACSJ3XG35B61X91ZL",
    "sk_live_d2g0hyjgkG1FiXyMGrKlyedL",
    "AKIADLDKSRE7GDG3VV72",
    "sk_live_ki2fXud4LrxUlRMeJQhtF5XU",
    "ghp_9xTBcE9AMXfwiPf3QUjKZtgSIBCLcjag5Y0h",
]
SYNTHETIC_GROUND_TRUTH: List[str] = SYNTHETIC_GROUND_TRUTH_OBVIOUS + SYNTHETIC_GROUND_TRUTH_OBFUSCATED
SYNTHETIC_FALSE_POSITIVE_TRAPS: List[str] = list(SYNTHETIC_FP_TRAP_FILES.values())


def _verify_fixtures() -> None:
    """Re-derive the synthetic ground truth from the real scanners and assert it
    matches the hardcoded lists above, so a future regex/decoder change can't
    silently invalidate this benchmark's ground truth without failing loudly.
    """
    from obfuscation.obfuscation_scanner import ObfuscationScanner
    from scanner.models import DiffLine
    from scanner.pattern_scanner import PatternScanner

    def line(content: str, ln: int = 1) -> DiffLine:
        return DiffLine(file_path="x.py", line_number=ln, content=content, change_type="added", commit_hash="c", author_email="a")

    ps = PatternScanner()
    obf = ObfuscationScanner()

    derived_obvious = []
    for content in SYNTHETIC_OBVIOUS_FILES.values():
        matches = ps.scan_diff_lines([line(content)])
        assert len(matches) == 1, f"obvious fixture no longer matches exactly once: {content!r} -> {matches}"
        derived_obvious.append(matches[0].matched_value)
    assert derived_obvious == SYNTHETIC_GROUND_TRUTH_OBVIOUS, "obvious ground truth is stale vs PatternScanner"

    derived_obfuscated = []
    for content in SYNTHETIC_OBFUSCATED_FILES.values():
        matches = obf.scan_lines([line(content)])
        assert len(matches) == 1, f"obfuscated fixture no longer matches exactly once: {content!r} -> {matches}"
        derived_obfuscated.append(matches[0].decoded_value)
    concat_lines = [line(c, i + 1) for i, c in enumerate(SYNTHETIC_CONCAT_LINES)]
    concat_matches = obf.scan_lines(concat_lines)
    assert len(concat_matches) == 1, concat_matches
    derived_obfuscated.append(concat_matches[0].decoded_value)
    assert derived_obfuscated == SYNTHETIC_GROUND_TRUTH_OBFUSCATED, "obfuscated ground truth is stale vs ObfuscationScanner"

    for content in SYNTHETIC_FP_TRAP_FILES.values():
        assert ps.scan_diff_lines([line(content)]) == [], f"FP trap now matches Layer 1: {content!r}"
        assert obf.scan_lines([line(content)]) == [], f"FP trap now matches Layer 3: {content!r}"


def build_synthetic_repo(path: Path = SYNTHETIC_REPO_PATH) -> Path:
    """(Re)create a small git repo: 10 obvious + 5 obfuscated real secrets (one
    commit each) plus 10 false-positive traps, for reproducible benchmarking.
    """
    if path.exists():
        shutil.rmtree(path)
    path.mkdir(parents=True)

    _git("init", "-q", cwd=path)
    _git("config", "user.email", "benchmark@secretsweep.local", cwd=path)
    _git("config", "user.name", "SecretSweep Benchmark", cwd=path)

    all_single_files = {**SYNTHETIC_OBVIOUS_FILES, **SYNTHETIC_OBFUSCATED_FILES, **SYNTHETIC_FP_TRAP_FILES}
    for fname, content in all_single_files.items():
        (path / fname).write_text(content + "\n", encoding="utf-8")
        _git("add", fname, cwd=path)
        _git("commit", "-q", "-m", f"add {fname}", cwd=path)

    (path / "obf_concat_github.py").write_text("\n".join(SYNTHETIC_CONCAT_LINES) + "\n", encoding="utf-8")
    _git("add", "obf_concat_github.py", cwd=path)
    _git("commit", "-q", "-m", "add obf_concat_github.py", cwd=path)

    return path


def ensure_test_keys_repo(path: Path = TEST_KEYS_LOCAL_PATH) -> Path:
    """Clone trufflesecurity/test_keys locally once, reusing the clone on later runs."""
    if not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run(["git", "clone", "-q", TEST_KEYS_REPO_URL, str(path)], check=True, capture_output=True, text=True)
    return path


class BenchmarkRunner:
    """Runs SecretSweep AI, GitLeaks, and TruffleHog against the same repositories
    and computes TP/FP/FN/precision/recall/F1/runtime for each.
    """

    def __init__(self) -> None:
        self._pipeline = None  # lazy: ScanPipeline eagerly loads the CodeBERT model

    def _get_pipeline(self):
        if self._pipeline is None:
            from scanner.scan_pipeline import ScanPipeline

            self._pipeline = ScanPipeline(clone_base_dir=str(PIPELINE_CLONE_DIR))
        return self._pipeline

    # ------------------------------------------------------------------ tools

    def run_secretsweep(self, repo_path: str) -> dict:
        """Run the full SecretSweep pipeline (Layers 1-3) on repo_path.

        findings are secret_hash / decoded_value_hash strings (never raw values),
        per this project's never-store-plaintext convention (CLAUDE.md §7) —
        even here, where nothing is persisted, only ever held in-process.
        """
        pipeline = self._get_pipeline()
        source = str(Path(repo_path).resolve().as_posix())

        start = time.perf_counter()
        result = pipeline.run(source)
        runtime = time.perf_counter() - start

        findings = set()
        for semantic_result in (*result.confirmed_secrets, *result.uncertain_findings):
            findings.add(semantic_result.pattern_match.matched_value_hash)
        for obf_match in result.obfuscation_matches:
            findings.add(obf_match.decoded_value_hash)

        return {"findings": list(findings), "runtime_sec": runtime}

    def run_gitleaks(self, repo_path: str) -> dict:
        report_path = Path(repo_path).parent / f"{Path(repo_path).name}_gitleaks_report.json"
        report_path.unlink(missing_ok=True)

        start = time.perf_counter()
        subprocess.run(
            [
                GITLEAKS_BIN, "detect",
                f"--source={repo_path}",
                "--report-format=json",
                f"--report-path={report_path}",
                "--no-banner",
                "--exit-code=0",
            ],
            capture_output=True, text=True,
        )
        runtime = time.perf_counter() - start

        findings: List[str] = []
        if report_path.exists() and report_path.stat().st_size > 0:
            with open(report_path, encoding="utf-8") as f:
                data = json.load(f)
            for item in data:
                secret = item.get("Secret") or item.get("Match", "")
                if secret:
                    findings.append(secret)

        return {"findings": findings, "runtime_sec": runtime}

    def run_trufflehog(self, repo_path: str) -> dict:
        uri = _to_file_uri(Path(repo_path))

        start = time.perf_counter()
        proc = subprocess.run(
            [TRUFFLEHOG_BIN, "git", uri, "--json", "--no-verification"],
            capture_output=True, text=True,
        )
        runtime = time.perf_counter() - start

        findings: List[str] = []
        for raw_line in proc.stdout.splitlines():
            raw_line = raw_line.strip()
            if not raw_line.startswith("{"):
                continue
            try:
                item = json.loads(raw_line)
            except json.JSONDecodeError:
                continue
            raw_value = item.get("Raw")
            if raw_value:
                findings.append(raw_value)

        return {"findings": findings, "runtime_sec": runtime}

    # ------------------------------------------------------------------ scoring

    def calculate_metrics(
        self,
        found: List[str],
        ground_truth: List[str],
        false_positive_traps: List[str],
        runtime_sec: float = 0.0,
    ) -> dict:
        """Containment-based matching: a ground-truth secret counts as found if
        it appears as a substring of some finding or vice versa. Exact-string
        equality is too brittle across tools that report matched text at
        different granularity (e.g. TruffleHog often includes the surrounding
        assignment, GitLeaks/SecretSweep report just the secret value).
        """

        def is_match(secret: str, finding: str) -> bool:
            secret, finding = secret.strip(), finding.strip()
            return bool(secret) and bool(finding) and (secret in finding or finding in secret)

        matched_ground_truth = set()
        matched_findings = set()
        for gt in ground_truth:
            for idx, f in enumerate(found):
                if is_match(gt, f):
                    matched_ground_truth.add(gt)
                    matched_findings.add(idx)

        tp = len(matched_ground_truth)
        fn = len(ground_truth) - tp
        fp = len(found) - len(matched_findings)

        trap_hits = sum(
            1 for idx, f in enumerate(found) if idx not in matched_findings and any(is_match(trap, f) for trap in false_positive_traps)
        )

        precision = tp / (tp + fp) if (tp + fp) else (1.0 if not found else 0.0)
        recall = tp / (tp + fn) if (tp + fn) else 1.0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0

        return {
            "tp": tp,
            "fp": fp,
            "fn": fn,
            "fp_from_designed_traps": trap_hits,
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1": round(f1, 4),
            "runtime_sec": round(runtime_sec, 3),
        }

    # ------------------------------------------------------------------ orchestration

    def run_full_benchmark(self) -> dict:
        logging.info("Verifying synthetic-repo fixtures against the real scanners...")
        _verify_fixtures()

        logging.info("Preparing repositories...")
        test_keys_path = ensure_test_keys_repo()
        synthetic_path = build_synthetic_repo()

        repos = [
            ("test_keys", test_keys_path, TEST_KEYS_GROUND_TRUTH, TEST_KEYS_FALSE_POSITIVE_TRAPS),
            ("synthetic", synthetic_path, SYNTHETIC_GROUND_TRUTH, SYNTHETIC_FALSE_POSITIVE_TRAPS),
        ]

        tool_runners = {
            "SecretSweep": self.run_secretsweep,
            "GitLeaks": self.run_gitleaks,
            "TruffleHog": self.run_trufflehog,
        }

        per_repo: Dict[str, Dict[str, dict]] = {}
        pooled: Dict[str, Dict[str, float]] = {name: {"tp": 0, "fp": 0, "fn": 0, "runtime_sec": 0.0} for name in tool_runners}
        tool_available: Dict[str, bool] = {}

        for repo_name, repo_path, ground_truth, fp_traps in repos:
            per_repo[repo_name] = {}
            for tool_name, runner in tool_runners.items():
                logging.info("Running %s on %s...", tool_name, repo_name)
                try:
                    run_result = runner(str(repo_path))
                except (FileNotFoundError, OSError) as exc:
                    logging.warning("%s is not available in this environment (%s) — skipping.", tool_name, exc)
                    tool_available[tool_name] = False
                    continue

                tool_available[tool_name] = True
                ground_truth_for_tool = ground_truth
                if tool_name == "SecretSweep":
                    ground_truth_for_tool = [_sha256(v) for v in ground_truth]

                metrics = self.calculate_metrics(
                    run_result["findings"], ground_truth_for_tool, fp_traps, run_result["runtime_sec"]
                )
                per_repo[repo_name][tool_name] = metrics
                pooled[tool_name]["tp"] += metrics["tp"]
                pooled[tool_name]["fp"] += metrics["fp"]
                pooled[tool_name]["fn"] += metrics["fn"]
                pooled[tool_name]["runtime_sec"] += metrics["runtime_sec"]

        overall: Dict[str, dict] = {}
        for tool_name in tool_runners:
            if not tool_available.get(tool_name):
                continue
            tp, fp, fn = pooled[tool_name]["tp"], pooled[tool_name]["fp"], pooled[tool_name]["fn"]
            precision = tp / (tp + fp) if (tp + fp) else 0.0
            recall = tp / (tp + fn) if (tp + fn) else 0.0
            f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
            overall[tool_name] = {
                "tp": tp, "fp": fp, "fn": fn,
                "precision": round(precision, 4),
                "recall": round(recall, 4),
                "f1": round(f1, 4),
                "runtime_sec": round(pooled[tool_name]["runtime_sec"], 3),
            }

        self._print_results_table(overall, tool_available)

        report = {"per_repo": per_repo, "overall": overall, "tool_available": tool_available}
        with open(RESULTS_PATH, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)
        logging.info("Saved results to %s", RESULTS_PATH)

        return report

    @staticmethod
    def _print_results_table(overall: Dict[str, dict], tool_available: Dict[str, bool]) -> None:
        header = f"{'Tool':<14}{'Prec.':>9}{'Recall':>10}{'F1':>9}{'Time (s)':>11}"
        sep = "=" * len(header)
        print(sep)
        print(header)
        print(sep)
        for tool_name in ("GitLeaks", "TruffleHog", "SecretSweep"):
            if not tool_available.get(tool_name):
                print(f"{tool_name:<14}{'N/A (not available in this environment)':>39}")
                continue
            m = overall[tool_name]
            print(f"{tool_name:<14}{m['precision']:>9.3f}{m['recall']:>10.3f}{m['f1']:>9.3f}{m['runtime_sec']:>10.1f}s")
        print(sep)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)s | %(message)s")
    BenchmarkRunner().run_full_benchmark()
