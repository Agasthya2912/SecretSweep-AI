"""Orchestrates Git extraction and all six detection/analysis layers: Layer 1
(pattern/entropy), Layer 2 (semantic classification), Layer 3 (obfuscation/
concatenation decoding), Layer 4 (Credential Data Flow Graph construction),
Layer 5 (active-key validation + severity scoring), and Layer 6 (developer
risk profiling).
"""

import logging
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from cdfg.cdfg_builder import CDFGBuilder
from cdfg.models import SecretLifecycle
from ml.finetune import MODEL_SAVE_DIR
from ml.inference import SemanticClassifier
from obfuscation.obfuscation_scanner import ObfuscationScanner
from profiler.developer_profiler import DeveloperProfiler
from scanner.git_extractor import GitExtractor
from scanner.models import CommitData, DiffLine, ScanResult
from scanner.pattern_scanner import PatternMatch, PatternScanner
from severity.active_validator import ActiveValidator
from severity.scorer import SeverityScorer

logger = logging.getLogger(__name__)

DEFAULT_CLONE_BASE_DIR = "data/repos"


def _repo_name_from_url(repo_url: str) -> str:
    """Derive a filesystem-safe directory name from a repo URL, e.g. 'owner/name.git' -> 'name'."""
    name = repo_url.rstrip("/").split("/")[-1]
    name = re.sub(r"\.git$", "", name)
    return name or "repo"


def _group_lines_by_commit(lines: List[DiffLine]) -> Dict[str, List[DiffLine]]:
    grouped: Dict[str, List[DiffLine]] = {}
    for line in lines:
        grouped.setdefault(line.commit_hash, []).append(line)
    return grouped


def _file_count_for_lifecycle(lifecycle: SecretLifecycle) -> int:
    """Count distinct file nodes this secret's defined/used/deleted edges point to."""
    file_node_ids: Set[str] = {
        edge.target_node_id
        for edge in (*lifecycle.defined_in, *lifecycle.used_in, *lifecycle.deleted_in)
    }
    return max(1, len(file_node_ids))


class ScanPipeline:
    """Coordinates GitExtractor (extraction), PatternScanner (Layer 1),
    SemanticClassifier (Layer 2), ObfuscationScanner (Layer 3), CDFGBuilder
    (Layer 4), ActiveValidator + SeverityScorer (Layer 5), and DeveloperProfiler
    (Layer 6) into a single end-to-end repository scan.
    """

    def __init__(
        self,
        clone_base_dir: str = DEFAULT_CLONE_BASE_DIR,
        semantic_model_path: str = MODEL_SAVE_DIR,
        neo4j_uri: Optional[str] = None,
        neo4j_user: Optional[str] = None,
        neo4j_password: Optional[str] = None,
    ) -> None:
        """Store the clone directory and eagerly load all six scanning layers."""
        self.clone_base_dir = clone_base_dir
        self.pattern_scanner = PatternScanner()
        self.semantic_classifier = SemanticClassifier(semantic_model_path)
        self.obfuscation_scanner = ObfuscationScanner()
        self.cdfg_builder = CDFGBuilder(
            neo4j_uri=neo4j_uri, neo4j_user=neo4j_user, neo4j_password=neo4j_password
        )
        self.active_validator = ActiveValidator()
        self.severity_scorer = SeverityScorer()
        self.developer_profiler = DeveloperProfiler()

    def run(
        self,
        repo_url: str,
        enable_active_validation: bool = False,
        repo_visibility: str = "unknown",
        scan_job_id: Optional[str] = None,
    ) -> ScanResult:
        """Clone repo_url, then run Layers 1-5.

        Layer 2 re-checks every Layer 1 match against its surrounding code context to
        drop false positives (obvious placeholders, hashes, etc.) and flag genuinely
        ambiguous cases as "uncertain" for human review, rather than either extreme.
        Layer 4 then traces every confirmed/uncertain/obfuscated secret's full lifecycle
        (birth, usage, deletion, resurrection) across the commit history. Layer 5 scores
        each lifecycle's severity; the active-key check within it only makes real network
        calls when enable_active_validation=True (default False, so a plain run() never
        contacts AWS/GitHub/Stripe by accident). scan_job_id, when given, tags this run's
        CDFG data in Neo4j so the dashboard can later query back just this scan's graph
        (see CDFGBuilder.sync_to_neo4j) — omit it for CLI/benchmark callers with no
        associated ScanJob row.
        """
        started_at = datetime.now(timezone.utc)
        local_path = str(Path(self.clone_base_dir) / _repo_name_from_url(repo_url))

        try:
            extractor = GitExtractor(repo_url, local_path)
            extractor.clone_repo()

            total_commits = 0
            all_commits: List[CommitData] = []
            all_diff_lines: List[DiffLine] = []
            for commit in extractor.extract_all_commits():
                total_commits += 1
                all_commits.append(commit)
                all_diff_lines.extend(extractor.extract_diff_lines(commit))

            pattern_matches: List[PatternMatch] = self.pattern_scanner.scan_diff_lines(all_diff_lines)

            lines_by_commit = _group_lines_by_commit(all_diff_lines)
            items = [
                (match, lines_by_commit.get(match.line.commit_hash, [match.line]))
                for match in pattern_matches
            ]
            semantic_results = self.semantic_classifier.classify_batch(items) if items else []

            confirmed_secrets = [r for r in semantic_results if r.semantic_label == "confirmed_secret"]
            uncertain_findings = [r for r in semantic_results if r.semantic_label == "uncertain"]
            false_positives_removed = sum(
                1 for r in semantic_results if r.semantic_label == "false_positive"
            )

            # Layer 3 runs over every line, not just Layer 1's matches — its whole point
            # is to catch secrets Layer 1's regexes never saw because they were encoded
            # or split across variables in the raw diff text.
            obfuscation_matches = self.obfuscation_scanner.scan_lines(all_diff_lines)

            result = ScanResult(
                repo_url=repo_url,
                local_path=local_path,
                status="success",
                total_commits=total_commits,
                started_at=started_at,
                completed_at=datetime.now(timezone.utc),
                pattern_matches=pattern_matches,
                total_pattern_matches=len(pattern_matches),
                semantic_results=semantic_results,
                confirmed_secrets=confirmed_secrets,
                uncertain_findings=uncertain_findings,
                false_positives_removed=false_positives_removed,
                obfuscation_matches=obfuscation_matches,
                total_obfuscation_findings=len(obfuscation_matches),
                total_secrets_found=len(confirmed_secrets) + len(uncertain_findings) + len(obfuscation_matches),
            )

            # Layer 4: trace every surviving finding's full lifecycle across commit history.
            result.lifecycles = self.cdfg_builder.process_scan_result(result, all_commits)
            result.graph_summary = self.cdfg_builder.get_graph_summary()
            result.high_risk_developers = result.graph_summary["high_risk_developers"]
            if scan_job_id:
                self.cdfg_builder.sync_to_neo4j(scan_job_id=scan_job_id)

            # Layer 5: optional active-key check, then severity scoring for every lifecycle.
            if enable_active_validation:
                findings: List[Tuple[str, str, str]] = [
                    (
                        semantic_result.pattern_match.pattern_name,
                        semantic_result.pattern_match.matched_value,
                        semantic_result.pattern_match.matched_value_hash,
                    )
                    for semantic_result in (*confirmed_secrets, *uncertain_findings)
                ] + [
                    (obf_match.pattern_name, obf_match.decoded_value, obf_match.decoded_value_hash)
                    for obf_match in obfuscation_matches
                ]
                result.active_statuses = self.active_validator.validate_batch(findings)

            file_counts = {
                lifecycle.secret_node.secret_hash: _file_count_for_lifecycle(lifecycle)
                for lifecycle in result.lifecycles
            }
            result.severity_scores = self.severity_scorer.score_all(
                result.lifecycles,
                active_statuses=result.active_statuses,
                repo_visibility=repo_visibility,
                file_counts=file_counts,
            )
            result.severity_summary = self.severity_scorer.get_summary(result.severity_scores)

            # Layer 6: aggregate lifecycles + severity into per-developer risk profiles.
            result.developer_profiles = self.developer_profiler.build_profiles(result, repo_url)
            result.organisation_summary = self.developer_profiler.get_organisation_summary(
                result.developer_profiles
            )

            logger.info(
                "Scan of %s complete: %d commits, %d Layer 1 matches -> %d confirmed, "
                "%d uncertain, %d false positives removed, %d Layer 3 obfuscation findings, "
                "%d Layer 4 lifecycles, severity=%s, %d developer profiles",
                repo_url,
                total_commits,
                len(pattern_matches),
                len(confirmed_secrets),
                len(uncertain_findings),
                false_positives_removed,
                len(obfuscation_matches),
                len(result.lifecycles),
                result.severity_summary,
                len(result.developer_profiles),
            )
            return result
        except Exception as exc:
            logger.error("Scan of %s failed: %s", repo_url, exc)
            return ScanResult(
                repo_url=repo_url,
                local_path=local_path,
                status="failed",
                total_commits=0,
                started_at=started_at,
                completed_at=datetime.now(timezone.utc),
                error_message=str(exc),
            )
        finally:
            self.cdfg_builder.close()
