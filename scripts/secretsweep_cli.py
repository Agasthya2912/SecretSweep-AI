"""CLI entry point: install/uninstall/status the pre-commit hook, and run a
one-off repository scan (with optional JSON output for CI/CD consumption).

Usage:
    python -m scripts.secretsweep_cli install
    python -m scripts.secretsweep_cli uninstall
    python -m scripts.secretsweep_cli status
    python -m scripts.secretsweep_cli scan {repo_url} [--output-format json --output-file results.json]
"""

import argparse
import json
import sys
from datetime import datetime, timezone

from hooks.installer import check_hook_installed, install_hook, uninstall_hook

# Windows consoles often default to cp1252, which can't encode the ✅/❌ used below.
try:
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")
except (AttributeError, ValueError):
    pass


def _cmd_install(args: argparse.Namespace) -> int:
    install_hook(args.repo_path)
    print("✅ SecretSweep AI pre-commit hook installed")
    return 0


def _cmd_uninstall(args: argparse.Namespace) -> int:
    uninstall_hook(args.repo_path)
    print("✅ Hook uninstalled")
    return 0


def _cmd_status(args: argparse.Namespace) -> int:
    if check_hook_installed(args.repo_path):
        print("✅ Hook is installed")
    else:
        print("❌ Hook is not installed")
    return 0


def _severity_summary_dict(raw_summary: dict) -> dict:
    return {
        "critical": raw_summary.get("critical", 0),
        "high": raw_summary.get("high", 0),
        "medium": raw_summary.get("medium", 0),
        "low": raw_summary.get("low", 0),
    }


def _high_risk_developers_list(result) -> list:
    return [
        {
            "email": profile.developer_email,
            "risk_score": profile.risk_score,
            "risk_label": profile.risk_label,
            "total_leaks": profile.total_leaks,
        }
        for profile in result.developer_profiles
        if profile.risk_label == "HIGH"
    ]


def _secrets_list(result) -> list:
    scores_by_hash = {score.secret_hash: score for score in result.severity_scores}
    secrets = []
    for lifecycle in result.lifecycles:
        node = lifecycle.secret_node
        score = scores_by_hash.get(node.secret_hash)
        secrets.append(
            {
                "pattern_name": node.pattern_name,
                "file_path": node.first_seen_file,
                "severity_label": score.severity_label if score else node.severity_hint,
                "severity_score": score.total_score if score else None,
                "commit_hash": node.first_seen_commit,
                "author_email": node.first_seen_author,
            }
        )
    return secrets


def _result_to_json(result, repo_url: str) -> dict:
    severity_summary = _severity_summary_dict(result.severity_summary)
    return {
        "repo_url": repo_url,
        "scanned_at": result.completed_at.isoformat() if result.completed_at else datetime.now(timezone.utc).isoformat(),
        "total_commits": result.total_commits,
        "total_secrets_found": result.total_secrets_found,
        "severity_summary": severity_summary,
        "high_risk_developers": _high_risk_developers_list(result),
        "secrets": _secrets_list(result),
    }


def _print_human_summary(result, repo_url: str) -> None:
    severity_summary = _severity_summary_dict(result.severity_summary)
    bar = "═" * 47
    thin = "─" * 47
    print(bar)
    print("SecretSweep AI Scan Results")
    print(bar)
    print(f"Repository : {repo_url}")
    print(f"Commits    : {result.total_commits}")
    print(f"Secrets    : {result.total_secrets_found}")
    print(thin)
    print(f"CRITICAL   : {severity_summary['critical']}")
    print(f"HIGH       : {severity_summary['high']}")
    print(f"MEDIUM     : {severity_summary['medium']}")
    print(f"LOW        : {severity_summary['low']}")
    print(thin)
    print("High Risk Developers:")
    high_risk = _high_risk_developers_list(result)
    if not high_risk:
        print("  (none)")
    for developer in high_risk:
        print(f"  {developer['email']} — Score: {developer['risk_score']}/100 ({developer['risk_label']})")
    print(bar)


def _cmd_scan(args: argparse.Namespace) -> int:
    from scanner.scan_pipeline import ScanPipeline  # heavy import — only loaded for `scan`

    pipeline = ScanPipeline()
    result = pipeline.run(args.repo_url)

    if result.status == "failed":
        print(f"❌ Scan failed: {result.error_message}")
        return 1

    if args.output_format == "json":
        payload = _result_to_json(result, args.repo_url)
        text = json.dumps(payload, indent=2)
        if args.output_file:
            with open(args.output_file, "w", encoding="utf-8") as f:
                f.write(text)
        else:
            print(text)
    else:
        _print_human_summary(result, args.repo_url)

    severity_summary = _severity_summary_dict(result.severity_summary)
    return 1 if severity_summary["critical"] > 0 else 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="secretsweep")
    subparsers = parser.add_subparsers(dest="command", required=True)

    for name, handler in (("install", _cmd_install), ("uninstall", _cmd_uninstall), ("status", _cmd_status)):
        sub = subparsers.add_parser(name)
        sub.add_argument("--repo-path", dest="repo_path", default=".")
        sub.set_defaults(func=handler)

    scan_parser = subparsers.add_parser("scan")
    scan_parser.add_argument("repo_url")
    scan_parser.add_argument("--output-format", dest="output_format", choices=["text", "json"], default="text")
    scan_parser.add_argument("--output-file", dest="output_file", default=None)
    scan_parser.set_defaults(func=_cmd_scan)

    return parser


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
