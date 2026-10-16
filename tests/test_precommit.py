"""Tests for the pre-commit hook, hook installer, CLI, and Slack alert integration.

Never makes real git calls (subprocess.run is always mocked) and never loads the
real ONNX model (hook.fast_mode is forced True) — both would make these tests
slow and non-deterministic.
"""

import json
import os
import re
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from hooks.hook import PreCommitHook
from hooks.installer import SIGNATURE, check_hook_installed, install_hook, uninstall_hook
from integrations.slack_alert import send_slack_alert
from scanner.models import ScanResult
from scripts.secretsweep_cli import main as cli_main


def _strip_ansi(text: str) -> str:
    return re.sub(r"\033\[[0-9;]*m", "", text)


def _make_scan_result(**overrides) -> ScanResult:
    now = datetime.now(timezone.utc)
    defaults = dict(
        repo_url="https://github.com/example/repo",
        local_path="/tmp/repo",
        status="success",
        total_commits=5,
        started_at=now,
        completed_at=now,
        total_secrets_found=2,
        severity_summary={"critical": 0, "high": 0, "medium": 0, "low": 0},
        developer_profiles=[],
        lifecycles=[],
        severity_scores=[],
    )
    defaults.update(overrides)
    return ScanResult(**defaults)


# --------------------------------------------------------------------------- hook


def test_get_staged_files_returns_list(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "config.py").write_text("x = 1\n", encoding="utf-8")
    (tmp_path / "api").mkdir()
    (tmp_path / "api" / "db.py").write_text("y = 2\n", encoding="utf-8")

    fake_result = SimpleNamespace(stdout="src/config.py\napi/db.py\n")
    with patch("hooks.hook.subprocess.run", return_value=fake_result) as mock_run:
        hook = PreCommitHook()
        files = hook.get_staged_files()

    assert files == ["src/config.py", "api/db.py"]
    mock_run.assert_called_once()


def test_get_staged_diff_returns_added_lines(monkeypatch):
    diff_output = (
        "diff --git a/config.py b/config.py\n"
        "index abc..def 100644\n"
        "--- a/config.py\n"
        "+++ b/config.py\n"
        "@@ -1,3 +1,4 @@\n"
        " import os\n"
        "-old_line = 1\n"
        "+new_line = 1\n"
        "+added_line = 2\n"
    )
    fake_result = SimpleNamespace(stdout=diff_output)
    with patch("hooks.hook.subprocess.run", return_value=fake_result):
        hook = PreCommitHook()
        lines = hook.get_staged_diff("config.py")

    assert lines == ["new_line = 1", "added_line = 2"]


def test_scan_staged_content_detects_aws_key():
    hook = PreCommitHook()
    hook.fast_mode = True

    findings = hook.scan_staged_content("src/config/database.py", ['AWS_KEY = "AKIAIOSFODNN7EXAMPLE"'])

    assert len(findings) == 1
    assert findings[0]["pattern"] == "AWS Access Key ID"
    assert findings[0]["severity"] == "CRITICAL"
    assert findings[0]["file"] == "src/config/database.py"


def test_scan_staged_content_clean_file():
    hook = PreCommitHook()
    hook.fast_mode = True

    findings = hook.scan_staged_content("names.py", ['name = "John Smith"'])

    assert findings == []


def test_format_finding_contains_required_fields():
    hook = PreCommitHook()
    finding = {
        "file": "src/config/database.py",
        "line": 14,
        "pattern": "AWS Access Key ID",
        "severity": "CRITICAL",
        "message": "Detected AWS Access Key ID.",
    }

    output = _strip_ansi(hook.format_finding(finding))

    assert "src/config/database.py" in output
    assert "14" in output
    assert "AWS Access Key ID" in output
    assert "CRITICAL" in output
    assert "Remove this value" in output
    assert ".env" in output


def test_run_blocks_on_critical(monkeypatch):
    hook = PreCommitHook()
    monkeypatch.setattr(hook, "get_staged_files", lambda: ["file.py"])
    monkeypatch.setattr(hook, "get_staged_diff", lambda file_path: ["line"])
    monkeypatch.setattr(
        hook,
        "scan_staged_content",
        lambda file_path, lines: [
            {"file": "file.py", "line": 1, "pattern": "AWS Access Key ID", "severity": "CRITICAL", "message": "m"}
        ],
    )

    assert hook.run() == 1


def test_run_warns_on_medium(monkeypatch):
    hook = PreCommitHook()
    monkeypatch.setattr(hook, "get_staged_files", lambda: ["file.py"])
    monkeypatch.setattr(hook, "get_staged_diff", lambda file_path: ["line"])
    monkeypatch.setattr(
        hook,
        "scan_staged_content",
        lambda file_path, lines: [
            {"file": "file.py", "line": 1, "pattern": "Generic Secret", "severity": "MEDIUM", "message": "m"}
        ],
    )

    assert hook.run() == 0


def test_run_passes_clean_commit(monkeypatch):
    hook = PreCommitHook()
    monkeypatch.setattr(hook, "get_staged_files", lambda: ["file.py"])
    monkeypatch.setattr(hook, "get_staged_diff", lambda file_path: ["line"])
    monkeypatch.setattr(hook, "scan_staged_content", lambda file_path, lines: [])

    assert hook.run() == 0


# --------------------------------------------------------------------------- installer


def test_install_hook_creates_file(tmp_path):
    (tmp_path / ".git" / "hooks").mkdir(parents=True)

    assert install_hook(str(tmp_path)) is True

    hook_path = tmp_path / ".git" / "hooks" / "pre-commit"
    assert hook_path.exists()
    assert SIGNATURE in hook_path.read_text(encoding="utf-8")
    # os.chmod only toggles the read-only attribute on Windows (no real executable
    # bit on NTFS) — os.access(X_OK) is the portable way to check "runnable" here.
    assert os.access(hook_path, os.X_OK)


def test_uninstall_hook_removes_file(tmp_path):
    (tmp_path / ".git" / "hooks").mkdir(parents=True)
    install_hook(str(tmp_path))

    assert uninstall_hook(str(tmp_path)) is True
    assert not (tmp_path / ".git" / "hooks" / "pre-commit").exists()


def test_uninstall_hook_skips_foreign_hook(tmp_path):
    hooks_dir = tmp_path / ".git" / "hooks"
    hooks_dir.mkdir(parents=True)
    foreign_hook = hooks_dir / "pre-commit"
    foreign_hook.write_text("#!/bin/sh\necho not secretsweep\n", encoding="utf-8")

    assert uninstall_hook(str(tmp_path)) is False
    assert foreign_hook.exists()


def test_check_hook_installed_true(tmp_path):
    (tmp_path / ".git" / "hooks").mkdir(parents=True)
    install_hook(str(tmp_path))

    assert check_hook_installed(str(tmp_path)) is True


def test_check_hook_installed_false(tmp_path):
    assert check_hook_installed(str(tmp_path)) is False


# --------------------------------------------------------------------------- CLI


def test_cli_scan_output_json(tmp_path):
    fake_result = _make_scan_result(
        total_commits=7,
        total_secrets_found=1,
        severity_summary={"critical": 1, "high": 0, "medium": 0, "low": 0},
    )
    fake_pipeline = MagicMock()
    fake_pipeline.run.return_value = fake_result
    output_file = tmp_path / "results.json"

    with patch("scanner.scan_pipeline.ScanPipeline", return_value=fake_pipeline):
        exit_code = cli_main(
            [
                "scan",
                "https://github.com/example/repo",
                "--output-format",
                "json",
                "--output-file",
                str(output_file),
            ]
        )

    assert exit_code == 1  # a CRITICAL finding was present
    payload = json.loads(output_file.read_text(encoding="utf-8"))
    assert payload["repo_url"] == "https://github.com/example/repo"
    assert payload["total_commits"] == 7
    assert payload["total_secrets_found"] == 1
    assert payload["severity_summary"] == {"critical": 1, "high": 0, "medium": 0, "low": 0}
    assert payload["high_risk_developers"] == []
    assert payload["secrets"] == []
    assert "scanned_at" in payload


# --------------------------------------------------------------------------- Slack


def test_slack_alert_sends_on_critical():
    scan_result = _make_scan_result(severity_summary={"critical": 1, "high": 0, "medium": 0, "low": 0})

    with patch("integrations.slack_alert.requests.post", return_value=SimpleNamespace(status_code=200)) as mock_post:
        sent = send_slack_alert(scan_result, "https://github.com/example/repo", "https://hooks.slack.com/services/xxx")

    assert sent is True
    mock_post.assert_called_once()


def test_slack_alert_skips_on_low():
    scan_result = _make_scan_result(severity_summary={"critical": 0, "high": 0, "medium": 1, "low": 2})

    with patch("integrations.slack_alert.requests.post") as mock_post:
        sent = send_slack_alert(scan_result, "https://github.com/example/repo", "https://hooks.slack.com/services/xxx")

    assert sent is False
    mock_post.assert_not_called()
