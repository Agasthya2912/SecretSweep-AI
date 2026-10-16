"""Slack Block Kit alerts for CRITICAL/HIGH findings, and a webhook connectivity test
used by the dashboard's Settings page "Test Slack" button.
"""

import logging
import os
from typing import Optional, Tuple

import requests

from scanner.models import ScanResult

logger = logging.getLogger(__name__)

DASHBOARD_URL = os.environ.get("DASHBOARD_URL", "http://localhost:3000")
REQUEST_TIMEOUT_SECONDS = 10


def _top_finding(scan_result: ScanResult) -> Tuple[str, str]:
    """Return (pattern_name, file_path) for the highest-severity finding, if any."""
    scores_by_hash = {score.secret_hash: score for score in scan_result.severity_scores}
    ranked = sorted(
        scan_result.lifecycles,
        key=lambda lc: scores_by_hash[lc.secret_node.secret_hash].total_score
        if lc.secret_node.secret_hash in scores_by_hash
        else -1,
        reverse=True,
    )
    if not ranked:
        return "unknown", "unknown"
    node = ranked[0].secret_node
    return node.pattern_name, node.first_seen_file


def send_slack_alert(scan_result: ScanResult, repo_url: str, webhook_url: str) -> bool:
    """POST a CRITICAL/HIGH summary to webhook_url. Returns False (never raises) on failure."""
    severity_summary = scan_result.severity_summary or {}
    critical = severity_summary.get("critical", 0)
    high = severity_summary.get("high", 0)

    if critical == 0 and high == 0:
        return False

    top_pattern, top_file = _top_finding(scan_result)

    payload = {
        "blocks": [
            {
                "type": "header",
                "text": {"type": "plain_text", "text": "🚨 SecretSweep AI Alert"},
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": (
                        f"*Repository:* {repo_url}\n"
                        f"*CRITICAL:* {critical} | *HIGH:* {high}\n"
                        f"*Top finding:* {top_pattern} in {top_file}"
                    ),
                },
            },
            {
                "type": "actions",
                "elements": [
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "View Dashboard"},
                        "url": f"{DASHBOARD_URL}/secrets",
                    }
                ],
            },
        ]
    }

    try:
        response = requests.post(webhook_url, json=payload, timeout=REQUEST_TIMEOUT_SECONDS)
        return response.status_code == 200
    except requests.RequestException:
        logger.error("Failed to send Slack alert", exc_info=True)
        return False


def send_slack_test(webhook_url: str) -> bool:
    """Send a test message to verify webhook_url works. Returns False (never raises) on failure."""
    payload = {
        "blocks": [
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": "✅ *SecretSweep AI* — this is a test alert. Your Slack webhook is configured correctly.",
                },
            }
        ]
    }

    try:
        response = requests.post(webhook_url, json=payload, timeout=REQUEST_TIMEOUT_SECONDS)
        return response.status_code == 200
    except requests.RequestException:
        logger.error("Failed to send Slack test message", exc_info=True)
        return False
