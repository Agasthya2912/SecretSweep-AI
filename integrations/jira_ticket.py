"""Auto-creates JIRA tickets (REST API v3) for CRITICAL/HIGH findings."""

import logging
from typing import Optional

import requests

logger = logging.getLogger(__name__)

REQUEST_TIMEOUT_SECONDS = 10
_ELIGIBLE_SEVERITIES = {"CRITICAL", "HIGH"}
_PRIORITY_BY_SEVERITY = {"CRITICAL": "Highest", "HIGH": "High"}


def create_jira_ticket(
    finding: dict,
    jira_base_url: str,
    jira_token: str,
    project_key: str,
) -> Optional[str]:
    """Create a JIRA Security issue for finding. Returns the ticket key, or None on failure.

    finding is expected to carry: severity (str), pattern_name (str), file_path (str),
    author_email (str), severity_score (float), and repo_url (str) for the summary line.
    """
    severity = finding.get("severity", "").upper()
    if severity not in _ELIGIBLE_SEVERITIES:
        return None

    summary = (
        f"SecretSweep AI: {severity} {finding.get('pattern_name', 'secret')} "
        f"detected in {finding.get('repo_url', 'repository')}"
    )
    description_text = (
        f"File: {finding.get('file_path', 'unknown')}\n"
        f"Author: {finding.get('author_email', 'unknown')}\n"
        f"Severity Score: {finding.get('severity_score', 'unknown')}\n"
        f"Action Required: Rotate credential immediately"
    )

    payload = {
        "fields": {
            "project": {"key": project_key},
            "summary": summary,
            "description": {
                "type": "doc",
                "version": 1,
                "content": [
                    {
                        "type": "paragraph",
                        "content": [{"type": "text", "text": description_text}],
                    }
                ],
            },
            "issuetype": {"name": "Security"},
            "priority": {"name": _PRIORITY_BY_SEVERITY[severity]},
        }
    }

    try:
        response = requests.post(
            f"{jira_base_url}/rest/api/3/issue",
            json=payload,
            headers={"Authorization": f"Bearer {jira_token}", "Content-Type": "application/json"},
            timeout=REQUEST_TIMEOUT_SECONDS,
        )
        if response.status_code not in (200, 201):
            logger.error("JIRA ticket creation failed: %s %s", response.status_code, response.text)
            return None
        return response.json().get("key")
    except requests.RequestException:
        logger.error("Failed to create JIRA ticket", exc_info=True)
        return None
    except (ValueError, KeyError):
        logger.error("Unexpected JIRA response shape", exc_info=True)
        return None
