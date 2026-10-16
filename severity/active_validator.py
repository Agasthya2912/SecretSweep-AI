"""
severity/active_validator.py

Confirms whether a leaked credential is still live by making a minimal,
non-destructive authenticated call against the issuing provider's API
(e.g. AWS STS GetCallerIdentity, Stripe balance retrieval, GitHub user
lookup), feeding the result into the severity engine's active-status factor.

Safety rules (non-negotiable):
  - The raw secret value is NEVER logged or stored — it only ever exists as
    a local variable/parameter for the duration of building and sending
    one HTTP request, then it's gone.
  - Every API call has a 5-second timeout.
  - Calls are rate-limited to 1 per second.
  - Any error (timeout, network failure, unexpected response) returns
    "unknown" — this validator must never raise or crash the pipeline.
"""

import logging
import threading
import time
from typing import Dict, List, Tuple

import requests

logger = logging.getLogger(__name__)

TIMEOUT_SECONDS = 5
MIN_SECONDS_BETWEEN_CALLS = 1.0

AWS_STS_URL = "https://sts.amazonaws.com/"
GITHUB_USER_URL = "https://api.github.com/user"
STRIPE_BALANCE_URL = "https://api.stripe.com/v1/balance"


def _normalize_key(name: str) -> str:
    return name.strip().lower().replace(" ", "_").replace("-", "_")


class ActiveValidator:
    """Checks whether a leaked credential still works, without ever persisting it."""

    # Populated after the class body so it can reference the bound method names below.
    _ROUTING: Dict[str, str] = {}

    def __init__(self) -> None:
        """Set up the 1-call/second rate limiter and the 5-second request timeout."""
        self._timeout = TIMEOUT_SECONDS
        self._min_interval = MIN_SECONDS_BETWEEN_CALLS
        self._last_call_at = 0.0
        self._rate_limit_lock = threading.Lock()

    def _rate_limit(self) -> None:
        """Block, if needed, so calls stay at or below 1 per second."""
        with self._rate_limit_lock:
            elapsed = time.monotonic() - self._last_call_at
            wait_seconds = self._min_interval - elapsed
            if wait_seconds > 0:
                time.sleep(wait_seconds)
            self._last_call_at = time.monotonic()

    def validate(self, pattern_name: str, raw_secret_value: str) -> str:
        """Route to the right provider check and return "active" | "revoked" | "unknown".

        raw_secret_value is used only in-memory to build this one request and is
        never logged, never assigned to self, and never returned to the caller.
        """
        method_name = self._ROUTING.get(_normalize_key(pattern_name), "_validate_generic")
        method = getattr(self, method_name)

        self._rate_limit()
        try:
            return method(raw_secret_value)
        except Exception:
            logger.warning("Active validation errored for pattern %r — returning unknown", pattern_name)
            return "unknown"

    def _validate_aws_key(self, access_key: str) -> str:
        """POST to STS GetCallerIdentity: 200 -> active, InvalidClientTokenId -> revoked."""
        try:
            response = requests.post(
                AWS_STS_URL,
                data={"Action": "GetCallerIdentity", "Version": "2011-06-15"},
                headers={"X-Amz-Access-Key": access_key},
                timeout=self._timeout,
            )
        except requests.RequestException:
            return "unknown"

        if response.status_code == 200:
            return "active"
        if "InvalidClientTokenId" in response.text:
            return "revoked"
        return "unknown"

    def _validate_github_token(self, token: str) -> str:
        """GET /user with the token: 200 -> active, 401 -> revoked."""
        try:
            response = requests.get(
                GITHUB_USER_URL,
                headers={"Authorization": f"token {token}"},
                timeout=self._timeout,
            )
        except requests.RequestException:
            return "unknown"

        if response.status_code == 200:
            return "active"
        if response.status_code == 401:
            return "revoked"
        return "unknown"

    def _validate_stripe_key(self, key: str) -> str:
        """GET /v1/balance with the key: 200 -> active, 401 -> revoked."""
        try:
            response = requests.get(
                STRIPE_BALANCE_URL,
                headers={"Authorization": f"Bearer {key}"},
                timeout=self._timeout,
            )
        except requests.RequestException:
            return "unknown"

        if response.status_code == 200:
            return "active"
        if response.status_code == 401:
            return "revoked"
        return "unknown"

    def _validate_generic(self, secret: str) -> str:
        """No known provider API to check against — always unknown."""
        return "unknown"

    def validate_batch(self, findings: List[Tuple[str, str, str]]) -> Dict[str, str]:
        """Validate [(pattern_name, raw_value, secret_hash), ...], skipping duplicate hashes.

        Returns {secret_hash: status}. Rate limiting is enforced by validate() itself,
        so calls made here are naturally spaced at least 1 second apart.
        """
        results: Dict[str, str] = {}
        for pattern_name, raw_value, secret_hash in findings:
            if secret_hash in results:
                continue
            results[secret_hash] = self.validate(pattern_name, raw_value)
        return results


ActiveValidator._ROUTING = {
    # --- spec's literal category keys ---
    "aws_access_key": "_validate_aws_key",
    "aws_root_key": "_validate_aws_key",
    "github_token": "_validate_github_token",
    "github_oauth": "_validate_github_token",
    "github_app_token": "_validate_github_token",
    "stripe_live_secret": "_validate_stripe_key",
    # --- real pattern_name strings from scanner/patterns/secret_patterns.py ---
    "aws_access_key_id": "_validate_aws_key",
    "aws_secret_access_key": "_validate_aws_key",
    "github_personal_token": "_validate_github_token",
    "github_oauth_token": "_validate_github_token",
    "stripe_live_secret_key": "_validate_stripe_key",
}
