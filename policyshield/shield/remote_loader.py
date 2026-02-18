"""Remote rule loader — fetch rules from HTTP/HTTPS with signature verification."""

from __future__ import annotations

import hashlib
import hmac
import logging
import threading

import httpx

from policyshield.core.models import RuleSet
from policyshield.core.parser import parse_rules_from_string

logger = logging.getLogger(__name__)


class RemoteRuleLoader:
    """Periodically fetch rules from a remote URL.

    Args:
        url: URL to fetch rules from.
        refresh_interval: Seconds between fetches.
        signature_key: Optional HMAC-SHA256 key for verifying rule integrity.
        callback: Called when rules are updated (new_ruleset: RuleSet).
        timeout: HTTP request timeout in seconds.
    """

    def __init__(
        self,
        url: str,
        refresh_interval: float = 30.0,
        signature_key: str | None = None,
        callback: object = None,
        timeout: float = 10.0,
    ) -> None:
        self._url = url
        self._refresh_interval = refresh_interval
        self._signature_key = signature_key
        self._callback = callback
        self._timeout = timeout
        self._last_etag: str | None = None
        self._last_hash: str | None = None
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._poll_loop, daemon=True)
        self._thread.start()
        logger.info(
            "Remote rule loader started: url=%s refresh=%ss",
            self._url,
            self._refresh_interval,
        )

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=5.0)

    def fetch_once(self) -> RuleSet | None:
        """Fetch rules once (for initial load or manual refresh)."""
        try:
            headers: dict[str, str] = {}
            if self._last_etag:
                headers["If-None-Match"] = self._last_etag

            with httpx.Client(timeout=self._timeout) as client:
                resp = client.get(self._url, headers=headers)

            if resp.status_code == 304:
                return None  # Not modified

            if resp.status_code >= 400:
                logger.error("Remote rules fetch failed: HTTP %d", resp.status_code)
                return None

            body = resp.content

            # Verify signature if key is configured
            if self._signature_key:
                server_sig = resp.headers.get("X-PolicyShield-Signature", "")
                expected = "sha256=" + hmac.new(self._signature_key.encode(), body, hashlib.sha256).hexdigest()
                if not hmac.compare_digest(expected, server_sig):
                    logger.error("Remote rules signature verification FAILED")
                    return None

            # Check if content actually changed
            content_hash = hashlib.sha256(body).hexdigest()
            if content_hash == self._last_hash:
                return None

            # Parse
            ruleset = parse_rules_from_string(body.decode("utf-8"))

            self._last_etag = resp.headers.get("ETag")
            self._last_hash = content_hash
            logger.info(
                "Remote rules loaded: %d rules from %s",
                len(ruleset.rules),
                self._url,
            )
            return ruleset

        except Exception as e:
            logger.error("Failed to fetch remote rules: %s", e)
            return None

    def _poll_loop(self) -> None:
        while not self._stop_event.is_set():
            ruleset = self.fetch_once()
            if ruleset and self._callback:
                try:
                    self._callback(ruleset)
                except Exception as e:
                    logger.error("Remote rule callback error: %s", e)
            self._stop_event.wait(self._refresh_interval)
