"""Remote rule loader — fetch rules from HTTP/HTTPS with signature verification."""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import logging
import socket
import threading
from typing import Any
from urllib.parse import urlparse

import httpx

from policyshield.core.models import RuleSet
from policyshield.core.parser import parse_rules_from_string

logger = logging.getLogger(__name__)

_RFC1918_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]


def _is_private_address(host: str) -> bool:
    try:
        addr = ipaddress.ip_address(host)
        return any(addr in net for net in _RFC1918_NETWORKS)
    except ValueError:
        pass
    try:
        resolved = socket.getaddrinfo(host, None)
        for _, _, _, _, sockaddr in resolved:
            addr = ipaddress.ip_address(sockaddr[0])
            if any(addr in net for net in _RFC1918_NETWORKS):
                return True
    except OSError:
        pass
    return False


def _validate_remote_url(url: str) -> None:
    parsed = urlparse(url)
    if parsed.scheme != "https":
        raise ValueError(f"Remote rules URL must use https://, got: {parsed.scheme!r}")
    host = parsed.hostname or ""
    if not host:
        raise ValueError("Remote rules URL has no host")
    if _is_private_address(host):
        raise ValueError(f"Remote rules URL resolves to a private/internal address: {host!r}")


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
        callback: Any = None,
        timeout: float = 10.0,
    ) -> None:
        _validate_remote_url(url)
        self._url = url
        self._refresh_interval = refresh_interval
        self._signature_key = signature_key
        self._callback = callback
        self._timeout = timeout
        self._last_etag: str | None = None
        self._last_hash: str | None = None
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        # NOTE: DNS rebinding limitation — the IP is validated at URL-check time via
        # _validate_remote_url(), but the actual TCP connection may resolve to a
        # different IP (DNS rebinding). TLS verification (verify=True) mitigates this
        # for HTTPS endpoints by requiring a valid certificate for the target hostname.
        self._client = httpx.Client(timeout=self._timeout, verify=True)

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
        try:
            self._client.close()
        except Exception:
            pass

    def fetch_once(self) -> RuleSet | None:
        """Fetch rules once (for initial load or manual refresh)."""
        try:
            headers: dict[str, str] = {}
            if self._last_etag:
                headers["If-None-Match"] = self._last_etag

            resp = self._client.get(self._url, headers=headers)

            if resp.status_code == 304:
                return None  # Not modified

            if resp.status_code >= 400:
                if resp.status_code < 500:
                    # 4xx = client error (bad URL, auth) — won't resolve on retry
                    logger.critical(
                        "Remote rules fetch failed: HTTP %d (client error — check URL/auth)",
                        resp.status_code,
                    )
                else:
                    # 5xx = server error — may be transient
                    logger.warning(
                        "Remote rules fetch failed: HTTP %d (server error — will retry)",
                        resp.status_code,
                    )
                return None

            body = resp.content

            # Verify signature if key is configured
            if self._signature_key:
                server_sig = resp.headers.get("X-PolicyShield-Signature", "")
                expected = "sha256=" + hmac.HMAC(self._signature_key.encode(), body, hashlib.sha256).hexdigest()
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
