"""Targeted tests to cover remote_loader.py and trace/search.py gaps."""

import hashlib
import hmac

import pytest

httpx = pytest.importorskip("httpx", reason="httpx not installed")

from unittest.mock import MagicMock, patch  # noqa: E402

from policyshield.shield.remote_loader import RemoteRuleLoader  # noqa: E402


VALID_YAML = """\
shield_name: remote-test
version: 1
rules:
  - id: block-exec
    when:
      tool: exec
    then: BLOCK
    message: blocked
"""


class TestRemoteLoaderFetchOnce:
    """Cover fetch_once paths in RemoteRuleLoader."""

    def test_fetch_success(self):
        """Successful fetch returns a RuleSet."""
        loader = RemoteRuleLoader(url="http://example.com/rules.yaml")
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = VALID_YAML.encode("utf-8")
        mock_resp.headers = {}

        with patch("httpx.Client") as mock_client:
            mock_client.return_value.__enter__ = MagicMock(
                return_value=MagicMock(get=MagicMock(return_value=mock_resp))
            )
            mock_client.return_value.__exit__ = MagicMock(return_value=False)
            result = loader.fetch_once()

        assert result is not None
        assert result.shield_name == "remote-test"
        assert len(result.rules) == 1

    def test_fetch_304_not_modified(self):
        """304 response returns None (no changes)."""
        loader = RemoteRuleLoader(url="http://example.com/rules.yaml")
        mock_resp = MagicMock()
        mock_resp.status_code = 304

        with patch("httpx.Client") as mock_client:
            mock_client.return_value.__enter__ = MagicMock(
                return_value=MagicMock(get=MagicMock(return_value=mock_resp))
            )
            mock_client.return_value.__exit__ = MagicMock(return_value=False)
            result = loader.fetch_once()

        assert result is None

    def test_fetch_4xx_error(self):
        """4xx response returns None and logs critical."""
        loader = RemoteRuleLoader(url="http://example.com/rules.yaml")
        mock_resp = MagicMock()
        mock_resp.status_code = 403

        with patch("httpx.Client") as mock_client:
            mock_client.return_value.__enter__ = MagicMock(
                return_value=MagicMock(get=MagicMock(return_value=mock_resp))
            )
            mock_client.return_value.__exit__ = MagicMock(return_value=False)
            result = loader.fetch_once()

        assert result is None

    def test_fetch_5xx_error(self):
        """5xx response returns None."""
        loader = RemoteRuleLoader(url="http://example.com/rules.yaml")
        mock_resp = MagicMock()
        mock_resp.status_code = 500

        with patch("httpx.Client") as mock_client:
            mock_client.return_value.__enter__ = MagicMock(
                return_value=MagicMock(get=MagicMock(return_value=mock_resp))
            )
            mock_client.return_value.__exit__ = MagicMock(return_value=False)
            result = loader.fetch_once()

        assert result is None

    def test_fetch_exception(self):
        """Network exception returns None."""
        loader = RemoteRuleLoader(url="http://example.com/rules.yaml")

        with patch("httpx.Client") as mock_client:
            mock_client.return_value.__enter__ = MagicMock(
                return_value=MagicMock(get=MagicMock(side_effect=Exception("Connection refused")))
            )
            mock_client.return_value.__exit__ = MagicMock(return_value=False)
            result = loader.fetch_once()

        assert result is None

    def test_fetch_same_content_returns_none(self):
        """Fetching same content twice returns None on second call."""
        loader = RemoteRuleLoader(url="http://example.com/rules.yaml")
        content = VALID_YAML.encode("utf-8")

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = content
        mock_resp.headers = {}

        with patch("httpx.Client") as mock_client:
            mock_client.return_value.__enter__ = MagicMock(
                return_value=MagicMock(get=MagicMock(return_value=mock_resp))
            )
            mock_client.return_value.__exit__ = MagicMock(return_value=False)

            result1 = loader.fetch_once()
            assert result1 is not None

            result2 = loader.fetch_once()
            assert result2 is None  # same hash

    def test_signature_verification_pass(self):
        """Valid HMAC signature allows fetch."""
        key = "secret-key"
        content = VALID_YAML.encode("utf-8")
        sig = "sha256=" + hmac.HMAC(key.encode(), content, hashlib.sha256).hexdigest()

        loader = RemoteRuleLoader(url="http://example.com/rules.yaml", signature_key=key)
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = content
        mock_resp.headers = {"X-PolicyShield-Signature": sig}

        with patch("httpx.Client") as mock_client:
            mock_client.return_value.__enter__ = MagicMock(
                return_value=MagicMock(get=MagicMock(return_value=mock_resp))
            )
            mock_client.return_value.__exit__ = MagicMock(return_value=False)
            result = loader.fetch_once()

        assert result is not None

    def test_signature_verification_fail(self):
        """Invalid HMAC signature rejects fetch."""
        loader = RemoteRuleLoader(url="http://example.com/rules.yaml", signature_key="secret")
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = VALID_YAML.encode("utf-8")
        mock_resp.headers = {"X-PolicyShield-Signature": "sha256=bad"}

        with patch("httpx.Client") as mock_client:
            mock_client.return_value.__enter__ = MagicMock(
                return_value=MagicMock(get=MagicMock(return_value=mock_resp))
            )
            mock_client.return_value.__exit__ = MagicMock(return_value=False)
            result = loader.fetch_once()

        assert result is None


class TestRemoteLoaderStartStop:
    """Cover start/stop lifecycle."""

    def test_start_and_stop(self):
        loader = RemoteRuleLoader(url="http://example.com/rules.yaml", refresh_interval=0.05)
        with patch.object(loader, "fetch_once", return_value=None):
            loader.start()
            assert loader._thread is not None
            loader.stop()
            assert loader._stop_event.is_set()

    def test_stop_without_start(self):
        loader = RemoteRuleLoader(url="http://example.com/rules.yaml")
        loader.stop()  # should not error
