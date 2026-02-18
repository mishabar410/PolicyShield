"""Tests for remote rule loader."""

from __future__ import annotations

import hashlib
import hmac
from unittest.mock import MagicMock, patch

from policyshield.shield.remote_loader import RemoteRuleLoader

RULES_YAML = "shield_name: test\nversion: 1\nrules:\n  - id: r1\n    tool: exec\n    then: BLOCK\n"


class _FakeResp:
    def __init__(self, status_code=200, content=b"", headers=None):
        self.status_code = status_code
        self.content = content
        self.headers = headers or {}


class TestRemoteRuleLoader:
    def test_fetch_and_parse(self):
        resp = _FakeResp(200, RULES_YAML.encode())
        with patch("policyshield.shield.remote_loader.httpx.Client") as mock_cls:
            mock_client = MagicMock()
            mock_client.get.return_value = resp
            mock_client.__enter__ = MagicMock(return_value=mock_client)
            mock_client.__exit__ = MagicMock(return_value=False)
            mock_cls.return_value = mock_client

            loader = RemoteRuleLoader(url="http://test.local/rules.yaml")
            ruleset = loader.fetch_once()
            assert ruleset is not None
            assert len(ruleset.rules) == 1

    def test_304_not_modified(self):
        resp = _FakeResp(304)
        with patch("policyshield.shield.remote_loader.httpx.Client") as mock_cls:
            mock_client = MagicMock()
            mock_client.get.return_value = resp
            mock_client.__enter__ = MagicMock(return_value=mock_client)
            mock_client.__exit__ = MagicMock(return_value=False)
            mock_cls.return_value = mock_client

            loader = RemoteRuleLoader(url="http://test.local/rules.yaml")
            ruleset = loader.fetch_once()
            assert ruleset is None

    def test_signature_verification_pass(self):
        content = RULES_YAML.encode()
        sig = "sha256=" + hmac.new(b"secret", content, hashlib.sha256).hexdigest()
        resp = _FakeResp(200, content, {"X-PolicyShield-Signature": sig})

        with patch("policyshield.shield.remote_loader.httpx.Client") as mock_cls:
            mock_client = MagicMock()
            mock_client.get.return_value = resp
            mock_client.__enter__ = MagicMock(return_value=mock_client)
            mock_client.__exit__ = MagicMock(return_value=False)
            mock_cls.return_value = mock_client

            loader = RemoteRuleLoader(url="http://test.local/rules.yaml", signature_key="secret")
            ruleset = loader.fetch_once()
            assert ruleset is not None

    def test_bad_signature_rejected(self):
        content = RULES_YAML.encode()
        resp = _FakeResp(200, content, {"X-PolicyShield-Signature": "sha256=bad"})

        with patch("policyshield.shield.remote_loader.httpx.Client") as mock_cls:
            mock_client = MagicMock()
            mock_client.get.return_value = resp
            mock_client.__enter__ = MagicMock(return_value=mock_client)
            mock_client.__exit__ = MagicMock(return_value=False)
            mock_cls.return_value = mock_client

            loader = RemoteRuleLoader(url="http://test.local/rules.yaml", signature_key="secret")
            ruleset = loader.fetch_once()
            assert ruleset is None

    def test_http_error_returns_none(self):
        resp = _FakeResp(500)
        with patch("policyshield.shield.remote_loader.httpx.Client") as mock_cls:
            mock_client = MagicMock()
            mock_client.get.return_value = resp
            mock_client.__enter__ = MagicMock(return_value=mock_client)
            mock_client.__exit__ = MagicMock(return_value=False)
            mock_cls.return_value = mock_client

            loader = RemoteRuleLoader(url="http://test.local/rules.yaml")
            assert loader.fetch_once() is None
