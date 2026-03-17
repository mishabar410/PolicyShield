"""Additional coverage tests targeting auth, approval backend, and config builders."""

from __future__ import annotations

import textwrap
from unittest.mock import MagicMock, patch

import pytest

from policyshield.config.loader import (
    PolicyShieldConfig,
    _build_approval_backend,
    build_async_engine_from_config,
    build_engine_from_config,
    validate_config_file,
)
from policyshield.core.models import RuleConfig, RuleSet, Verdict
from policyshield.server.app import _get_api_token


_RULES_YAML = textwrap.dedent("""\
    shield_name: test
    version: 1
    rules:
      - id: r1
        when:
          tool: test_tool
        then: ALLOW
""")


class TestGetApiToken:
    """Cover _get_api_token edge cases (lines 63, 65, 73-76)."""

    def test_empty_string_returns_none(self, monkeypatch):
        monkeypatch.setenv("POLICYSHIELD_API_TOKEN", "")
        assert _get_api_token() is None

    def test_set_token_returns_value(self, monkeypatch):
        monkeypatch.setenv("POLICYSHIELD_API_TOKEN", "my-token")
        assert _get_api_token() == "my-token"

    def test_unset_returns_none(self, monkeypatch):
        monkeypatch.delenv("POLICYSHIELD_API_TOKEN", raising=False)
        assert _get_api_token() is None


class TestVerifyTokenPaths:
    """Cover verify_token 401/403 paths (line 120)."""

    @pytest.fixture
    def authed_client(self, monkeypatch):
        """Client with token auth enabled."""
        from fastapi.testclient import TestClient
        from policyshield.server.app import create_app
        from policyshield.shield.async_engine import AsyncShieldEngine

        monkeypatch.setenv("POLICYSHIELD_API_TOKEN", "test-secret")
        import policyshield.server.app as _app
        _app._token_cache_ts = 0.0

        engine = AsyncShieldEngine(
            RuleSet(shield_name="t", version=1, rules=[
                RuleConfig(id="r1", when={"tool": "t"}, then=Verdict.ALLOW),
            ])
        )
        return TestClient(create_app(engine))

    def test_missing_bearer_returns_401(self, authed_client):
        resp = authed_client.post("/api/v1/check", json={"tool_name": "test", "args": {}})
        assert resp.status_code == 401

    def test_invalid_token_returns_403(self, authed_client):
        resp = authed_client.post(
            "/api/v1/check",
            json={"tool_name": "test", "args": {}},
            headers={"Authorization": "Bearer wrong-token"},
        )
        assert resp.status_code == 403

    def test_valid_token_returns_200(self, authed_client):
        resp = authed_client.post(
            "/api/v1/check",
            json={"tool_name": "test", "args": {}},
            headers={"Authorization": "Bearer test-secret"},
        )
        assert resp.status_code == 200


class TestBuildApprovalBackends:
    """Cover _build_approval_backend branches (lines 242-268)."""

    def test_inmemory(self):
        b = _build_approval_backend("inmemory")
        assert b is not None

    def test_none(self):
        b = _build_approval_backend("none")
        assert b is None

    def test_unknown(self):
        b = _build_approval_backend("unknown_backend_xyz")
        assert b is None

    def test_webhook(self, monkeypatch):
        monkeypatch.setenv("POLICYSHIELD_APPROVAL_WEBHOOK_URL", "https://example.com/hook")
        b = _build_approval_backend("webhook")
        assert b is not None


class TestBuildEngineFromConfigExtended:
    """Cover more config builder branches."""

    def test_build_engine_with_webhook(self, tmp_path, monkeypatch):
        """Cover webhook notifier branch (lines 330-332)."""
        monkeypatch.chdir(tmp_path)
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        (rules_dir / "rules.yaml").write_text(_RULES_YAML, encoding="utf-8")

        cfg = PolicyShieldConfig(
            rules_path=str(rules_dir),
            trace_enabled=False,
            webhook_url="https://example.com/hook",
            webhook_events=["BLOCK"],
        )
        engine = build_engine_from_config(cfg)
        assert engine is not None

    def test_build_async_engine_with_webhook(self, tmp_path, monkeypatch):
        """Cover async webhook notifier branch (lines 429-431)."""
        monkeypatch.chdir(tmp_path)
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        (rules_dir / "rules.yaml").write_text(_RULES_YAML, encoding="utf-8")

        cfg = PolicyShieldConfig(
            rules_path=str(rules_dir),
            trace_enabled=False,
            webhook_url="https://example.com/hook",
            webhook_events=["BLOCK"],
        )
        engine = build_async_engine_from_config(cfg)
        assert engine is not None

    def test_build_engine_with_remote_rules(self, tmp_path, monkeypatch):
        """Cover remote rules loader branch (lines 353-362)."""
        monkeypatch.chdir(tmp_path)
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        (rules_dir / "rules.yaml").write_text(_RULES_YAML, encoding="utf-8")

        cfg = PolicyShieldConfig(
            rules_path=str(rules_dir),
            trace_enabled=False,
            remote_rules_url="https://example.com/rules.yaml",
            remote_rules_interval=300,
        )

        with patch("policyshield.config.loader.RemoteRuleLoader", create=True) as MockLoader:
            mock_loader = MagicMock()
            MockLoader.return_value = mock_loader
            with patch.dict("sys.modules", {
                "policyshield.shield.remote_loader": MagicMock(RemoteRuleLoader=MockLoader)
            }):
                engine = build_engine_from_config(cfg)
                assert engine is not None

    def test_build_async_engine_with_remote_rules(self, tmp_path, monkeypatch):
        """Cover async remote rules loader branch (lines 452-461)."""
        monkeypatch.chdir(tmp_path)
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        (rules_dir / "rules.yaml").write_text(_RULES_YAML, encoding="utf-8")

        cfg = PolicyShieldConfig(
            rules_path=str(rules_dir),
            trace_enabled=False,
            remote_rules_url="https://example.com/rules.yaml",
            remote_rules_interval=300,
        )

        with patch("policyshield.config.loader.RemoteRuleLoader", create=True) as MockLoader:
            mock_loader = MagicMock()
            MockLoader.return_value = mock_loader
            with patch.dict("sys.modules", {
                "policyshield.shield.remote_loader": MagicMock(RemoteRuleLoader=MockLoader)
            }):
                engine = build_async_engine_from_config(cfg)
                assert engine is not None

    def test_validate_config_file_not_found(self):
        """Cover file not found validation."""
        errors = validate_config_file("/nonexistent/path/config.yaml")
        assert any("not found" in e.lower() for e in errors)

    def test_build_engine_with_trace_and_watch(self, tmp_path, monkeypatch):
        """Cover trace + watch branches."""
        monkeypatch.chdir(tmp_path)
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        (rules_dir / "rules.yaml").write_text(_RULES_YAML, encoding="utf-8")

        trace_dir = tmp_path / "traces"
        trace_dir.mkdir()

        cfg = PolicyShieldConfig(
            rules_path=str(rules_dir),
            trace_enabled=True,
            trace_output_dir=str(trace_dir),
            trace_batch_size=10,
            watch=True,
            watch_interval=10.0,
        )
        engine = build_engine_from_config(cfg)
        assert engine is not None
        engine.stop_watching()
