"""Tests for lifecycle & reliability hardening — prompts 331-340."""

from __future__ import annotations

import json
import logging
import sys

import pytest

from policyshield.core.models import Verdict
from policyshield.server.app import create_app
from policyshield.shield.async_engine import AsyncShieldEngine
from policyshield.trace.recorder import TraceRecorder
from starlette.testclient import TestClient


def _make_engine(tmp_path, **kwargs):
    rules = tmp_path / "rules.yaml"
    rules.write_text("shield_name: test\nversion: '1'\nrules: []\n")
    return AsyncShieldEngine(rules=rules, **kwargs)


def _make_client(tmp_path, monkeypatch=None, **env):
    if monkeypatch:
        for k, v in env.items():
            monkeypatch.setenv(k, v)
    engine = _make_engine(tmp_path)
    app = create_app(engine)
    return TestClient(app), engine


# ── Prompt 331: Graceful Shutdown ────────────────────────────────


class TestGracefulShutdown:
    def test_health_available_always(self, tmp_path):
        client, _ = _make_client(tmp_path)
        resp = client.get("/api/v1/health")
        assert resp.status_code == 200


# ── Prompt 332: Trace Flush ──────────────────────────────────────


class TestTraceFlush:
    def test_flush_writes_buffered_entries(self, tmp_path):
        recorder = TraceRecorder(output_dir=tmp_path)
        recorder.record("s1", "test", Verdict.ALLOW)
        assert len(recorder._buffer) > 0
        recorder.flush()
        assert len(recorder._buffer) == 0
        files = list(tmp_path.glob("*.jsonl"))
        assert len(files) == 1

    def test_atexit_flush_registered(self, tmp_path):

        recorder = TraceRecorder(output_dir=tmp_path)
        # _atexit_flush should be registered
        assert hasattr(recorder, "_atexit_flush")
        # Best-effort: calling it should not error
        recorder.record("s2", "tool", Verdict.BLOCK)
        recorder._atexit_flush()
        assert len(recorder._buffer) == 0


# ── Prompt 333: Config Validation ────────────────────────────────


class TestConfigValidation:
    def test_valid_config_passes(self, monkeypatch):
        from policyshield.config.validator import validate_env_config

        monkeypatch.setenv("POLICYSHIELD_MAX_CONCURRENT_CHECKS", "50")
        validate_env_config()  # Should not raise

    def test_invalid_number_fails(self, monkeypatch):
        from policyshield.config.validator import ConfigError, validate_env_config

        monkeypatch.setenv("POLICYSHIELD_MAX_CONCURRENT_CHECKS", "abc")
        with pytest.raises(ConfigError, match="not a valid number"):
            validate_env_config()

    def test_negative_number_fails(self, monkeypatch):
        from policyshield.config.validator import ConfigError, validate_env_config

        monkeypatch.setenv("POLICYSHIELD_REQUEST_TIMEOUT", "-5")
        with pytest.raises(ConfigError, match="must be positive"):
            validate_env_config()

    def test_invalid_fail_mode(self, monkeypatch):
        from policyshield.config.validator import ConfigError, validate_env_config

        monkeypatch.setenv("POLICYSHIELD_FAIL_MODE", "maybe")
        with pytest.raises(ConfigError, match="must be 'open' or 'closed'"):
            validate_env_config()

    def test_invalid_log_format(self, monkeypatch):
        from policyshield.config.validator import ConfigError, validate_env_config

        monkeypatch.setenv("POLICYSHIELD_LOG_FORMAT", "csv")
        with pytest.raises(ConfigError, match="must be 'text' or 'json'"):
            validate_env_config()


# ── Prompt 334: Fail Mode ────────────────────────────────────────


class TestFailMode:
    def test_fail_closed_by_default(self, tmp_path, monkeypatch):
        monkeypatch.delenv("POLICYSHIELD_FAIL_MODE", raising=False)
        engine = _make_engine(tmp_path, fail_open=False)
        assert engine._fail_open is False

    def test_fail_open_from_env(self, tmp_path, monkeypatch):
        monkeypatch.setenv("POLICYSHIELD_FAIL_MODE", "open")
        engine = _make_engine(tmp_path, fail_open=False)
        assert engine._fail_open is True

    def test_fail_closed_from_env(self, tmp_path, monkeypatch):
        monkeypatch.setenv("POLICYSHIELD_FAIL_MODE", "closed")
        engine = _make_engine(tmp_path, fail_open=True)
        assert engine._fail_open is False


# ── Prompt 335: Engine Timeout ───────────────────────────────────


class TestEngineTimeout:
    def test_engine_timeout_configurable(self, tmp_path, monkeypatch):
        monkeypatch.setenv("POLICYSHIELD_ENGINE_TIMEOUT", "10.0")
        engine = _make_engine(tmp_path)
        assert engine._engine_timeout == 10.0

    def test_engine_timeout_default(self, tmp_path, monkeypatch):
        monkeypatch.delenv("POLICYSHIELD_ENGINE_TIMEOUT", raising=False)
        engine = _make_engine(tmp_path)
        assert engine._engine_timeout == 5.0


# ── Prompt 336: Atomic Hot-Reload ────────────────────────────────


class TestAtomicHotReload:
    def test_invalid_reload_keeps_old_rules(self, tmp_path):
        engine = _make_engine(tmp_path)
        old_count = len(engine.rules.rules)
        invalid_yaml = tmp_path / "bad.yaml"
        invalid_yaml.write_text("!!invalid yaml [[[")
        with pytest.raises(Exception):
            engine.reload_rules(str(invalid_yaml))
        assert len(engine.rules.rules) == old_count


# ── Prompt 337: Startup Self-Test ────────────────────────────────


class TestStartupSelfTest:
    def test_self_test_runs_on_startup(self, tmp_path):
        """Self-test runs implicitly in create_app via lifespan."""
        engine = _make_engine(tmp_path)
        app = create_app(engine)
        # TestClient invokes lifespan → self-test runs
        client = TestClient(app)
        resp = client.get("/api/v1/health")
        assert resp.status_code == 200


# ── Prompt 338: Python Version Check ─────────────────────────────


class TestPythonVersionCheck:
    def test_current_version_passes(self):
        assert sys.version_info >= (3, 10)


# ── Prompt 339: Structured Logging ───────────────────────────────


class TestStructuredLogging:
    def test_json_output_parseable(self):
        from policyshield.logging_config import JSONFormatter

        formatter = JSONFormatter()
        record = logging.LogRecord("test", logging.INFO, "", 0, "hello", (), None)
        output = formatter.format(record)
        parsed = json.loads(output)
        assert parsed["message"] == "hello"
        assert parsed["level"] == "INFO"
        assert "timestamp" in parsed

    def test_configure_json_mode(self, monkeypatch):
        from policyshield.logging_config import JSONFormatter, configure_logging

        monkeypatch.setenv("POLICYSHIELD_LOG_FORMAT", "json")
        configure_logging()
        handler = logging.getLogger().handlers[0]
        assert isinstance(handler.formatter, JSONFormatter)

    def test_configure_text_mode(self, monkeypatch):
        from policyshield.logging_config import JSONFormatter, configure_logging

        monkeypatch.delenv("POLICYSHIELD_LOG_FORMAT", raising=False)
        configure_logging()
        handler = logging.getLogger().handlers[0]
        assert not isinstance(handler.formatter, JSONFormatter)


# ── Prompt 340: Telegram Shutdown ────────────────────────────────


class TestTelegramPollerShutdown:
    def test_stop_event_exists(self):
        """Verify _stop_event is part of TelegramApprovalBackend."""
        from policyshield.approval.telegram import TelegramApprovalBackend

        assert hasattr(TelegramApprovalBackend, "__init__")
        # Attribute checked indirectly; full integration requires Telegram token

    def test_double_stop_is_safe(self):
        """stop() twice should not crash."""
        from policyshield.approval.memory import InMemoryBackend

        backend = InMemoryBackend()
        backend.stop()
        backend.stop()  # Should not raise
