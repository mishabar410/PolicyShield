"""Targeted tests to boost coverage past 85% threshold."""

from __future__ import annotations

import textwrap
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from policyshield.approval.sanitizer import sanitize_args
from policyshield.config.loader import (
    PolicyShieldConfig,
    _build_config,
    _expand_env,
    build_async_engine_from_config,
    build_engine_from_config,
    load_config,
    render_config,
    validate_config_file,
)
from policyshield.core.models import ShieldMode, Verdict
from policyshield.trace.recorder import TraceRecorder, _stable_default, compute_args_hash


# ── Sanitizer coverage (lines 24, 26, 32) ─────────────────────────


class TestSanitizerCoverage:
    def test_nested_dict_sanitized(self):
        """Cover recursive dict branch (line 24)."""
        # Use a value that matches the catch-all pattern (40+ alphanumeric chars)
        long_token = "A" * 50
        result = sanitize_args({"outer": {"key": long_token}})
        assert long_token not in str(result["outer"])

    def test_list_sanitized(self):
        """Cover list/tuple branch (line 26)."""
        long_token = "B" * 50
        result = sanitize_args({"items": [long_token, "safe"]})
        assert long_token not in str(result["items"])

    def test_truncation_after_no_secret(self):
        """Cover truncation when no secret pattern matches (line 32)."""
        # Use chars that don't match any secret pattern but exceed 200 chars
        long_text = "Hello world! " * 20  # 260 chars, no secret pattern match
        result = sanitize_args({"text": long_text})
        assert len(str(result["text"])) <= 220  # truncated


# ── TraceRecorder coverage (lines 21-27, 97-98, 114-115, 211-213) ──


class TestRecorderCoverage:
    def test_stable_default_datetime(self):
        """Cover _stable_default datetime branch (line 22)."""
        dt = datetime(2025, 1, 1, tzinfo=timezone.utc)
        assert "2025" in _stable_default(dt)

    def test_stable_default_set(self):
        """Cover _stable_default set branch (line 24)."""
        result = _stable_default({3, 1, 2})
        assert result == [1, 2, 3]

    def test_stable_default_object(self):
        """Cover _stable_default __dict__ branch (line 26)."""

        class Obj:
            def __init__(self):
                self.a = 1

        result = _stable_default(Obj())
        assert result == {"a": 1}

    def test_stable_default_fallback(self):
        """Cover _stable_default repr fallback (line 27)."""
        result = _stable_default(42)
        assert result == "42"

    def test_context_manager(self, tmp_path):
        """Cover __enter__/__exit__ and close (lines 97-98, 103-107)."""
        with TraceRecorder(output_dir=tmp_path) as rec:
            rec.record("s1", "tool", Verdict.ALLOW)
        # After exit, _closed should be True
        assert rec._closed is True

    def test_close_idempotent(self, tmp_path):
        """Calling close twice should not error."""
        rec = TraceRecorder(output_dir=tmp_path)
        rec.record("s1", "tool", Verdict.ALLOW)
        rec.close()
        rec.close()  # Second close should be no-op
        assert rec._closed is True

    def test_atexit_flush_when_not_closed(self, tmp_path):
        """Cover _atexit_flush (lines 111-115)."""
        rec = TraceRecorder(output_dir=tmp_path)
        rec.record("s1", "tool", Verdict.BLOCK)
        rec._atexit_flush()
        files = list(tmp_path.glob("*.jsonl"))
        assert len(files) == 1

    def test_compute_args_hash(self):
        """Cover compute_args_hash function."""
        h1 = compute_args_hash({"key": "value"})
        h2 = compute_args_hash({"key": "value"})
        h3 = compute_args_hash({"key": "other"})
        assert h1 == h2
        assert h1 != h3


# ── Config loader coverage (lines 97-99, 308-310, 318-320, etc.) ──


_RULES_YAML = textwrap.dedent("""\
    shield_name: test
    version: 1
    rules:
      - id: r1
        when:
          tool: test_tool
        then: ALLOW
""")


class TestConfigCoverage:
    def test_expand_env_with_default(self, monkeypatch):
        """Cover _expand_env default branch (line 98)."""
        monkeypatch.delenv("NONEXISTENT_VAR", raising=False)
        result = _expand_env("${NONEXISTENT_VAR:-fallback}")
        assert result == "fallback"

    def test_expand_env_not_found_no_default(self, monkeypatch):
        """Cover _expand_env keep-original branch (line 99)."""
        monkeypatch.delenv("NONEXISTENT_VAR", raising=False)
        result = _expand_env("${NONEXISTENT_VAR}")
        assert result == "${NONEXISTENT_VAR}"

    def test_build_config_with_rules_string(self):
        """Cover rules-as-string branch (line 174)."""
        cfg = _build_config({"rules": "/path/to/rules"})
        assert cfg.rules_path == "/path/to/rules"

    def test_load_config_file_not_found(self, tmp_path):
        """Cover FileNotFoundError branch (line 138)."""
        with pytest.raises(FileNotFoundError):
            load_config(path=tmp_path / "nonexistent.yaml")

    def test_validate_config_invalid_yaml(self, tmp_path):
        """Cover invalid YAML branch in validate_config_file."""
        bad = tmp_path / "bad.yaml"
        bad.write_text(": :\n  bad: [unclosed", encoding="utf-8")
        errors = validate_config_file(bad)
        assert len(errors) > 0

    def test_validate_config_not_mapping(self, tmp_path):
        """Cover non-mapping root."""
        bad = tmp_path / "bad.yaml"
        bad.write_text("just a string", encoding="utf-8")
        errors = validate_config_file(bad)
        assert "mapping" in errors[0]

    def test_validate_config_invalid_mode(self, tmp_path):
        """Cover invalid mode validation."""
        bad = tmp_path / "config.yaml"
        bad.write_text("mode: BADMODE\nrules:\n  path: ./rules", encoding="utf-8")
        errors = validate_config_file(bad)
        assert any("mode" in e.lower() for e in errors)

    def test_validate_config_rules_path_not_string(self, tmp_path):
        """Cover rules.path type validation."""
        bad = tmp_path / "config.yaml"
        bad.write_text("rules:\n  path: 123", encoding="utf-8")
        errors = validate_config_file(bad)
        assert any("string" in e.lower() for e in errors)

    def test_render_config(self):
        """Cover render_config function."""
        cfg = PolicyShieldConfig()
        rendered = render_config(cfg)
        assert "mode" in rendered
        assert "ENFORCE" in rendered

    def test_build_engine_with_otel(self, tmp_path, monkeypatch):
        """Cover OTel builder branch (lines 308-310)."""
        monkeypatch.chdir(tmp_path)
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        (rules_dir / "rules.yaml").write_text(_RULES_YAML, encoding="utf-8")

        cfg = PolicyShieldConfig(
            rules_path=str(rules_dir),
            trace_enabled=False,
            otel_enabled=True,
            otel_service_name="test-svc",
            otel_endpoint="http://localhost:4317",
        )

        mock_otel_mod = MagicMock()
        with patch.dict("sys.modules", {"policyshield.trace.otel": mock_otel_mod}):
            engine = build_engine_from_config(cfg)
            assert engine is not None

    def test_build_engine_with_budget(self, tmp_path, monkeypatch):
        """Cover budget builder branch (lines 318-320)."""
        monkeypatch.chdir(tmp_path)
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        (rules_dir / "rules.yaml").write_text(_RULES_YAML, encoding="utf-8")

        cfg = PolicyShieldConfig(
            rules_path=str(rules_dir),
            trace_enabled=False,
            budget_enabled=True,
            budget_max_per_session=100,
            budget_max_per_hour=500,
        )
        engine = build_engine_from_config(cfg)
        assert engine is not None

    def test_build_async_engine_with_sanitizer(self, tmp_path, monkeypatch):
        """Cover async engine builder with sanitizer (lines 381-387)."""
        monkeypatch.chdir(tmp_path)
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        (rules_dir / "rules.yaml").write_text(_RULES_YAML, encoding="utf-8")

        cfg = PolicyShieldConfig(
            rules_path=str(rules_dir),
            trace_enabled=False,
            sanitizer_enabled=True,
            sanitizer_blocked_patterns=["<script>"],
        )
        engine = build_async_engine_from_config(cfg)
        assert engine._sanitizer is not None

    def test_build_async_engine_with_otel(self, tmp_path, monkeypatch):
        """Cover async OTel builder branch (lines 407-409)."""
        monkeypatch.chdir(tmp_path)
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        (rules_dir / "rules.yaml").write_text(_RULES_YAML, encoding="utf-8")

        cfg = PolicyShieldConfig(
            rules_path=str(rules_dir),
            trace_enabled=False,
            otel_enabled=True,
            otel_service_name="test-svc",
            otel_endpoint="http://localhost:4317",
        )

        mock_otel_mod = MagicMock()
        with patch.dict("sys.modules", {"policyshield.trace.otel": mock_otel_mod}):
            engine = build_async_engine_from_config(cfg)
            assert engine is not None

    def test_build_async_engine_with_budget(self, tmp_path, monkeypatch):
        """Cover async budget builder branch (lines 417-419)."""
        monkeypatch.chdir(tmp_path)
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        (rules_dir / "rules.yaml").write_text(_RULES_YAML, encoding="utf-8")

        cfg = PolicyShieldConfig(
            rules_path=str(rules_dir),
            trace_enabled=False,
            budget_enabled=True,
            budget_max_per_session=100,
            budget_max_per_hour=500,
        )
        engine = build_async_engine_from_config(cfg)
        assert engine is not None

    def test_build_config_invalid_watch_interval(self):
        """Cover watch_interval validation (line 194)."""
        with pytest.raises(ValueError, match="watch_interval"):
            _build_config({"rules": {"watch_interval": -1}})

    def test_build_config_invalid_batch_size(self):
        """Cover batch_size validation (line 198)."""
        with pytest.raises(ValueError, match="batch_size"):
            _build_config({"trace": {"batch_size": 0}})

    def test_build_config_invalid_max_string_length(self):
        """Cover max_string_length validation (line 202)."""
        with pytest.raises(ValueError, match="max_string_length"):
            _build_config({"sanitizer": {"max_string_length": 0}})

    def test_load_config_env_mode_override(self, monkeypatch):
        """Cover env mode override (lines 148-149)."""
        monkeypatch.delenv("POLICYSHIELD_CONFIG", raising=False)
        monkeypatch.setenv("POLICYSHIELD_MODE", "AUDIT")
        cfg = load_config()
        assert cfg.mode == ShieldMode.AUDIT

    def test_load_config_env_fail_open_override(self, monkeypatch):
        """Cover env fail_open override (lines 152-153)."""
        monkeypatch.delenv("POLICYSHIELD_CONFIG", raising=False)
        monkeypatch.setenv("POLICYSHIELD_FAIL_OPEN", "true")
        cfg = load_config()
        assert cfg.fail_open is True
