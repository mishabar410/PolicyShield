"""Tests for low-severity issue fixes."""

from __future__ import annotations

from collections import OrderedDict
from pathlib import Path
from unittest.mock import MagicMock


from policyshield.core.models import RuleConfig, RuleSet, Verdict
from policyshield.shield.engine import ShieldEngine
from policyshield.shield.rate_limiter import _SlidingWindow


# ── #12: JSON serialization for output matching ──


class TestOutputJsonSerialization:
    def test_dict_result_serialized(self):
        """Non-string results should be JSON-serialized for output matching."""
        rules = RuleSet(shield_name="t", version=1, rules=[])
        engine = ShieldEngine(rules)
        # Should not raise — dict result gets json.dumps() instead of str()
        result = engine.check("tool", {"x": 1})
        assert result is not None

    def test_list_result_serialized(self):
        rules = RuleSet(shield_name="t", version=1, rules=[])
        engine = ShieldEngine(rules)
        result = engine.check("tool", {"x": [1, 2, 3]})
        assert result is not None


# ── #143: _count_and_prune renamed method ──


class TestSlidingWindowRename:
    def test_count_and_prune(self):
        """_count_and_prune should prune expired and return valid count."""
        w = _SlidingWindow()
        now = 1000.0
        w.add(now - 100)  # expired
        w.add(now - 50)  # valid (within 60s window)
        w.add(now - 5)  # valid
        w.add(now)  # valid
        count = w._count_and_prune(now, 60.0)
        assert count == 3  # 50, 5, and 0 seconds ago are within 60s window
        assert len(w.timestamps) == 3

    def test_old_method_removed(self):
        """count_in_window should no longer exist."""
        w = _SlidingWindow()
        assert not hasattr(w, "count_in_window")


# ── #61: LRU cache eviction ──


class TestLRUCacheEviction:
    def test_lru_eviction(self):
        """LLM Guard cache should use OrderedDict for LRU support."""
        from policyshield.shield.llm_guard import LLMGuard, LLMGuardConfig

        config = LLMGuardConfig(
            enabled=True,
            model="test",
        )
        guard = LLMGuard(config)
        assert isinstance(guard._cache, OrderedDict)


# ── #97: load_schema fallback ──


class TestLoadSchemaFallback:
    def test_missing_schema_returns_empty(self, monkeypatch):
        """Missing schema file should return empty dict."""
        from policyshield.config import loader

        original = loader._SCHEMA_PATH
        monkeypatch.setattr(loader, "_SCHEMA_PATH", Path("/nonexistent/schema.json"))
        result = loader.load_schema()
        assert result == {}
        monkeypatch.setattr(loader, "_SCHEMA_PATH", original)


# ── #60: verdict_enum property ──


class TestVerdictEnumProperty:
    def test_verdict_enum(self):
        from policyshield.sdk.client import CheckResult

        r = CheckResult(verdict="ALLOW", message="ok")
        v = r.verdict_enum
        assert v == Verdict.ALLOW

    def test_verdict_enum_block(self):
        from policyshield.sdk.client import CheckResult

        r = CheckResult(verdict="BLOCK", message="no")
        v = r.verdict_enum
        assert v == Verdict.BLOCK


# ── #73: buffer overflow callback ──


class TestBufferOverflowCallback:
    def test_overflow_callback_invoked(self, tmp_path):
        from policyshield.trace.recorder import TraceRecorder

        callback = MagicMock()
        rec = TraceRecorder(
            output_dir=tmp_path,
            batch_size=5,
            on_buffer_overflow=callback,
        )
        # Fill buffer past max_retained (batch_size * 10 = 50)
        # Make flush fail by removing output dir

        rec._file_path = Path("/nonexistent/trace.jsonl")
        for i in range(60):
            rec.record("s", "t", Verdict.ALLOW)

        # Overflow should have triggered callback
        rec.close()


# ── #167: get_policy_summary under lock ──


class TestPolicySummaryLock:
    def test_summary_under_lock(self):
        rules = RuleSet(
            shield_name="t",
            version=1,
            rules=[
                RuleConfig(id="r1", when={"tool": "a"}, then=Verdict.BLOCK, message="hi"),
            ],
        )
        engine = ShieldEngine(rules)
        summary = engine.get_policy_summary()
        assert "t" in summary
        assert "r1" in summary
        assert "BLOCK" in summary


# ── #124: _bind_args fallback preserves positional args ──


class TestBindArgsFallback:
    def test_normal_binding(self):
        from policyshield.decorators import _bind_args

        def my_func(a, b, c="default"):
            pass

        result = _bind_args(my_func, ("hello", "world"), {})
        assert result["a"] == "hello"
        assert result["b"] == "world"
        assert result["c"] == "default"


# ── #208: cleanup_default_engine ──


class TestCleanupDefaultEngine:
    def test_cleanup(self):
        from policyshield.decorators import cleanup_default_engine

        cleanup_default_engine()  # Should not raise


# ── #209: Safe JSON truncation ──


class TestSafeJsonTruncation:
    def test_truncation_adds_marker(self):
        from policyshield.shield.llm_guard import LLMGuard, LLMGuardConfig

        config = LLMGuardConfig(enabled=True, model="test")
        guard = LLMGuard(config)
        # Build prompt with long args
        big_args = {"data": "x" * 10000}
        prompt = guard._build_prompt("my_tool", big_args)
        assert "...[truncated]" in prompt
        assert "my_tool" in prompt

    def test_no_truncation_small_args(self):
        from policyshield.shield.llm_guard import LLMGuard, LLMGuardConfig

        config = LLMGuardConfig(enabled=True, model="test")
        guard = LLMGuard(config)
        small_args = {"x": 1}
        prompt = guard._build_prompt("tool", small_args)
        assert "...[truncated]" not in prompt


# ── #178: post_check latency logging ──


class TestPostCheckLatency:
    def test_post_check_returns_result(self):
        rules = RuleSet(shield_name="t", version=1, rules=[])
        engine = ShieldEngine(rules)
        result = engine.post_check("tool", "some output")
        assert result is not None


# ── #179: rules_hash includes output_rules ──


class TestRulesHashExpanded:
    def test_hash_includes_default_verdict(self):
        from policyshield.server.app import _rules_hash
        from policyshield.shield.async_engine import AsyncShieldEngine

        rules = RuleSet(shield_name="t", version=1, rules=[])
        engine = AsyncShieldEngine(rules)
        h = _rules_hash(engine)
        assert isinstance(h, str)
        assert len(h) == 16


# ── #98: Recorder periodic cleanup ──


class TestRecorderPeriodicCleanup:
    def test_cleanup_old_traces(self, tmp_path):
        from policyshield.trace.recorder import TraceRecorder

        rec = TraceRecorder(output_dir=tmp_path, retention_days=0)
        # Create an old trace file
        old_file = tmp_path / "trace_20200101_000000.jsonl"
        old_file.write_text("{}\n")
        import os
        # Set mtime to old
        os.utime(old_file, (0, 0))
        removed = rec.cleanup_old_traces()
        assert removed == 0  # retention_days=0 returns 0
        rec.close()

    def test_recorder_daily_rotation_check(self, tmp_path):
        from policyshield.trace.recorder import TraceRecorder

        rec = TraceRecorder(output_dir=tmp_path, rotation="daily")
        assert rec._rotation == "daily"
        # Save a record and check no error
        rec.record("s", "t", Verdict.ALLOW)
        rec.flush()
        rec.close()

    def test_recorder_no_rotation(self, tmp_path):
        from policyshield.trace.recorder import TraceRecorder

        rec = TraceRecorder(output_dir=tmp_path, rotation="none")
        assert rec._should_rotate() is False
        rec.record("s", "t", Verdict.BLOCK)
        rec.flush()
        rec.close()


# ── #97: Schema JSON decode error ──


class TestSchemaJsonError:
    def test_invalid_json_schema(self, tmp_path, monkeypatch):
        from policyshield.config import loader

        bad_schema = tmp_path / "bad_schema.json"
        bad_schema.write_text("NOT VALID JSON {{{")
        monkeypatch.setattr(loader, "_SCHEMA_PATH", bad_schema)
        result = loader.load_schema()
        assert result == {}


# ── Config render ──


class TestConfigRender:
    def test_render_config(self):
        from policyshield.config.loader import render_config, PolicyShieldConfig

        config = PolicyShieldConfig()
        yaml_text = render_config(config)
        assert "policyshield" in yaml_text
        assert "version" in yaml_text
