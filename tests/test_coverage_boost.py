"""Targeted tests to close the 84.47% → 85% coverage gap.

Focuses on async_engine.py and decorators.py — the two largest gaps.
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from policyshield.core.models import PostCheckResult, ShieldMode, ShieldResult, Verdict
from policyshield.decorators import _bind_args, _rebuild_args, guard, shield


# ─── decorators.py ────────────────────────────────────────────────


class TestShieldDecoratorSync:
    """Cover sync_wrapper paths in shield()."""

    def _make_engine(self, verdict=Verdict.ALLOW, message="ok", modified_args=None):
        result = ShieldResult(verdict=verdict, message=message, modified_args=modified_args)
        engine = MagicMock()
        engine.check = MagicMock(return_value=result)
        return engine

    def test_allow(self):
        engine = self._make_engine()

        @shield(engine)
        def my_tool(x: int) -> int:
            return x * 2

        assert my_tool(5) == 10

    def test_block_raise(self):
        engine = self._make_engine(verdict=Verdict.BLOCK, message="no")

        @shield(engine, on_block="raise")
        def my_tool(x: int) -> int:
            return x

        with pytest.raises(PermissionError, match="PolicyShield blocked"):
            my_tool(5)

    def test_block_return_none(self):
        engine = self._make_engine(verdict=Verdict.BLOCK, message="no")

        @shield(engine, on_block="return_none")
        def my_tool(x: int) -> int:
            return x

        assert my_tool(5) is None

    def test_approve_raise(self):
        engine = self._make_engine(verdict=Verdict.APPROVE, message="approval needed")

        @shield(engine, on_block="raise")
        def my_tool(x: int) -> int:
            return x

        with pytest.raises(PermissionError, match="requires approval"):
            my_tool(5)

    def test_approve_return_none(self):
        engine = self._make_engine(verdict=Verdict.APPROVE, message="approval needed")

        @shield(engine, on_block="return_none")
        def my_tool(x: int) -> int:
            return x

        assert my_tool(5) is None

    def test_redact_modified_args(self):
        engine = self._make_engine(
            verdict=Verdict.REDACT,
            modified_args={"x": 99},
        )

        @shield(engine)
        def my_tool(x: int) -> int:
            return x

        assert my_tool(5) == 99

    def test_custom_tool_name(self):
        engine = self._make_engine()

        @shield(engine, tool_name="custom_name")
        def my_tool(x: int) -> int:
            return x

        my_tool(5)
        engine.check.assert_called_once()
        call_args = engine.check.call_args
        assert call_args[0][0] == "custom_name"


class TestShieldDecoratorAsync:
    """Cover async_wrapper paths in shield()."""

    def _make_engine(self, verdict=Verdict.ALLOW, message="ok", modified_args=None):
        result = ShieldResult(verdict=verdict, message=message, modified_args=modified_args)
        engine = MagicMock()
        engine.check = AsyncMock(return_value=result)
        return engine

    @pytest.mark.asyncio
    async def test_allow(self):
        engine = self._make_engine()

        @shield(engine)
        async def my_tool(x: int) -> int:
            return x * 2

        assert await my_tool(5) == 10

    @pytest.mark.asyncio
    async def test_block_raise(self):
        engine = self._make_engine(verdict=Verdict.BLOCK, message="no")

        @shield(engine, on_block="raise")
        async def my_tool(x: int) -> int:
            return x

        with pytest.raises(PermissionError, match="PolicyShield blocked"):
            await my_tool(5)

    @pytest.mark.asyncio
    async def test_block_return_none(self):
        engine = self._make_engine(verdict=Verdict.BLOCK, message="no")

        @shield(engine, on_block="return_none")
        async def my_tool(x: int) -> int:
            return x

        assert await my_tool(5) is None

    @pytest.mark.asyncio
    async def test_approve_raise(self):
        engine = self._make_engine(verdict=Verdict.APPROVE, message="need approval")

        @shield(engine, on_block="raise")
        async def my_tool(x: int) -> int:
            return x

        with pytest.raises(PermissionError, match="requires approval"):
            await my_tool(5)

    @pytest.mark.asyncio
    async def test_approve_return_none(self):
        engine = self._make_engine(verdict=Verdict.APPROVE, message="need approval")

        @shield(engine, on_block="return_none")
        async def my_tool(x: int) -> int:
            return x

        assert await my_tool(5) is None

    @pytest.mark.asyncio
    async def test_redact_modified_args(self):
        engine = self._make_engine(
            verdict=Verdict.REDACT,
            modified_args={"x": 42},
        )

        @shield(engine)
        async def my_tool(x: int) -> int:
            return x

        assert await my_tool(5) == 42


class TestBindAndRebuildArgs:
    """Cover _bind_args and _rebuild_args."""

    def test_bind_args_mixed(self):
        def fn(a: int, b: str, c: float = 3.0):
            pass

        result = _bind_args(fn, (1, "hello"), {"c": 5.0})
        assert result == {"a": 1, "b": "hello", "c": 5.0}

    def test_bind_args_defaults(self):
        def fn(a: int, b: str = "default"):
            pass

        result = _bind_args(fn, (1,), {})
        assert result == {"a": 1, "b": "default"}

    def test_bind_args_fallback(self):
        """Tests fallback when signature cannot be inspected."""
        # Use a callable that raises ValueError on signature inspection
        import operator
        result = _bind_args(operator.add, (), {"end": "!"})
        assert result == {"end": "!"}

    def test_rebuild_args_positional(self):
        def fn(a: int, b: str):
            pass

        new_args, new_kwargs = _rebuild_args(fn, {"a": 99}, (1, "hello"), {})
        assert new_args == (99, "hello")
        assert new_kwargs == {}

    def test_rebuild_args_keyword(self):
        def fn(a: int, b: str = "default"):
            pass

        new_args, new_kwargs = _rebuild_args(fn, {"b": "modified"}, (1,), {})
        assert new_args == (1,)
        assert new_kwargs == {"b": "modified"}

    def test_rebuild_args_unknown_key(self):
        def fn(a: int):
            pass

        new_args, new_kwargs = _rebuild_args(fn, {"unknown": "val"}, (1,), {})
        assert new_args == (1,)
        assert new_kwargs == {"unknown": "val"}

    def test_rebuild_args_fallback(self):
        """Fallback when signature cannot be inspected."""
        new_args, new_kwargs = _rebuild_args(print, {"x": 1}, (1,), {"y": 2})
        assert new_args == (1,)
        assert new_kwargs == {"y": 2, "x": 1}


class TestGuardLegacy:
    """Cover the guard() backward-compatible function."""

    def test_guard_with_engine(self):
        result = ShieldResult(verdict=Verdict.ALLOW, message="ok")
        engine = MagicMock()
        engine.check = MagicMock(return_value=result)

        @guard("my_tool", engine=engine)
        def my_tool(x: int) -> int:
            return x

        assert my_tool(5) == 5
        engine.check.assert_called_once()

    def test_guard_block(self):
        result = ShieldResult(verdict=Verdict.BLOCK, message="blocked")
        engine = MagicMock()
        engine.check = MagicMock(return_value=result)

        @guard("my_tool", engine=engine, on_block="return_none")
        def my_tool(x: int) -> int:
            return x

        assert my_tool(5) is None


# ─── async_engine.py ──────────────────────────────────────────────


class TestAsyncEngineExtended:
    """Cover uncovered paths in AsyncShieldEngine."""

    @pytest.fixture()
    def engine(self, tmp_path):
        rules_file = tmp_path / "rules.yaml"
        rules_file.write_text(
            "rules:\n"
            "  - id: block-exec\n"
            "    when:\n"
            "      tool: exec\n"
            "    then: block\n"
            "    severity: high\n"
            "    message: exec blocked\n"
        )
        from policyshield.shield.async_engine import AsyncShieldEngine

        return AsyncShieldEngine(rules=str(rules_file))

    @pytest.mark.asyncio
    async def test_disabled_mode(self, engine):
        engine._mode = ShieldMode.DISABLED
        result = await engine.check("exec", {"cmd": "rm -rf /"})
        assert result.verdict == Verdict.ALLOW

    @pytest.mark.asyncio
    async def test_kill_switch_blocks(self, engine):
        engine._killed.set()
        engine._kill_reason = "Emergency"
        result = await engine.check("exec", {"cmd": "ls"})
        assert result.verdict == Verdict.BLOCK
        assert "Kill switch" in result.message or "Emergency" in result.message

    @pytest.mark.asyncio
    async def test_basic_block(self, engine):
        result = await engine.check("exec", {"cmd": "ls"})
        assert result.verdict == Verdict.BLOCK
        assert "exec blocked" in (result.message or "")

    @pytest.mark.asyncio
    async def test_allow_no_match(self, engine):
        result = await engine.check("read_file", {"path": "/tmp/test"})
        assert result.verdict == Verdict.ALLOW

    @pytest.mark.asyncio
    async def test_timeout_fail_open(self, engine):
        """Cover the asyncio.TimeoutError path (lines 70-77)."""
        engine._engine_timeout = 0.001
        engine._fail_open = True

        # Make _do_check take longer than timeout
        original = engine._do_check

        async def slow_check(*args, **kwargs):
            await asyncio.sleep(1)
            return await original(*args, **kwargs)

        engine._do_check = slow_check
        result = await engine.check("exec", {"cmd": "ls"})
        assert result.verdict == Verdict.ALLOW
        assert "timed out" in (result.message or "").lower()

    @pytest.mark.asyncio
    async def test_timeout_fail_closed(self, engine):
        """Cover timeout path with fail_open=False (line 76)."""
        engine._engine_timeout = 0.001
        engine._fail_open = False

        async def slow_check(*args, **kwargs):
            await asyncio.sleep(1)
            return ShieldResult(verdict=Verdict.ALLOW, message="ok")

        engine._do_check = slow_check
        result = await engine.check("exec", {"cmd": "ls"})
        assert result.verdict == Verdict.BLOCK

    @pytest.mark.asyncio
    async def test_exception_fail_open(self, engine):
        """Cover the Exception path with fail_open=True (lines 78-81)."""
        engine._fail_open = True

        async def failing_check(*args, **kwargs):
            raise RuntimeError("test error")

        engine._do_check = failing_check
        result = await engine.check("exec", {"cmd": "ls"})
        assert result.verdict == Verdict.ALLOW

    @pytest.mark.asyncio
    async def test_exception_fail_closed(self, engine):
        """Cover the Exception path with fail_open=False (lines 82-83)."""
        engine._fail_open = False

        async def failing_check(*args, **kwargs):
            raise RuntimeError("test error")

        engine._do_check = failing_check
        with pytest.raises(Exception, match="Shield check failed"):
            await engine.check("exec", {"cmd": "ls"})

    @pytest.mark.asyncio
    async def test_redact_verdict(self, tmp_path):
        """Cover the REDACT path (lines 245-256)."""
        rules_file = tmp_path / "rules.yaml"
        rules_file.write_text(
            "rules:\n"
            "  - id: redact-email\n"
            "    when:\n"
            "      tool: send_email\n"
            "    then: redact\n"
            "    severity: medium\n"
            "    message: redacted\n"
        )
        from policyshield.shield.async_engine import AsyncShieldEngine

        eng = AsyncShieldEngine(rules=str(rules_file))
        result = await eng.check("send_email", {"body": "My SSN is 123-45-6789"})
        assert result.verdict == Verdict.REDACT

    @pytest.mark.asyncio
    async def test_post_check(self, engine):
        """Cover the post_check method (line 382)."""
        result = await engine.post_check("exec", "some output", session_id="test")
        assert isinstance(result, PostCheckResult)

    @pytest.mark.asyncio
    async def test_sanitizer_rejection(self, engine):
        """Cover the sanitizer path (lines 124-132)."""
        mock_result = SimpleNamespace(rejected=True, rejection_reason="Dangerous input", sanitized_args={})
        engine._sanitizer = MagicMock()
        engine._sanitizer.sanitize = MagicMock(return_value=mock_result)
        result = await engine.check("read_file", {"path": "/etc/passwd"})
        assert result.verdict == Verdict.BLOCK
        assert "Dangerous" in (result.message or "")

    @pytest.mark.asyncio
    async def test_rate_limiter_block(self, engine):
        """Cover the rate limiter path (lines 152-159)."""
        mock_rl_result = SimpleNamespace(allowed=False, message="Rate limited")
        engine._rate_limiter = MagicMock()
        engine._rate_limiter.check_and_record = MagicMock(return_value=mock_rl_result)
        result = await engine.check("read_file", {"path": "/tmp/test"})
        assert result.verdict == Verdict.BLOCK
        assert "Rate limited" in (result.message or "")

    @pytest.mark.asyncio
    async def test_matcher_error_fail_open(self, engine):
        """Cover matcher exception path (lines 192-196)."""
        engine._fail_open = True
        engine._matcher = MagicMock()
        engine._matcher.find_best_match = MagicMock(side_effect=RuntimeError("match error"))
        result = await engine.check("read_file", {"path": "/tmp/test"})
        assert result.verdict == Verdict.ALLOW

    @pytest.mark.asyncio
    async def test_matcher_error_fail_closed(self, engine):
        """Cover matcher exception path (lines 196-200)."""
        engine._fail_open = False
        engine._matcher = MagicMock()
        engine._matcher.find_best_match = MagicMock(side_effect=RuntimeError("match error"))
        result = await engine.check("read_file", {"path": "/tmp/test"})
        assert result.verdict == Verdict.BLOCK
        assert "Internal error" in (result.message or "")
