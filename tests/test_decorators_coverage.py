"""Tests for shield/guard decorators to boost coverage."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from policyshield.core.exceptions import ApprovalRequiredError
from policyshield.core.models import Verdict
from policyshield.decorators import _bind_args, _rebuild_args, cleanup_default_engine, shield


class TestSyncShieldDecorator:
    def test_allow(self):
        engine = MagicMock()
        result = MagicMock(verdict=Verdict.ALLOW, modified_args=None, message="")
        engine.check.return_value = result

        @shield(engine)
        def my_tool(x: int) -> int:
            return x * 2

        assert my_tool(5) == 10
        engine.check.assert_called_once()

    def test_block_raises(self):
        engine = MagicMock()
        result = MagicMock(verdict=Verdict.BLOCK, message="blocked!")
        engine.check.return_value = result

        @shield(engine, on_block="raise")
        def my_tool(x: int) -> int:
            return x * 2

        with pytest.raises(PermissionError, match="blocked"):
            my_tool(5)

    def test_block_return_none(self):
        engine = MagicMock()
        result = MagicMock(verdict=Verdict.BLOCK, message="blocked")
        engine.check.return_value = result

        @shield(engine, on_block="return_none")
        def my_tool(x: int) -> int:
            return x * 2

        assert my_tool(5) is None

    def test_approve_raises(self):
        engine = MagicMock()
        result = MagicMock(verdict=Verdict.APPROVE, message="needs approval", approval_id="a1")
        engine.check.return_value = result

        @shield(engine, on_block="raise")
        def my_tool(x: int) -> int:
            return x * 2

        with pytest.raises(ApprovalRequiredError):
            my_tool(5)

    def test_approve_return_dict(self):
        engine = MagicMock()
        result = MagicMock(verdict=Verdict.APPROVE, message="needs approval", approval_id="a1")
        engine.check.return_value = result

        @shield(engine, on_block="return_none")
        def my_tool(x: int) -> int:
            return x * 2

        out = my_tool(5)
        assert isinstance(out, dict)
        assert out["approval_required"] is True

    def test_modified_args(self):
        engine = MagicMock()
        result = MagicMock(verdict=Verdict.ALLOW, modified_args={"x": 99}, message="")
        engine.check.return_value = result

        @shield(engine)
        def my_tool(x: int) -> int:
            return x

        assert my_tool(5) == 99

    def test_post_check(self):
        engine = MagicMock()
        result = MagicMock(verdict=Verdict.ALLOW, modified_args=None, message="")
        engine.check.return_value = result
        engine.post_check.return_value = None

        @shield(engine)
        def my_tool() -> str:
            return "output"

        assert my_tool() == "output"
        engine.post_check.assert_called_once()


class TestAsyncShieldDecorator:
    @pytest.mark.asyncio
    async def test_allow(self):
        engine = MagicMock()
        result = MagicMock(verdict=Verdict.ALLOW, modified_args=None, message="")
        engine.check = AsyncMock(return_value=result)

        @shield(engine)
        async def my_tool(x: int) -> int:
            return x * 2

        assert await my_tool(5) == 10

    @pytest.mark.asyncio
    async def test_block_raises(self):
        engine = MagicMock()
        result = MagicMock(verdict=Verdict.BLOCK, message="blocked!")
        engine.check = AsyncMock(return_value=result)

        @shield(engine)
        async def my_tool(x: int) -> int:
            return x * 2

        with pytest.raises(PermissionError):
            await my_tool(5)

    @pytest.mark.asyncio
    async def test_block_return_none(self):
        engine = MagicMock()
        result = MagicMock(verdict=Verdict.BLOCK, message="blocked")
        engine.check = AsyncMock(return_value=result)

        @shield(engine, on_block="return_none")
        async def my_tool(x: int) -> int:
            return x * 2

        assert await my_tool(5) is None

    @pytest.mark.asyncio
    async def test_approve(self):
        engine = MagicMock()
        result = MagicMock(verdict=Verdict.APPROVE, message="needs approval", approval_id="a1")
        engine.check = AsyncMock(return_value=result)

        @shield(engine, on_block="return_none")
        async def my_tool(x: int) -> int:
            return x * 2

        out = await my_tool(5)
        assert isinstance(out, dict)
        assert out["approval_required"] is True

    @pytest.mark.asyncio
    async def test_modified_args(self):
        engine = MagicMock()
        result = MagicMock(verdict=Verdict.ALLOW, modified_args={"x": 42}, message="")
        engine.check = AsyncMock(return_value=result)

        @shield(engine)
        async def my_tool(x: int) -> int:
            return x

        assert await my_tool(5) == 42

    @pytest.mark.asyncio
    async def test_post_check(self):
        engine = MagicMock()
        result = MagicMock(verdict=Verdict.ALLOW, modified_args=None, message="")
        engine.check = AsyncMock(return_value=result)
        engine.post_check = AsyncMock(return_value=None)

        @shield(engine)
        async def my_tool() -> str:
            return "output"

        assert await my_tool() == "output"


class TestBindArgs:
    def test_normal_binding(self):
        def f(a, b, c=3):
            pass

        result = _bind_args(f, (1, 2), {})
        assert result == {"a": 1, "b": 2, "c": 3}

    def test_variadic_binding(self):
        def f(*args, **kwargs):
            pass

        result = _bind_args(f, (1, 2), {"key": "val"})
        assert "args" in result or "key" in result


class TestRebuildArgs:
    def test_positional_update(self):
        def f(a, b):
            pass

        new_args, new_kwargs = _rebuild_args(f, {"a": 10}, (1, 2), {})
        assert new_args == (10, 2)

    def test_keyword_update(self):
        def f(a, b=5):
            pass

        new_args, new_kwargs = _rebuild_args(f, {"b": 99}, (1,), {})
        assert new_kwargs["b"] == 99


class TestCleanup:
    def test_cleanup_default_engine(self):
        cleanup_default_engine()
        # Should not raise
