"""Tests for the Telegram bot — PolicyBot."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from policyshield.ai.compiler import CompileResult
from policyshield.bot.telegram_bot import PolicyBot, run_bot


@pytest.fixture
def tmp_rules(tmp_path: Path) -> Path:
    """Create a temporary rules file."""
    rules = tmp_path / "rules.yaml"
    rules.write_text("rules: []\n")
    return rules


@pytest.fixture
def bot(tmp_rules: Path) -> PolicyBot:
    """Create a PolicyBot with a mock compiler and HTTP client."""
    compiler = MagicMock()
    b = PolicyBot(
        bot_token="test-token",
        rules_path=tmp_rules,
        server_url="http://localhost:8100",
        compiler=compiler,
        api_base="https://mock.telegram.api",
    )
    b._client = AsyncMock()
    return b


# ------------------------------------------------------------------
# Unit tests
# ------------------------------------------------------------------


class TestBotProperties:
    def test_base_url(self, bot: PolicyBot) -> None:
        assert bot._base_url == "https://mock.telegram.api/bottest-token"

    def test_auth_headers_no_token(self, bot: PolicyBot) -> None:
        bot._admin_token = None
        assert bot._auth_headers() == {}

    def test_auth_headers_with_token(self, bot: PolicyBot) -> None:
        bot._admin_token = "secret"
        assert bot._auth_headers() == {"Authorization": "Bearer secret"}


class TestHandleMessage:
    @pytest.mark.asyncio
    async def test_command_routing(self, bot: PolicyBot) -> None:
        """Commands should be routed to handler, not to compile."""
        bot._handle_command = AsyncMock()
        msg = {"chat": {"id": 123}, "text": "/status"}
        await bot._handle_message(msg)
        bot._handle_command.assert_awaited_once_with(123, "/status")

    @pytest.mark.asyncio
    async def test_nl_input(self, bot: PolicyBot) -> None:
        """Plain text should trigger compilation."""
        bot._handle_compile = AsyncMock()
        msg = {"chat": {"id": 123}, "text": "Block delete_file"}
        await bot._handle_message(msg)
        bot._handle_compile.assert_awaited_once_with(123, "Block delete_file")

    @pytest.mark.asyncio
    async def test_empty_text_ignored(self, bot: PolicyBot) -> None:
        """Empty messages should be ignored."""
        bot._handle_compile = AsyncMock()
        msg = {"chat": {"id": 123}, "text": ""}
        await bot._handle_message(msg)
        bot._handle_compile.assert_not_awaited()


class TestCompileFlow:
    @pytest.mark.asyncio
    async def test_successful_compile(self, bot: PolicyBot) -> None:
        """Successful compilation should show preview with deploy/cancel buttons."""
        yaml_text = "rules:\n  - id: no-delete\n    when: {tool: delete_file}\n    then: block\n"
        bot._compiler.compile = AsyncMock(return_value=CompileResult(yaml_text=yaml_text, is_valid=True, attempts=1))
        bot._send = AsyncMock(return_value={})

        await bot._handle_compile(123, "Block delete_file")

        assert bot._send.await_count == 2  # "Compiling..." + preview
        # Check that deploy/cancel buttons are sent
        last_call = bot._send.await_args_list[-1]
        markup = json.loads(last_call.kwargs["reply_markup"])
        buttons = markup["inline_keyboard"][0]
        assert any(b["text"] == "✅ Deploy" for b in buttons)
        assert any(b["text"] == "❌ Cancel" for b in buttons)
        assert bot._pending[123] == yaml_text

    @pytest.mark.asyncio
    async def test_failed_compile(self, bot: PolicyBot) -> None:
        """Failed compilation should show errors."""
        bot._compiler.compile = AsyncMock(
            return_value=CompileResult(yaml_text="", is_valid=False, errors=["Missing 'rules' key"], attempts=2)
        )
        bot._send = AsyncMock(return_value={})

        await bot._handle_compile(123, "gibberish")

        assert bot._send.await_count == 2  # "Compiling..." + error
        last_msg = bot._send.await_args_list[-1].args[1]
        assert "failed" in last_msg.lower()

    @pytest.mark.asyncio
    async def test_compile_exception(self, bot: PolicyBot) -> None:
        """Compiler exception should be reported to user."""
        bot._compiler.compile = AsyncMock(side_effect=RuntimeError("LLM down"))
        bot._send = AsyncMock(return_value={})

        await bot._handle_compile(123, "anything")

        last_msg = bot._send.await_args_list[-1].args[1]
        assert "LLM down" in last_msg


class TestCallbackHandler:
    @pytest.mark.asyncio
    async def test_deploy_callback(self, bot: PolicyBot, tmp_rules: Path) -> None:
        """Deploy callback should write YAML and reload server."""
        yaml_text = "rules:\n  - id: test\n    when: {tool: x}\n    then: block\n"
        bot._pending[123] = yaml_text
        bot._answer_callback = AsyncMock()
        bot._edit_message = AsyncMock()

        # Mock server reload response
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"rules_count": 1, "rules_hash": "abc123"}
        mock_resp.raise_for_status = MagicMock()
        bot._client.post = AsyncMock(return_value=mock_resp)

        callback = {
            "id": "cb1",
            "data": "deploy",
            "message": {"chat": {"id": 123}, "message_id": 456},
        }
        await bot._handle_callback(callback)

        # Check YAML was written
        assert tmp_rules.read_text() == yaml_text
        # Check pending was cleared
        assert 123 not in bot._pending
        # Check success message
        bot._edit_message.assert_awaited_once()
        msg = bot._edit_message.await_args.args[2]
        assert "Deployed" in msg

    @pytest.mark.asyncio
    async def test_cancel_callback(self, bot: PolicyBot) -> None:
        """Cancel callback should clear pending and confirm."""
        bot._pending[123] = "some yaml"
        bot._answer_callback = AsyncMock()
        bot._edit_message = AsyncMock()

        callback = {
            "id": "cb2",
            "data": "cancel",
            "message": {"chat": {"id": 123}, "message_id": 789},
        }
        await bot._handle_callback(callback)

        assert 123 not in bot._pending
        bot._edit_message.assert_awaited_once()
        msg = bot._edit_message.await_args.args[2]
        assert "cancelled" in msg.lower()

    @pytest.mark.asyncio
    async def test_deploy_no_pending(self, bot: PolicyBot) -> None:
        """Deploy with no pending YAML should be handled gracefully."""
        bot._answer_callback = AsyncMock()

        callback = {
            "id": "cb3",
            "data": "deploy",
            "message": {"chat": {"id": 999}, "message_id": 1},
        }
        await bot._handle_callback(callback)

        bot._answer_callback.assert_awaited_once_with("cb3", "No pending rules")

    @pytest.mark.asyncio
    async def test_deploy_creates_backup(self, bot: PolicyBot, tmp_rules: Path) -> None:
        """Deploy should back up existing rules."""
        tmp_rules.write_text("old: rules\n")
        bot._pending[123] = "new: rules\n"
        bot._answer_callback = AsyncMock()
        bot._edit_message = AsyncMock()

        mock_resp = MagicMock()
        mock_resp.json.return_value = {"rules_count": 1, "rules_hash": "x"}
        mock_resp.raise_for_status = MagicMock()
        bot._client.post = AsyncMock(return_value=mock_resp)

        callback = {
            "id": "cb4",
            "data": "deploy",
            "message": {"chat": {"id": 123}, "message_id": 1},
        }
        await bot._handle_callback(callback)

        # Backup should exist
        backups = list(tmp_rules.parent.glob("*.bak"))
        assert len(backups) == 1
        assert backups[0].read_text() == "old: rules\n"
        assert tmp_rules.read_text() == "new: rules\n"

    @pytest.mark.asyncio
    async def test_deploy_server_unreachable(self, bot: PolicyBot, tmp_rules: Path) -> None:
        """Deploy should warn if server reload fails."""
        bot._pending[123] = "rules:\n  - id: t\n    when: {tool: x}\n    then: block\n"
        bot._answer_callback = AsyncMock()
        bot._edit_message = AsyncMock()
        bot._client.post = AsyncMock(side_effect=Exception("Connection refused"))

        callback = {
            "id": "cb5",
            "data": "deploy",
            "message": {"chat": {"id": 123}, "message_id": 1},
        }
        await bot._handle_callback(callback)

        msg = bot._edit_message.await_args.args[2]
        assert "reload failed" in msg.lower()
        # Rules should still be written
        assert "rules" in tmp_rules.read_text()


class TestCommands:
    @pytest.mark.asyncio
    async def test_start(self, bot: PolicyBot) -> None:
        bot._send = AsyncMock(return_value={})
        await bot._cmd_start(123)
        msg = bot._send.await_args.args[1]
        assert "PolicyShield Bot" in msg

    @pytest.mark.asyncio
    async def test_help(self, bot: PolicyBot) -> None:
        bot._send = AsyncMock(return_value={})
        await bot._cmd_help(123)
        msg = bot._send.await_args.args[1]
        assert "/status" in msg

    @pytest.mark.asyncio
    async def test_status_online(self, bot: PolicyBot) -> None:
        mock_resp = MagicMock()
        mock_resp.json.return_value = {
            "shield_name": "test",
            "mode": "enforce",
            "rules_count": 5,
            "rules_hash": "abc",
        }
        mock_resp.raise_for_status = MagicMock()
        bot._client.get = AsyncMock(return_value=mock_resp)
        bot._send = AsyncMock(return_value={})

        await bot._cmd_status(123)
        msg = bot._send.await_args.args[1]
        assert "Online" in msg

    @pytest.mark.asyncio
    async def test_status_offline(self, bot: PolicyBot) -> None:
        bot._client.get = AsyncMock(side_effect=Exception("refused"))
        bot._send = AsyncMock(return_value={})

        await bot._cmd_status(123)
        msg = bot._send.await_args.args[1]
        assert "Unreachable" in msg

    @pytest.mark.asyncio
    async def test_unknown_command(self, bot: PolicyBot) -> None:
        bot._send = AsyncMock(return_value={})
        await bot._handle_command(123, "/foobar")
        msg = bot._send.await_args.args[1]
        assert "Unknown" in msg


class TestRunBot:
    def test_missing_token_raises(self) -> None:
        with pytest.raises(ValueError, match="token required"):
            run_bot(token="", rules_path="./rules.yaml")

    def test_env_fallback(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("POLICYSHIELD_BOT_TOKEN", "env-token")
        monkeypatch.setenv("POLICYSHIELD_BOT_RULES_PATH", "/tmp/r.yaml")

        with patch("policyshield.bot.telegram_bot.PolicyBot") as MockBot:
            mock_instance = MagicMock()
            mock_instance.run = AsyncMock()
            MockBot.return_value = mock_instance

            with patch("asyncio.run"):
                run_bot()

            MockBot.assert_called_once()
            kwargs = MockBot.call_args
            assert kwargs.kwargs["bot_token"] == "env-token"
            assert str(kwargs.kwargs["rules_path"]) == "/tmp/r.yaml"
