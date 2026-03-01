"""Telegram bot for managing PolicyShield via natural language.

Send a message like "Block delete_file and redact PII in send_email" and
the bot will compile it to validated YAML, show a preview, and deploy
on confirmation.

Usage::

    policyshield bot --token BOT_TOKEN --rules ./rules.yaml
    policyshield bot --token BOT_TOKEN --rules ./rules.yaml --server http://localhost:8100

Or set env vars::

    POLICYSHIELD_BOT_TOKEN=123:ABC
    POLICYSHIELD_BOT_RULES_PATH=./rules.yaml
    POLICYSHIELD_SERVER_URL=http://localhost:8100
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import shutil
from datetime import datetime, timezone
from pathlib import Path

import httpx

from policyshield.ai.compiler import PolicyCompiler

logger = logging.getLogger("policyshield.bot")

_TELEGRAM_API = "https://api.telegram.org"

# Maximum YAML preview length in a Telegram message (code block)
_MAX_PREVIEW_LEN = 3500


class PolicyBot:
    """Telegram bot that compiles NL descriptions to PolicyShield YAML and deploys.

    Args:
        bot_token: Telegram Bot API token.
        rules_path: Path to the YAML rules file to write.
        server_url: URL of the running PolicyShield server (for reload/status).
        compiler: Optional pre-configured PolicyCompiler instance.
        api_base: Telegram API base URL (for testing).
        admin_token: Optional admin token for server API calls.
    """

    def __init__(
        self,
        bot_token: str,
        rules_path: str | Path,
        server_url: str = "http://localhost:8100",
        compiler: PolicyCompiler | None = None,
        api_base: str = _TELEGRAM_API,
        admin_token: str | None = None,
    ) -> None:
        self._token = bot_token
        self._rules_path = Path(rules_path)
        self._server_url = server_url.rstrip("/")
        self._compiler = compiler or PolicyCompiler()
        self._api_base = api_base
        self._admin_token = admin_token or os.environ.get("POLICYSHIELD_ADMIN_TOKEN")

        self._client = httpx.AsyncClient(timeout=30.0)
        self._update_offset: int = 0
        self._running = False

        # Pending compilations: chat_id → yaml_text
        self._pending: dict[int, str] = {}

    @property
    def _base_url(self) -> str:
        return f"{self._api_base}/bot{self._token}"

    # ------------------------------------------------------------------
    # Main loop
    # ------------------------------------------------------------------

    async def run(self) -> None:
        """Start the bot long-polling loop."""
        logger.info("PolicyBot starting — polling for messages...")
        me = await self._api("getMe")
        if me.get("ok"):
            name = me["result"].get("username", "unknown")
            logger.info("Bot authenticated as @%s", name)

        self._running = True
        while self._running:
            try:
                await self._poll()
            except Exception:
                logger.exception("Error in poll loop")
                await asyncio.sleep(2)

    async def stop(self) -> None:
        """Stop the polling loop."""
        self._running = False
        await self._client.aclose()

    # ------------------------------------------------------------------
    # Telegram API helpers
    # ------------------------------------------------------------------

    async def _api(self, method: str, **kwargs) -> dict:
        """Call a Telegram Bot API method."""
        resp = await self._client.post(f"{self._base_url}/{method}", **kwargs)
        return resp.json()

    async def _send(self, chat_id: int, text: str, **kwargs) -> dict:
        """Send a text message."""
        payload = {"chat_id": chat_id, "text": text, "parse_mode": "Markdown", **kwargs}
        return await self._api("sendMessage", json=payload)

    async def _answer_callback(self, callback_id: str, text: str) -> None:
        """Answer an inline keyboard callback."""
        await self._api(
            "answerCallbackQuery",
            json={"callback_query_id": callback_id, "text": text},
        )

    async def _edit_message(self, chat_id: int, message_id: int, text: str) -> None:
        """Edit an existing message."""
        await self._api(
            "editMessageText",
            json={
                "chat_id": chat_id,
                "message_id": message_id,
                "text": text,
                "parse_mode": "Markdown",
            },
        )

    # ------------------------------------------------------------------
    # Polling
    # ------------------------------------------------------------------

    async def _poll(self) -> None:
        """Fetch and process new updates via long polling."""
        data = await self._api(
            "getUpdates",
            params={"offset": self._update_offset, "timeout": 30},
        )
        if not data.get("ok"):
            return

        for update in data.get("result", []):
            self._update_offset = update["update_id"] + 1

            # Handle callback queries (button presses)
            if "callback_query" in update:
                await self._handle_callback(update["callback_query"])
                continue

            # Handle text messages
            msg = update.get("message", {})
            text = msg.get("text", "")
            if text:
                await self._handle_message(msg)

    # ------------------------------------------------------------------
    # Message handlers
    # ------------------------------------------------------------------

    async def _handle_message(self, msg: dict) -> None:
        """Handle an incoming text message."""
        chat_id = msg["chat"]["id"]
        text = msg.get("text", "").strip()

        if not text:
            return

        # Command routing
        if text.startswith("/"):
            await self._handle_command(chat_id, text)
            return

        # Natural language → compile
        await self._handle_compile(chat_id, text)

    async def _handle_command(self, chat_id: int, text: str) -> None:
        """Route /commands."""
        cmd = text.split()[0].lower().split("@")[0]  # strip @botname

        handlers = {
            "/start": self._cmd_start,
            "/help": self._cmd_help,
            "/status": self._cmd_status,
            "/rules": self._cmd_rules,
            "/kill": self._cmd_kill,
            "/resume": self._cmd_resume,
        }

        handler = handlers.get(cmd)
        if handler:
            await handler(chat_id)
        else:
            await self._send(chat_id, f"Unknown command `{cmd}`. Send /help for usage.")

    async def _cmd_start(self, chat_id: int) -> None:
        await self._send(
            chat_id,
            "🛡️ *PolicyShield Bot*\n\n"
            "Send me a policy description in natural language and I'll compile "
            "it to YAML rules and deploy to your server.\n\n"
            "Example:\n"
            '_"Block file deletions and redact PII in send\\_email"_\n\n'
            "Commands: /help /status /rules /kill /resume",
        )

    async def _cmd_help(self, chat_id: int) -> None:
        await self._send(
            chat_id,
            "📖 *Commands:*\n\n"
            "/status — server health check\n"
            "/rules — show current rules summary\n"
            "/kill — emergency kill switch (block ALL)\n"
            "/resume — deactivate kill switch\n\n"
            "Or just send a policy description in plain text.",
        )

    async def _cmd_status(self, chat_id: int) -> None:
        try:
            resp = await self._server_get("/api/v1/health")
            h = resp.json()
            status = (
                f"🟢 *Server Online*\n\n"
                f"Shield: `{h.get('shield_name', '?')}`\n"
                f"Mode: `{h.get('mode', '?')}`\n"
                f"Rules: {h.get('rules_count', '?')}\n"
                f"Hash: `{h.get('rules_hash', '?')}`"
            )
        except Exception as e:
            status = f"🔴 *Server Unreachable*\n\n`{e}`"
        await self._send(chat_id, status)

    async def _cmd_rules(self, chat_id: int) -> None:
        try:
            resp = await self._server_get("/api/v1/constraints")
            data = resp.json()
            summary = data.get("summary", "No constraints available.")
            await self._send(chat_id, f"📋 *Current Policy:*\n\n{summary}")
        except Exception as e:
            await self._send(chat_id, f"❌ Failed to get rules: `{e}`")

    async def _cmd_kill(self, chat_id: int) -> None:
        try:
            resp = await self._server_post(
                "/api/v1/kill",
                json={"reason": "Kill via Telegram bot"},
            )
            data = resp.json()
            await self._send(
                chat_id,
                f"🚨 *Kill switch activated!*\n\nAll tool calls are now BLOCKED.\nReason: {data.get('reason', 'N/A')}\n\nUse /resume to deactivate.",
            )
        except Exception as e:
            await self._send(chat_id, f"❌ Failed to activate kill switch: `{e}`")

    async def _cmd_resume(self, chat_id: int) -> None:
        try:
            await self._server_post("/api/v1/resume")
            await self._send(chat_id, "✅ *Kill switch deactivated.* Normal operation resumed.")
        except Exception as e:
            await self._send(chat_id, f"❌ Failed to resume: `{e}`")

    # ------------------------------------------------------------------
    # Compile & Deploy
    # ------------------------------------------------------------------

    async def _handle_compile(self, chat_id: int, description: str) -> None:
        """Compile NL description to YAML and show preview."""
        await self._send(chat_id, "⏳ Compiling your policy...")

        try:
            result = await self._compiler.compile(description)
        except Exception as e:
            await self._send(chat_id, f"❌ Compilation failed: `{e}`")
            return

        if not result.is_valid:
            errors = "\n".join(f"• {e}" for e in result.errors)
            await self._send(
                chat_id,
                f"❌ *Compilation failed* (after {result.attempts} attempts):\n\n{errors}",
            )
            return

        # Store pending YAML
        self._pending[chat_id] = result.yaml_text

        # Preview
        yaml_preview = result.yaml_text
        if len(yaml_preview) > _MAX_PREVIEW_LEN:
            yaml_preview = yaml_preview[:_MAX_PREVIEW_LEN] + "\n# ... (truncated)"

        keyboard = {
            "inline_keyboard": [
                [
                    {"text": "✅ Deploy", "callback_data": "deploy"},
                    {"text": "❌ Cancel", "callback_data": "cancel"},
                ]
            ]
        }

        await self._send(
            chat_id,
            f"📝 *Compiled rules* ({result.attempts} attempt(s)):\n\n```yaml\n{yaml_preview}\n```\n\nDeploy to server?",
            reply_markup=json.dumps(keyboard),
        )

    async def _handle_callback(self, callback: dict) -> None:
        """Handle inline keyboard button press."""
        chat_id = callback["message"]["chat"]["id"]
        message_id = callback["message"]["message_id"]
        action = callback.get("data", "")
        callback_id = callback["id"]

        if action == "deploy":
            await self._deploy(chat_id, message_id, callback_id)
        elif action == "cancel":
            self._pending.pop(chat_id, None)
            await self._answer_callback(callback_id, "Cancelled")
            await self._edit_message(chat_id, message_id, "❌ Deployment cancelled.")
        else:
            await self._answer_callback(callback_id, "Unknown action")

    async def _deploy(self, chat_id: int, message_id: int, callback_id: str) -> None:
        """Write YAML to disk and reload the server."""
        yaml_text = self._pending.pop(chat_id, None)
        if not yaml_text:
            await self._answer_callback(callback_id, "No pending rules")
            return

        await self._answer_callback(callback_id, "Deploying...")

        # Backup existing rules
        if self._rules_path.exists():
            ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
            backup = self._rules_path.with_suffix(f".{ts}.bak")
            shutil.copy2(self._rules_path, backup)
            logger.info("Backed up rules to %s", backup)

        # Write new rules
        self._rules_path.parent.mkdir(parents=True, exist_ok=True)
        self._rules_path.write_text(yaml_text, encoding="utf-8")
        logger.info("Wrote new rules to %s", self._rules_path)

        # Reload server
        try:
            resp = await self._server_post("/api/v1/reload")
            data = resp.json()
            count = data.get("rules_count", "?")
            rhash = data.get("rules_hash", "?")
            await self._edit_message(
                chat_id,
                message_id,
                f"✅ *Deployed!*\n\nRules: {count}\nHash: `{rhash}`\nFile: `{self._rules_path}`",
            )
        except Exception as e:
            await self._edit_message(
                chat_id,
                message_id,
                f"⚠️ *Rules written* to `{self._rules_path}` but server reload failed:\n\n`{e}`\n\nTry: `policyshield server --rules {self._rules_path}`",
            )

    # ------------------------------------------------------------------
    # Server API helpers
    # ------------------------------------------------------------------

    def _auth_headers(self) -> dict[str, str]:
        """Build auth headers for server API calls."""
        headers: dict[str, str] = {}
        if self._admin_token:
            headers["Authorization"] = f"Bearer {self._admin_token}"
        return headers

    async def _server_get(self, path: str) -> httpx.Response:
        """GET request to the PolicyShield server."""
        resp = await self._client.get(
            f"{self._server_url}{path}",
            headers=self._auth_headers(),
        )
        resp.raise_for_status()
        return resp

    async def _server_post(self, path: str, **kwargs) -> httpx.Response:
        """POST request to the PolicyShield server."""
        headers = {**self._auth_headers(), **kwargs.pop("headers", {})}
        resp = await self._client.post(
            f"{self._server_url}{path}",
            headers=headers,
            **kwargs,
        )
        resp.raise_for_status()
        return resp


def run_bot(
    token: str | None = None,
    rules_path: str | None = None,
    server_url: str | None = None,
    admin_token: str | None = None,
) -> None:
    """Entry point for ``policyshield bot`` CLI command."""
    _token = token or os.environ.get("POLICYSHIELD_BOT_TOKEN", "")
    _rules = rules_path or os.environ.get("POLICYSHIELD_BOT_RULES_PATH", "./rules.yaml")
    _server = server_url or os.environ.get("POLICYSHIELD_SERVER_URL", "http://localhost:8100")
    _admin = admin_token or os.environ.get("POLICYSHIELD_ADMIN_TOKEN")

    if not _token:
        raise ValueError("Bot token required. Set POLICYSHIELD_BOT_TOKEN or pass --token.")

    bot = PolicyBot(
        bot_token=_token,
        rules_path=_rules,
        server_url=_server,
        admin_token=_admin,
    )

    try:
        asyncio.run(bot.run())
    except KeyboardInterrupt:
        logger.info("Bot stopped by user")
