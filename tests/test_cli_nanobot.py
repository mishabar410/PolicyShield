"""Tests for `policyshield nanobot` CLI wrapper."""

from __future__ import annotations

import types
from unittest.mock import MagicMock

from policyshield.cli.main import app


# ---------- helpers ----------


def _make_fake_agent_loop_module():
    """Create a fake nanobot.agent.loop module with a mock AgentLoop."""
    mod = types.ModuleType("nanobot.agent.loop")

    class FakeAgentLoop:
        def __init__(self):
            self.tools = []

    mod.AgentLoop = FakeAgentLoop  # type: ignore[attr-defined]
    return mod


def _make_fake_nanobot_cli_module():
    """Create a fake nanobot.cli.commands module with a mock app."""
    mod = types.ModuleType("nanobot.cli.commands")
    mod.app = MagicMock()  # type: ignore[attr-defined]
    return mod


# ---------- patch_agent_loop_class tests ----------


class TestPatchAgentLoopClass:
    def test_patch_agent_loop_class(self, tmp_path, monkeypatch):
        """After patching, new AgentLoop instances get shielded."""
        loop_mod = _make_fake_agent_loop_module()
        monkeypatch.setitem(__import__("sys").modules, "nanobot", types.ModuleType("nanobot"))
        monkeypatch.setitem(__import__("sys").modules, "nanobot.agent", types.ModuleType("nanobot.agent"))
        monkeypatch.setitem(__import__("sys").modules, "nanobot.agent.loop", loop_mod)

        # Mock shield_agent_loop
        mock_shield = MagicMock()
        monkeypatch.setattr(
            "policyshield.integrations.nanobot.monkey_patch.shield_agent_loop",
            mock_shield,
        )

        from policyshield.integrations.nanobot.cli_wrapper import patch_agent_loop_class

        rules = tmp_path / "rules.yaml"
        rules.write_text("shield_name: test\nversion: 1\nrules: []\n")

        original = patch_agent_loop_class(str(rules), mode="ENFORCE", fail_open=True)
        assert original is not None

        # Creating a new instance should trigger the shield
        _instance = loop_mod.AgentLoop()
        assert mock_shield.called

    def test_patch_idempotent(self, tmp_path, monkeypatch):
        """Double patch doesn't break things."""
        loop_mod = _make_fake_agent_loop_module()
        monkeypatch.setitem(__import__("sys").modules, "nanobot", types.ModuleType("nanobot"))
        monkeypatch.setitem(__import__("sys").modules, "nanobot.agent", types.ModuleType("nanobot.agent"))
        monkeypatch.setitem(__import__("sys").modules, "nanobot.agent.loop", loop_mod)

        mock_shield = MagicMock()
        monkeypatch.setattr(
            "policyshield.integrations.nanobot.monkey_patch.shield_agent_loop",
            mock_shield,
        )

        from policyshield.integrations.nanobot.cli_wrapper import patch_agent_loop_class

        rules = tmp_path / "rules.yaml"
        rules.write_text("shield_name: test\nversion: 1\nrules: []\n")

        patch_agent_loop_class(str(rules))
        patch_agent_loop_class(str(rules))

        _instance = loop_mod.AgentLoop()
        # Should not crash
        assert mock_shield.called

    def test_patch_restores_original(self, tmp_path, monkeypatch):
        """Returned original_init can restore the class."""
        loop_mod = _make_fake_agent_loop_module()
        monkeypatch.setitem(__import__("sys").modules, "nanobot", types.ModuleType("nanobot"))
        monkeypatch.setitem(__import__("sys").modules, "nanobot.agent", types.ModuleType("nanobot.agent"))
        monkeypatch.setitem(__import__("sys").modules, "nanobot.agent.loop", loop_mod)

        mock_shield = MagicMock()
        monkeypatch.setattr(
            "policyshield.integrations.nanobot.monkey_patch.shield_agent_loop",
            mock_shield,
        )

        from policyshield.integrations.nanobot.cli_wrapper import patch_agent_loop_class

        rules = tmp_path / "rules.yaml"
        rules.write_text("shield_name: test\nversion: 1\nrules: []\n")

        original_init = loop_mod.AgentLoop.__init__
        returned_original = patch_agent_loop_class(str(rules))
        assert returned_original is original_init

        # Restore
        loop_mod.AgentLoop.__init__ = returned_original
        mock_shield.reset_mock()
        _instance = loop_mod.AgentLoop()
        mock_shield.assert_not_called()


# ---------- CLI tests ----------


class TestCliNanobot:
    def test_cli_nanobot_missing_rules(self, capsys):
        """nanobot without --rules → error."""
        import pytest

        with pytest.raises(SystemExit) as exc_info:
            app(["nanobot"])
        assert exc_info.value.code != 0

    def test_cli_nanobot_invalid_rules(self, tmp_path, capsys):
        """--rules nonexistent.yaml → error message."""
        exit_code = app(["nanobot", "--rules", str(tmp_path / "nonexistent.yaml")])
        assert exit_code == 1
        captured = capsys.readouterr()
        assert "not found" in captured.err.lower()

    def test_cli_nanobot_mode_audit(self, tmp_path, monkeypatch, capsys):
        """--mode AUDIT is accepted."""
        rules = tmp_path / "rules.yaml"
        rules.write_text("shield_name: test\nversion: 1\nrules: []\n")

        loop_mod = _make_fake_agent_loop_module()
        cli_mod = _make_fake_nanobot_cli_module()
        monkeypatch.setitem(__import__("sys").modules, "nanobot", types.ModuleType("nanobot"))
        monkeypatch.setitem(__import__("sys").modules, "nanobot.agent", types.ModuleType("nanobot.agent"))
        monkeypatch.setitem(__import__("sys").modules, "nanobot.agent.loop", loop_mod)
        monkeypatch.setitem(__import__("sys").modules, "nanobot.cli", types.ModuleType("nanobot.cli"))
        monkeypatch.setitem(__import__("sys").modules, "nanobot.cli.commands", cli_mod)

        mock_shield = MagicMock()
        monkeypatch.setattr(
            "policyshield.integrations.nanobot.monkey_patch.shield_agent_loop",
            mock_shield,
        )

        exit_code = app(["nanobot", "--rules", str(rules), "--mode", "AUDIT", "agent"])
        assert exit_code == 0

    def test_cli_nanobot_args_passthrough(self, tmp_path, monkeypatch, capsys):
        """Arguments after --rules are passed to nanobot."""
        rules = tmp_path / "rules.yaml"
        rules.write_text("shield_name: test\nversion: 1\nrules: []\n")

        loop_mod = _make_fake_agent_loop_module()
        cli_mod = _make_fake_nanobot_cli_module()
        monkeypatch.setitem(__import__("sys").modules, "nanobot", types.ModuleType("nanobot"))
        monkeypatch.setitem(__import__("sys").modules, "nanobot.agent", types.ModuleType("nanobot.agent"))
        monkeypatch.setitem(__import__("sys").modules, "nanobot.agent.loop", loop_mod)
        monkeypatch.setitem(__import__("sys").modules, "nanobot.cli", types.ModuleType("nanobot.cli"))
        monkeypatch.setitem(__import__("sys").modules, "nanobot.cli.commands", cli_mod)

        mock_shield = MagicMock()
        monkeypatch.setattr(
            "policyshield.integrations.nanobot.monkey_patch.shield_agent_loop",
            mock_shield,
        )

        exit_code = app(["nanobot", "--rules", str(rules), "agent", "-m", "Hello"])
        assert exit_code == 0
        cli_mod.app.assert_called_once()

    def test_cli_nanobot_no_nanobot_installed(self, tmp_path, monkeypatch, capsys):
        """ImportError → friendly error message."""
        rules = tmp_path / "rules.yaml"
        rules.write_text("shield_name: test\nversion: 1\nrules: []\n")

        # Remove nanobot from sys.modules
        import sys

        for mod_name in list(sys.modules.keys()):
            if mod_name.startswith("nanobot"):
                monkeypatch.delitem(sys.modules, mod_name)

        # Mock import to raise ImportError
        orig_import = __builtins__.__import__ if hasattr(__builtins__, "__import__") else __import__

        def fake_import(name, *args, **kwargs):
            if name.startswith("nanobot"):
                raise ImportError("No module named 'nanobot'")
            return orig_import(name, *args, **kwargs)

        monkeypatch.setattr("builtins.__import__", fake_import)

        exit_code = app(["nanobot", "--rules", str(rules), "agent"])
        assert exit_code == 1
        captured = capsys.readouterr()
        assert "not installed" in captured.err.lower()
