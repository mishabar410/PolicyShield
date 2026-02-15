"""Tests for the OpenClaw CLI commands."""

from __future__ import annotations

from policyshield.cli.main import app


class TestOpenClawCLI:
    """Test suite for policyshield openclaw subcommands."""

    def test_openclaw_status_no_server(self, capsys) -> None:
        """Status should report server not reachable when no server is running."""
        code = app(["openclaw", "status"])
        assert code == 0
        captured = capsys.readouterr()
        assert "not reachable" in captured.out

    def test_openclaw_teardown_no_pid(self, capsys, tmp_path, monkeypatch) -> None:
        """Teardown with no PID file should report nothing to stop."""
        monkeypatch.chdir(tmp_path)
        code = app(["openclaw", "teardown", "--rules-dir", str(tmp_path)])
        assert code == 0
        captured = capsys.readouterr()
        assert "Nothing to stop" in captured.out

    def test_openclaw_help(self, capsys) -> None:
        """openclaw with no subcommand should show usage."""
        code = app(["openclaw"])
        assert code == 1
        captured = capsys.readouterr()
        assert "setup" in captured.err or "Usage" in captured.err

    def test_openclaw_setup_help(self) -> None:
        """setup --help should work."""
        import pytest

        with pytest.raises(SystemExit) as exc_info:
            app(["openclaw", "setup", "--help"])
        assert exc_info.value.code == 0
