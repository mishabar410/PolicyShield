"""Tests for CLI generate-rules command."""

import argparse
import tempfile
from pathlib import Path

import yaml

from policyshield.cli.main import _cmd_generate_rules


class TestGenerateRulesCLI:
    def test_from_tools_flag(self):
        """--tools generates rules to file."""
        with tempfile.TemporaryDirectory() as td:
            output = Path(td) / "rules.yaml"
            args = argparse.Namespace(
                from_openclaw=False,
                url="http://localhost:3000",
                tools="exec,write_file,delete_file,read_file",
                output=str(output),
                include_safe=False,
                default_verdict="block",
                force=True,
            )
            _cmd_generate_rules(args)
            assert output.exists()
            data = yaml.safe_load(output.read_text())
            assert len(data["rules"]) >= 2  # exec=block, write=approve, delete=block
            assert data["default_verdict"] == "block"

    def test_include_safe(self):
        """--include-safe includes safe tool rules."""
        with tempfile.TemporaryDirectory() as td:
            output = Path(td) / "rules.yaml"
            args = argparse.Namespace(
                from_openclaw=False,
                url="http://localhost:3000",
                tools="log_message,exec",
                output=str(output),
                include_safe=True,
                default_verdict="block",
                force=True,
            )
            _cmd_generate_rules(args)
            data = yaml.safe_load(output.read_text())
            names = [r["when"]["tool"] for r in data["rules"]]
            assert "log_message" in names

    def test_no_tools_no_openclaw(self):
        """Must specify --from-openclaw or --tools."""
        args = argparse.Namespace(
            from_openclaw=False,
            url="http://localhost:3000",
            tools=None,
            output="/dev/null",
            include_safe=False,
            default_verdict="block",
            force=True,
        )
        result = _cmd_generate_rules(args)
        assert result == 1

    def test_makedirs(self):
        """Output directory is created if needed."""
        with tempfile.TemporaryDirectory() as td:
            output = Path(td) / "deep" / "nested" / "rules.yaml"
            args = argparse.Namespace(
                from_openclaw=False,
                url="http://localhost:3000",
                tools="exec",
                output=str(output),
                include_safe=False,
                default_verdict="block",
                force=True,
            )
            _cmd_generate_rules(args)
            assert output.exists()
