"""Tests for --preset secure."""

import tempfile
from pathlib import Path

import yaml

from policyshield.cli.init_scaffold import scaffold, _get_preset_rules


class TestSecurePreset:
    def test_rules_count(self):
        rules = _get_preset_rules("secure")
        assert len(rules) == 10

    def test_has_whitelist(self):
        rules = _get_preset_rules("secure")
        allow_rules = [r for r in rules if r["then"] == "allow"]
        assert len(allow_rules) >= 4  # read, list, search, info

    def test_has_blocks(self):
        rules = _get_preset_rules("secure")
        block_rules = [r for r in rules if r["then"] == "block"]
        assert len(block_rules) >= 3  # exec, delete, network

    def test_scaffold_creates_files(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            created = scaffold(tmpdir, preset="secure", interactive=False)
            assert "policies/rules.yaml" in created
            assert "policyshield.yaml" in created

    def test_scaffold_default_verdict_block(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            scaffold(tmpdir, preset="secure", interactive=False)
            rules_file = Path(tmpdir) / "policies" / "rules.yaml"
            data = yaml.safe_load(rules_file.read_text())
            assert data["default_verdict"] == "block"

    def test_scaffold_builtin_detectors(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            scaffold(tmpdir, preset="secure", interactive=False)
            config_file = Path(tmpdir) / "policyshield.yaml"
            config = yaml.safe_load(config_file.read_text())
            detectors = config.get("sanitizer", {}).get("builtin_detectors", [])
            assert "path_traversal" in detectors
            assert "shell_injection" in detectors
            assert len(detectors) == 5

    def test_scaffold_fail_closed(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            scaffold(tmpdir, preset="secure", interactive=False)
            config_file = Path(tmpdir) / "policyshield.yaml"
            config = yaml.safe_load(config_file.read_text())
            assert config["fail_open"] is False

    def test_preset_not_break_others(self):
        """Adding secure preset doesn't break existing presets."""
        for preset in ("minimal", "security", "compliance", "openclaw"):
            rules = _get_preset_rules(preset)
            assert len(rules) > 0
