"""End-to-end tests for built-in detectors through the full pipeline (Prompt 203).

Tests verify: YAML config → parser → SanitizerConfig → InputSanitizer → ShieldEngine → Verdict.
"""

from __future__ import annotations

from policyshield.core.models import RuleConfig, RuleSet, Verdict
from policyshield.core.parser import parse_sanitizer_config
from policyshield.shield.engine import ShieldEngine
from policyshield.shield.sanitizer import InputSanitizer, SanitizerConfig


# ── helpers ────────────────────────────────────────────────────────


def _engine_with_detectors(detector_names: list[str]) -> ShieldEngine:
    """Build a ShieldEngine with detectors enabled via the same path as YAML."""
    rules = RuleSet(
        shield_name="e2e-detector-test",
        version=1,
        rules=[
            RuleConfig(
                id="allow-all",
                when={"tool": ".*"},
                then=Verdict.ALLOW,
                message="Allowed by default",
            ),
        ],
    )
    san = InputSanitizer(SanitizerConfig(builtin_detectors=detector_names))
    return ShieldEngine(rules=rules, sanitizer=san)


def _engine_from_yaml_dict(yaml_data: dict) -> ShieldEngine:
    """Build a ShieldEngine by parsing a YAML-like dict (mirrors real config flow)."""
    san_cfg = parse_sanitizer_config(yaml_data)
    sanitizer = InputSanitizer(SanitizerConfig(**san_cfg)) if san_cfg else None

    rules = RuleSet(
        shield_name="e2e-yaml-test",
        version=1,
        rules=[
            RuleConfig(
                id="allow-all",
                when={"tool": ".*"},
                then=Verdict.ALLOW,
                message="Allowed by default",
            ),
        ],
    )
    return ShieldEngine(rules=rules, sanitizer=sanitizer)


# ── E2E: each detector blocks through full pipeline ───────────────


class TestPathTraversalE2E:
    def test_blocks_attack(self):
        engine = _engine_with_detectors(["path_traversal"])
        result = engine.check("read_file", {"path": "../../etc/passwd"})
        assert result.verdict == Verdict.BLOCK
        assert result.rule_id == "__sanitizer__"

    def test_allows_clean(self):
        engine = _engine_with_detectors(["path_traversal"])
        result = engine.check("read_file", {"path": "/home/user/doc.txt"})
        assert result.verdict == Verdict.ALLOW


class TestShellInjectionE2E:
    def test_blocks_attack(self):
        engine = _engine_with_detectors(["shell_injection"])
        result = engine.check("exec", {"command": "echo hello; rm -rf /"})
        assert result.verdict == Verdict.BLOCK
        assert result.rule_id == "__sanitizer__"

    def test_allows_clean(self):
        engine = _engine_with_detectors(["shell_injection"])
        result = engine.check("exec", {"command": "echo hello"})
        assert result.verdict == Verdict.ALLOW


class TestSQLInjectionE2E:
    def test_blocks_attack(self):
        engine = _engine_with_detectors(["sql_injection"])
        result = engine.check("db_query", {"sql": "' OR '1'='1"})
        assert result.verdict == Verdict.BLOCK
        assert result.rule_id == "__sanitizer__"

    def test_allows_clean(self):
        engine = _engine_with_detectors(["sql_injection"])
        result = engine.check("db_query", {"sql": "SELECT name FROM products WHERE id=42"})
        assert result.verdict == Verdict.ALLOW


class TestSSRFE2E:
    def test_blocks_attack(self):
        engine = _engine_with_detectors(["ssrf"])
        result = engine.check("web_fetch", {"url": "http://169.254.169.254/latest/meta-data"})
        assert result.verdict == Verdict.BLOCK
        assert result.rule_id == "__sanitizer__"

    def test_allows_clean(self):
        engine = _engine_with_detectors(["ssrf"])
        result = engine.check("web_fetch", {"url": "https://api.example.com/data"})
        assert result.verdict == Verdict.ALLOW


class TestURLSchemesE2E:
    def test_blocks_attack(self):
        engine = _engine_with_detectors(["url_schemes"])
        result = engine.check("open_url", {"url": "file:///etc/passwd"})
        assert result.verdict == Verdict.BLOCK
        assert result.rule_id == "__sanitizer__"

    def test_allows_clean(self):
        engine = _engine_with_detectors(["url_schemes"])
        result = engine.check("open_url", {"url": "https://example.com"})
        assert result.verdict == Verdict.ALLOW


# ── E2E: all detectors combined ──────────────────────────────────


ALL_DETECTORS = ["path_traversal", "shell_injection", "sql_injection", "ssrf", "url_schemes"]


class TestAllDetectorsCombined:
    def test_blocks_mixed_attack(self):
        engine = _engine_with_detectors(ALL_DETECTORS)
        result = engine.check("exec", {"cmd": "echo; curl http://127.0.0.1/admin"})
        assert result.verdict == Verdict.BLOCK

    def test_clean_passes_all(self):
        engine = _engine_with_detectors(ALL_DETECTORS)
        result = engine.check("safe_tool", {"arg": "perfectly normal text"})
        assert result.verdict == Verdict.ALLOW


# ── E2E: YAML config parsing → engine ────────────────────────────


class TestYAMLConfigFlow:
    """Simulate the full YAML → engine pipeline."""

    def test_yaml_with_detectors(self):
        yaml_data = {
            "sanitizer": {
                "builtin_detectors": ["path_traversal", "ssrf"],
            },
        }
        engine = _engine_from_yaml_dict(yaml_data)
        # path_traversal blocks
        r1 = engine.check("read", {"path": "../../etc/shadow"})
        assert r1.verdict == Verdict.BLOCK
        # ssrf blocks
        r2 = engine.check("fetch", {"url": "http://10.0.0.1/internal"})
        assert r2.verdict == Verdict.BLOCK
        # clean passes
        r3 = engine.check("fetch", {"url": "https://example.com"})
        assert r3.verdict == Verdict.ALLOW

    def test_yaml_without_detectors(self):
        yaml_data = {
            "sanitizer": {
                "max_string_length": 5000,
            },
        }
        engine = _engine_from_yaml_dict(yaml_data)
        # Attack passes because no detectors configured
        result = engine.check("read", {"path": "../../etc/passwd"})
        assert result.verdict == Verdict.ALLOW

    def test_yaml_no_sanitizer_section(self):
        yaml_data = {"rules": []}
        engine = _engine_from_yaml_dict(yaml_data)
        result = engine.check("exec", {"cmd": "; rm -rf /"})
        assert result.verdict == Verdict.ALLOW

    def test_yaml_detectors_with_blocked_patterns(self):
        yaml_data = {
            "sanitizer": {
                "builtin_detectors": ["shell_injection"],
                "blocked_patterns": ["badword"],
            },
        }
        engine = _engine_from_yaml_dict(yaml_data)
        # Detector blocks first
        r1 = engine.check("exec", {"cmd": "; rm -rf /"})
        assert r1.verdict == Verdict.BLOCK
        assert "Built-in detector" in r1.message

        # Pattern blocks too
        r2 = engine.check("chat", {"text": "badword"})
        assert r2.verdict == Verdict.BLOCK
        assert "Blocked pattern" in r2.message
