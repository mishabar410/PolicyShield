"""Tests for compile, compile-and-apply endpoints, and matcher priority resolution."""

import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

fastapi = pytest.importorskip("fastapi", reason="fastapi not installed")

from fastapi.testclient import TestClient  # noqa: E402

from policyshield.core.models import (  # noqa: E402
    RuleConfig,
    RuleSet,
    Severity,
    Verdict,
)
from policyshield.server.app import create_app  # noqa: E402
from policyshield.server.models import CompileRequest  # noqa: E402
from policyshield.shield.async_engine import AsyncShieldEngine  # noqa: E402
from policyshield.shield.matcher import MatcherEngine  # noqa: E402


# ── Matcher priority tests ──────────────────────────────────────────


class TestMatcherPriority:
    """Test that priority field controls rule ordering."""

    def test_lower_priority_number_wins(self):
        """Rule with lower priority number should be selected as best match."""
        rules = RuleSet(
            shield_name="priority-test",
            version=1,
            rules=[
                RuleConfig(
                    id="block-files",
                    when={"tool": "file.delete"},
                    then=Verdict.BLOCK,
                    severity=Severity.CRITICAL,
                    priority=1,
                ),
                RuleConfig(
                    id="allow-files",
                    when={"tool": "file.delete"},
                    then=Verdict.ALLOW,
                    severity=Severity.LOW,
                    priority=0,
                ),
            ],
        )
        matcher = MatcherEngine(rules)
        best = matcher.find_best_match("file.delete")
        assert best is not None
        assert best.rule.id == "allow-files"
        assert best.rule.then == Verdict.ALLOW

    def test_same_priority_most_restrictive_wins(self):
        """When priority is equal, more restrictive verdict wins."""
        rules = RuleSet(
            shield_name="priority-test",
            version=1,
            rules=[
                RuleConfig(
                    id="allow-exec",
                    when={"tool": "exec"},
                    then=Verdict.ALLOW,
                    priority=1,
                ),
                RuleConfig(
                    id="block-exec",
                    when={"tool": "exec"},
                    then=Verdict.BLOCK,
                    severity=Severity.CRITICAL,
                    priority=1,
                ),
            ],
        )
        matcher = MatcherEngine(rules)
        best = matcher.find_best_match("exec")
        assert best is not None
        assert best.rule.id == "block-exec"

    def test_priority_ordering_multiple_rules(self):
        """Multiple rules sorted correctly by priority."""
        rules = RuleSet(
            shield_name="priority-test",
            version=1,
            rules=[
                RuleConfig(id="r3", when={"tool": "t"}, then=Verdict.BLOCK, priority=3),
                RuleConfig(id="r1", when={"tool": "t"}, then=Verdict.ALLOW, priority=1),
                RuleConfig(id="r0", when={"tool": "t"}, then=Verdict.REDACT, priority=0),
                RuleConfig(id="r2", when={"tool": "t"}, then=Verdict.BLOCK, priority=2),
            ],
        )
        matcher = MatcherEngine(rules)
        matches = matcher.find_matching_rules("t")
        assert [m.rule.id for m in matches] == ["r0", "r1", "r2", "r3"]

    def test_default_priority(self):
        """Rules without explicit priority default to 1."""
        rule = RuleConfig(id="test", when={"tool": "t"}, then=Verdict.ALLOW)
        assert rule.priority == 1


# ── Compile endpoint tests ───────────────────────────────────────────


def _make_engine_with_file():
    """Create engine backed by a temp rules file."""
    tmp = Path(tempfile.mkdtemp()) / "rules.yaml"
    tmp.write_text(
        """\
shield_name: test
version: 1
rules:
  - id: block-exec
    when:
      tool: exec
    then: BLOCK
    message: blocked
    severity: CRITICAL
    priority: 1
""",
        encoding="utf-8",
    )
    from policyshield.core.models import ShieldMode

    engine = AsyncShieldEngine(rules=tmp, mode=ShieldMode.ENFORCE)
    return engine, tmp


class TestCompileEndpoint:
    """Test POST /api/v1/compile."""

    def test_compile_success(self):
        """Compile endpoint returns YAML when compilation succeeds."""
        engine = AsyncShieldEngine(
            RuleSet(shield_name="t", version=1, rules=[])
        )
        app = create_app(engine)
        client = TestClient(app)

        mock_result = AsyncMock()
        mock_result.is_valid = True
        mock_result.yaml_text = "shield_name: test\nrules:\n  - id: r1\n    then: BLOCK\n"
        mock_result.errors = []

        with patch(
            "policyshield.ai.compiler.PolicyCompiler.compile",
            return_value=mock_result,
        ):
            resp = client.post(
                "/api/v1/compile",
                json={"description": "Block all file deletions"},
            )
        assert resp.status_code == 200
        data = resp.json()
        assert data["is_valid"] is True
        assert "shield_name" in data["yaml_text"]

    def test_compile_failure(self):
        """Compile endpoint returns errors when compilation fails."""
        engine = AsyncShieldEngine(
            RuleSet(shield_name="t", version=1, rules=[])
        )
        app = create_app(engine)
        client = TestClient(app)

        mock_result = AsyncMock()
        mock_result.is_valid = False
        mock_result.yaml_text = ""
        mock_result.errors = ["LLM generation failed"]

        with patch(
            "policyshield.ai.compiler.PolicyCompiler.compile",
            return_value=mock_result,
        ):
            resp = client.post(
                "/api/v1/compile",
                json={"description": "something invalid"},
            )
        assert resp.status_code == 200
        data = resp.json()
        assert data["is_valid"] is False
        assert len(data["errors"]) > 0


class TestCompileAndApplyEndpoint:
    """Test POST /api/v1/compile-and-apply."""

    def test_compile_and_apply_success(self):
        """New rule is merged, saved, and engine reloaded."""
        engine, tmp = _make_engine_with_file()
        app = create_app(engine)
        client = TestClient(app)

        mock_result = AsyncMock()
        mock_result.is_valid = True
        mock_result.yaml_text = (
            "shield_name: override\n"
            "version: 1\n"
            "rules:\n"
            "  - id: allow-exec\n"
            "    when:\n"
            "      tool: exec\n"
            "    then: ALLOW\n"
            "    message: allowed\n"
            "    severity: LOW\n"
            "    priority: 1\n"
        )
        mock_result.errors = []

        with patch(
            "policyshield.ai.compiler.PolicyCompiler.compile",
            return_value=mock_result,
        ):
            resp = client.post(
                "/api/v1/compile-and-apply",
                json={"description": "Allow exec"},
            )
        assert resp.status_code == 200
        data = resp.json()
        assert data["applied"] is True
        assert data["is_valid"] is True
        assert data["rules_count"] >= 1

        # Verify the old conflicting rule was removed
        import yaml

        saved = yaml.safe_load(tmp.read_text(encoding="utf-8"))
        rule_ids = [r["id"] for r in saved["rules"]]
        assert "allow-exec" in rule_ids
        assert "block-exec" not in rule_ids  # conflicting rule removed

    def test_compile_and_apply_failure(self):
        """Compilation failure returns errors without modifying file."""
        engine, tmp = _make_engine_with_file()
        original_content = tmp.read_text(encoding="utf-8")
        app = create_app(engine)
        client = TestClient(app)

        mock_result = AsyncMock()
        mock_result.is_valid = False
        mock_result.yaml_text = ""
        mock_result.errors = ["Bad description"]

        with patch(
            "policyshield.ai.compiler.PolicyCompiler.compile",
            return_value=mock_result,
        ):
            resp = client.post(
                "/api/v1/compile-and-apply",
                json={"description": "garbage"},
            )
        assert resp.status_code == 200
        data = resp.json()
        assert data["applied"] is False
        assert len(data["errors"]) > 0
        # File unchanged
        assert tmp.read_text(encoding="utf-8") == original_content

    def test_compile_and_apply_no_rules_path(self):
        """Engine without rules_path returns error."""
        engine = AsyncShieldEngine(
            RuleSet(shield_name="t", version=1, rules=[])
        )
        app = create_app(engine)
        client = TestClient(app)

        mock_result = AsyncMock()
        mock_result.is_valid = True
        mock_result.yaml_text = "shield_name: x\nrules:\n  - id: r1\n    when:\n      tool: t\n    then: ALLOW\n"
        mock_result.errors = []

        with patch(
            "policyshield.ai.compiler.PolicyCompiler.compile",
            return_value=mock_result,
        ):
            resp = client.post(
                "/api/v1/compile-and-apply",
                json={"description": "test"},
            )
        assert resp.status_code == 200
        data = resp.json()
        assert data["applied"] is False
        assert any("rules file path" in e.lower() or "no rules" in e.lower() for e in data["errors"])


class TestCompileModels:
    """Test Pydantic model validation for compile models."""

    def test_compile_request_validation(self):
        req = CompileRequest(description="Block file deletions")
        assert req.description == "Block file deletions"

    def test_compile_request_min_length(self):
        with pytest.raises(Exception):
            CompileRequest(description="")


class TestStatusEndpoint:
    """Test GET /api/v1/status."""

    def test_status_response(self):
        engine = AsyncShieldEngine(
            RuleSet(shield_name="status-test", version=2, rules=[
                RuleConfig(id="r1", when={"tool": "t"}, then=Verdict.BLOCK),
            ])
        )
        app = create_app(engine)
        client = TestClient(app)

        resp = client.get("/api/v1/status")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "running"
        assert data["rules_count"] == 1

    def test_status_reflects_kill_switch(self):
        engine = AsyncShieldEngine(
            RuleSet(shield_name="t", version=1, rules=[])
        )
        app = create_app(engine)
        client = TestClient(app)

        # Kill
        client.post("/api/v1/kill", json={"reason": "test"})

        resp = client.get("/api/v1/status")
        data = resp.json()
        assert data["killed"] is True

        # Resume
        client.post("/api/v1/resume")
        resp = client.get("/api/v1/status")
        data = resp.json()
        assert data["killed"] is False
