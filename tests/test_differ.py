"""Tests for PolicyDiffer (Prompt 06)."""

from __future__ import annotations

from policyshield.core.models import RuleConfig, RuleSet, Severity, Verdict
from policyshield.lint.differ import PolicyDiffer


def _rule(**kwargs) -> RuleConfig:
    defaults = dict(id="r1", description="desc", then=Verdict.ALLOW, severity=Severity.LOW)
    defaults.update(kwargs)
    return RuleConfig(**defaults)


def _ruleset(*rules: RuleConfig) -> RuleSet:
    return RuleSet(shield_name="test", version=1, rules=list(rules))


# ── Test 1: identical ────────────────────────────────────────────────


def test_identical_rulesets():
    rs = _ruleset(_rule(id="a"), _rule(id="b"))
    d = PolicyDiffer.diff(rs, rs)
    assert not d.has_changes
    assert d.unchanged == 2


# ── Test 2: added rule ──────────────────────────────────────────────


def test_added_rule():
    old = _ruleset(_rule(id="a"))
    new = _ruleset(_rule(id="a"), _rule(id="b"))
    d = PolicyDiffer.diff(old, new)
    assert len(d.added) == 1
    assert d.added[0].id == "b"


# ── Test 3: removed rule ────────────────────────────────────────────


def test_removed_rule():
    old = _ruleset(_rule(id="a"), _rule(id="b"))
    new = _ruleset(_rule(id="a"))
    d = PolicyDiffer.diff(old, new)
    assert len(d.removed) == 1
    assert d.removed[0].id == "b"


# ── Test 4: modified verdict ────────────────────────────────────────


def test_modified_verdict():
    old = _ruleset(_rule(id="a", then=Verdict.ALLOW))
    new = _ruleset(_rule(id="a", then=Verdict.BLOCK))
    d = PolicyDiffer.diff(old, new)
    assert len(d.modified) == 1
    assert d.modified[0].rule_id == "a"
    assert any(c.field == "then" for c in d.modified[0].changes)


# ── Test 5: modified severity ───────────────────────────────────────


def test_modified_severity():
    old = _ruleset(_rule(id="a", severity=Severity.LOW))
    new = _ruleset(_rule(id="a", severity=Severity.HIGH))
    d = PolicyDiffer.diff(old, new)
    assert len(d.modified) == 1
    ch = [c for c in d.modified[0].changes if c.field == "severity"]
    assert len(ch) == 1
    assert ch[0].old_value == "LOW"
    assert ch[0].new_value == "HIGH"


# ── Test 6: modified when ───────────────────────────────────────────


def test_modified_when():
    old = _ruleset(_rule(id="a", when={"tool": "exec"}))
    new = _ruleset(_rule(id="a", when={"tool": "web_fetch"}))
    d = PolicyDiffer.diff(old, new)
    assert len(d.modified) == 1
    assert any(c.field == "when" for c in d.modified[0].changes)


# ── Test 7: modified message ────────────────────────────────────────


def test_modified_message():
    old = _ruleset(_rule(id="a", message="old msg"))
    new = _ruleset(_rule(id="a", message="new msg"))
    d = PolicyDiffer.diff(old, new)
    assert len(d.modified) == 1
    ch = [c for c in d.modified[0].changes if c.field == "message"]
    assert ch[0].old_value == "old msg"
    assert ch[0].new_value == "new msg"


# ── Test 8: modified enabled ────────────────────────────────────────


def test_modified_enabled():
    old = _ruleset(_rule(id="a", enabled=True))
    new = _ruleset(_rule(id="a", enabled=False))
    d = PolicyDiffer.diff(old, new)
    assert len(d.modified) == 1
    assert any(c.field == "enabled" for c in d.modified[0].changes)


# ── Test 9: multiple changes ────────────────────────────────────────


def test_multiple_changes():
    old = _ruleset(_rule(id="a", then=Verdict.ALLOW, severity=Severity.LOW, message="x"))
    new = _ruleset(_rule(id="a", then=Verdict.BLOCK, severity=Severity.HIGH, message="y"))
    d = PolicyDiffer.diff(old, new)
    assert len(d.modified) == 1
    assert len(d.modified[0].changes) == 3


# ── Test 10: complex diff ───────────────────────────────────────────


def test_complex_diff():
    old = _ruleset(
        _rule(id="a"),
        _rule(id="b", then=Verdict.ALLOW),
        _rule(id="c"),
    )
    new = _ruleset(
        _rule(id="a"),
        _rule(id="b", then=Verdict.BLOCK),
        _rule(id="d"),
    )
    d = PolicyDiffer.diff(old, new)
    assert d.unchanged == 1  # a
    assert len(d.removed) == 1  # c
    assert d.removed[0].id == "c"
    assert len(d.added) == 1  # d
    assert d.added[0].id == "d"
    assert len(d.modified) == 1  # b
    assert d.modified[0].rule_id == "b"


# ── Test 11: format_diff ────────────────────────────────────────────


def test_format_diff():
    old = _ruleset(_rule(id="a"), _rule(id="b", then=Verdict.ALLOW))
    new = _ruleset(_rule(id="b", then=Verdict.BLOCK), _rule(id="c"))
    d = PolicyDiffer.diff(old, new)

    text = PolicyDiffer.format_diff(d)
    assert "+ ADDED" in text
    assert "- REMOVED" in text
    assert "~ MODIFIED" in text
    assert "Summary" in text


# ── Test 12: diff_to_dict ───────────────────────────────────────────


def test_diff_to_dict():
    old = _ruleset(_rule(id="a"), _rule(id="b", then=Verdict.ALLOW))
    new = _ruleset(_rule(id="b", then=Verdict.BLOCK), _rule(id="c"))
    d = PolicyDiffer.diff(old, new)

    data = PolicyDiffer.diff_to_dict(d)
    assert "added" in data
    assert "removed" in data
    assert "modified" in data
    assert "unchanged" in data
    assert isinstance(data["added"], list)
    assert len(data["added"]) == 1
    assert data["added"][0]["id"] == "c"
