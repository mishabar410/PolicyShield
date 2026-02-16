from policyshield.replay.loader import TraceEntry
from policyshield.replay.engine import ReplayEngine, ChangeType, _classify_change
from policyshield.core.models import RuleSet, RuleConfig, Verdict


def _make_ruleset(rules, default=Verdict.ALLOW):
    return RuleSet(shield_name="test", version="1", rules=rules, default_verdict=default)


def test_replay_unchanged():
    rules = _make_ruleset(
        [
            RuleConfig(id="r1", when={"tool": "read_file"}, then=Verdict.ALLOW),
        ]
    )
    engine = ReplayEngine(rules)
    entry = TraceEntry(timestamp="2026-01-01T00:00:00+00:00", session_id="s1", tool="read_file", verdict="allow")
    result = engine.replay_one(entry)
    assert not result.changed
    assert result.change_type == ChangeType.UNCHANGED


def test_replay_tightened():
    rules = _make_ruleset(
        [
            RuleConfig(id="r1", when={"tool": "read_file"}, then=Verdict.BLOCK),
        ]
    )
    engine = ReplayEngine(rules)
    entry = TraceEntry(timestamp="2026-01-01T00:00:00+00:00", session_id="s1", tool="read_file", verdict="allow")
    result = engine.replay_one(entry)
    assert result.changed
    assert result.change_type == ChangeType.TIGHTENED
    assert result.new_verdict == "BLOCK"


def test_replay_relaxed():
    rules = _make_ruleset(
        [
            RuleConfig(id="r1", when={"tool": "delete_file"}, then=Verdict.ALLOW),
        ]
    )
    engine = ReplayEngine(rules)
    entry = TraceEntry(timestamp="2026-01-01T00:00:00+00:00", session_id="s1", tool="delete_file", verdict="block")
    result = engine.replay_one(entry)
    assert result.changed
    assert result.change_type == ChangeType.RELAXED


def test_replay_all_with_summary():
    rules = _make_ruleset(
        [
            RuleConfig(id="r1", when={"tool": "read_file"}, then=Verdict.ALLOW),
            RuleConfig(id="r2", when={"tool": "delete_file"}, then=Verdict.BLOCK),
        ]
    )
    engine = ReplayEngine(rules)
    entries = [
        TraceEntry(timestamp="2026-01-01T00:00:00+00:00", session_id="s1", tool="read_file", verdict="allow"),
        TraceEntry(timestamp="2026-01-01T00:01:00+00:00", session_id="s1", tool="delete_file", verdict="allow"),
    ]
    results = engine.replay_all(entries)
    summary = engine.summary(results)
    assert summary["total"] == 2
    assert summary["unchanged"] == 1
    assert summary["tightened"] == 1


def test_default_verdict_used_when_no_match():
    rules = _make_ruleset([], default=Verdict.BLOCK)
    engine = ReplayEngine(rules)
    entry = TraceEntry(timestamp="2026-01-01T00:00:00+00:00", session_id="s1", tool="unknown", verdict="allow")
    result = engine.replay_one(entry)
    assert result.new_verdict == "BLOCK"
    assert result.change_type == ChangeType.TIGHTENED


def test_classify_change():
    assert _classify_change("allow", "allow") == ChangeType.UNCHANGED
    assert _classify_change("allow", "block") == ChangeType.TIGHTENED
    assert _classify_change("block", "allow") == ChangeType.RELAXED
