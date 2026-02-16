"""Tests for chain matcher — prompt 106."""

from policyshield.core.models import RuleConfig, RuleSet, Verdict
from policyshield.shield.matcher import MatcherEngine
from policyshield.shield.ring_buffer import EventRingBuffer


def _make_ruleset(rules, default=Verdict.ALLOW):
    return RuleSet(shield_name="test", version=1, rules=rules, default_verdict=default)


def test_chain_matches_with_history():
    """Chain rule should match when prerequisite is in the buffer."""
    rule = RuleConfig(
        id="exfil",
        when={"tool": "send_email"},
        then=Verdict.BLOCK,
        chain=[{"tool": "read_file", "within_seconds": 300}],
    )
    rs = _make_ruleset([rule])
    engine = MatcherEngine(rs)

    buf = EventRingBuffer()
    buf.add("read_file", "ALLOW")

    match = engine.find_best_match("send_email", event_buffer=buf)
    assert match is not None
    assert match.rule.id == "exfil"


def test_chain_no_match_without_history():
    """Chain rule should NOT match when buffer is empty."""
    rule = RuleConfig(
        id="exfil",
        when={"tool": "send_email"},
        then=Verdict.BLOCK,
        chain=[{"tool": "read_file", "within_seconds": 300}],
    )
    rs = _make_ruleset([rule])
    engine = MatcherEngine(rs)

    buf = EventRingBuffer()
    match = engine.find_best_match("send_email", event_buffer=buf)
    assert match is None


def test_chain_no_match_without_buffer():
    """Chain rule should NOT match when no buffer is provided."""
    rule = RuleConfig(
        id="exfil",
        when={"tool": "send_email"},
        then=Verdict.BLOCK,
        chain=[{"tool": "read_file", "within_seconds": 300}],
    )
    rs = _make_ruleset([rule])
    engine = MatcherEngine(rs)

    match = engine.find_best_match("send_email")
    assert match is None


def test_chain_multi_step():
    """Multi-step chain: all prerequisites must be met."""
    rule = RuleConfig(
        id="multi",
        when={"tool": "send_email"},
        then=Verdict.BLOCK,
        chain=[
            {"tool": "read_file", "within_seconds": 300},
            {"tool": "query_db", "within_seconds": 300},
        ],
    )
    rs = _make_ruleset([rule])
    engine = MatcherEngine(rs)

    # Only read_file present — no match
    buf = EventRingBuffer()
    buf.add("read_file", "ALLOW")
    assert engine.find_best_match("send_email", event_buffer=buf) is None

    # Both present — match
    buf.add("query_db", "ALLOW")
    match = engine.find_best_match("send_email", event_buffer=buf)
    assert match is not None
    assert match.rule.id == "multi"


def test_chain_min_count():
    """Chain requires min_count events."""
    rule = RuleConfig(
        id="min-count",
        when={"tool": "send_email"},
        then=Verdict.BLOCK,
        chain=[{"tool": "read_file", "within_seconds": 300, "min_count": 3}],
    )
    rs = _make_ruleset([rule])
    engine = MatcherEngine(rs)

    buf = EventRingBuffer()
    buf.add("read_file", "ALLOW")
    buf.add("read_file", "ALLOW")
    assert engine.find_best_match("send_email", event_buffer=buf) is None

    buf.add("read_file", "ALLOW")
    assert engine.find_best_match("send_email", event_buffer=buf) is not None


def test_chain_verdict_filter():
    """Chain matches only events with specific verdict."""
    rule = RuleConfig(
        id="blocked-retry",
        when={"tool": "send_email"},
        then=Verdict.BLOCK,
        chain=[{"tool": "send_email", "verdict": "BLOCK", "within_seconds": 300}],
    )
    rs = _make_ruleset([rule])
    engine = MatcherEngine(rs)

    buf = EventRingBuffer()
    buf.add("send_email", "ALLOW")  # Wrong verdict
    assert engine.find_best_match("send_email", event_buffer=buf) is None

    buf.add("send_email", "BLOCK")  # Correct verdict
    assert engine.find_best_match("send_email", event_buffer=buf) is not None


def test_non_chain_rule_unaffected():
    """Regular rules (no chain) should still work normally."""
    rule = RuleConfig(
        id="simple",
        when={"tool": "dangerous_tool"},
        then=Verdict.BLOCK,
    )
    rs = _make_ruleset([rule])
    engine = MatcherEngine(rs)

    # Without event buffer — should still match
    match = engine.find_best_match("dangerous_tool")
    assert match is not None
    assert match.rule.id == "simple"

    # With event buffer — should still match
    buf = EventRingBuffer()
    match = engine.find_best_match("dangerous_tool", event_buffer=buf)
    assert match is not None
