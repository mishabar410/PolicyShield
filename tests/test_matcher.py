"""Tests for matcher engine."""


from policyshield.core.models import RuleConfig, RuleSet, Severity, Verdict
from policyshield.shield.matcher import CompiledRule, MatcherEngine


def make_ruleset(rules: list[RuleConfig]) -> RuleSet:
    return RuleSet(shield_name="test", version=1, rules=rules)


class TestCompiledRule:
    def test_from_simple_rule(self):
        rule = RuleConfig(id="r1", when={"tool": "exec"}, then=Verdict.BLOCK)
        compiled = CompiledRule.from_rule(rule)
        assert compiled.tool_pattern is not None
        assert compiled.tool_pattern.match("exec")
        assert not compiled.tool_pattern.match("read")

    def test_from_rule_with_args(self):
        rule = RuleConfig(
            id="r1",
            when={"tool": "exec", "args": {"command": {"predicate": "regex", "value": r"rm\s+-rf"}}},
            then=Verdict.BLOCK,
        )
        compiled = CompiledRule.from_rule(rule)
        assert len(compiled.arg_patterns) == 1

    def test_from_rule_no_when(self):
        rule = RuleConfig(id="r1", then=Verdict.ALLOW)
        compiled = CompiledRule.from_rule(rule)
        assert compiled.tool_pattern is None


class TestMatcherEngine:
    def test_simple_tool_match(self):
        rules = [RuleConfig(id="r1", when={"tool": "exec"}, then=Verdict.BLOCK)]
        engine = MatcherEngine(make_ruleset(rules))
        match = engine.find_best_match("exec")
        assert match is not None
        assert match.rule.then == Verdict.BLOCK

    def test_no_match(self):
        rules = [RuleConfig(id="r1", when={"tool": "exec"}, then=Verdict.BLOCK)]
        engine = MatcherEngine(make_ruleset(rules))
        match = engine.find_best_match("read_file")
        assert match is None

    def test_args_regex_match(self):
        rules = [
            RuleConfig(
                id="r1",
                when={"tool": "exec", "args": {"command": r"rm\s+-rf"}},
                then=Verdict.BLOCK,
            ),
        ]
        engine = MatcherEngine(make_ruleset(rules))
        assert engine.find_best_match("exec", {"command": "rm -rf /"}) is not None
        assert engine.find_best_match("exec", {"command": "ls"}) is None

    def test_most_restrictive_wins(self):
        rules = [
            RuleConfig(id="r1", when={"tool": "exec"}, then=Verdict.ALLOW),
            RuleConfig(id="r2", when={"tool": "exec"}, then=Verdict.BLOCK, severity=Severity.HIGH),
        ]
        engine = MatcherEngine(make_ruleset(rules))
        match = engine.find_best_match("exec")
        assert match is not None
        assert match.rule.then == Verdict.BLOCK
        assert match.rule.id == "r2"

    def test_disabled_rules_excluded(self):
        rules = [
            RuleConfig(id="r1", when={"tool": "exec"}, then=Verdict.BLOCK, enabled=False),
        ]
        engine = MatcherEngine(make_ruleset(rules))
        assert engine.find_best_match("exec") is None

    def test_wildcard_tool_pattern(self):
        rules = [RuleConfig(id="r1", when={"tool": ".*"}, then=Verdict.BLOCK)]
        engine = MatcherEngine(make_ruleset(rules))
        assert engine.find_best_match("anything") is not None
        assert engine.find_best_match("another_tool") is not None

    def test_session_condition(self):
        rules = [
            RuleConfig(
                id="rate-limit",
                when={"tool": "exec", "session": {"total_calls": {"gt": 10}}},
                then=Verdict.BLOCK,
            )
        ]
        engine = MatcherEngine(make_ruleset(rules))
        assert engine.find_best_match("exec", session_state={"total_calls": 5}) is None
        assert engine.find_best_match("exec", session_state={"total_calls": 11}) is not None

    def test_sender_match(self):
        rules = [
            RuleConfig(
                id="admin-only",
                when={"tool": "admin_panel", "sender": "admin"},
                then=Verdict.ALLOW,
            )
        ]
        engine = MatcherEngine(make_ruleset(rules))
        assert engine.find_best_match("admin_panel", sender="admin") is not None
        assert engine.find_best_match("admin_panel", sender="user") is None

    def test_find_all_matching_rules(self):
        rules = [
            RuleConfig(id="r1", when={"tool": "exec"}, then=Verdict.ALLOW),
            RuleConfig(id="r2", when={"tool": "exec"}, then=Verdict.BLOCK),
        ]
        engine = MatcherEngine(make_ruleset(rules))
        matches = engine.find_matching_rules("exec")
        assert len(matches) == 2

    def test_rule_count(self):
        rules = [
            RuleConfig(id="r1", when={"tool": "exec"}, then=Verdict.BLOCK),
            RuleConfig(id="r2", when={"tool": "read"}, then=Verdict.ALLOW),
            RuleConfig(id="r3", when={"tool": "write"}, then=Verdict.APPROVE, enabled=False),
        ]
        engine = MatcherEngine(make_ruleset(rules))
        assert engine.rule_count == 2  # r3 is disabled

    def test_args_eq_predicate(self):
        rules = [
            RuleConfig(
                id="r1",
                when={"tool": "set_config", "args": {"key": {"predicate": "eq", "value": "dangerous"}}},
                then=Verdict.BLOCK,
            )
        ]
        engine = MatcherEngine(make_ruleset(rules))
        assert engine.find_best_match("set_config", {"key": "dangerous"}) is not None
        assert engine.find_best_match("set_config", {"key": "safe"}) is None

    def test_args_missing_field(self):
        rules = [
            RuleConfig(
                id="r1",
                when={"tool": "exec", "args": {"command": r"rm"}},
                then=Verdict.BLOCK,
            )
        ]
        engine = MatcherEngine(make_ruleset(rules))
        assert engine.find_best_match("exec", {}) is None
