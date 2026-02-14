"""Tests for ApprovalCache with batch approve strategies."""

from __future__ import annotations


from policyshield.approval.base import ApprovalResponse
from policyshield.approval.cache import ApprovalCache, ApprovalStrategy
from policyshield.approval.memory import InMemoryBackend
from policyshield.core.models import RuleConfig, RuleSet, Verdict
from policyshield.shield.engine import ShieldEngine


def _approved(request_id: str = "r1") -> ApprovalResponse:
    return ApprovalResponse(request_id=request_id, approved=True, responder="admin")


def _denied(request_id: str = "r1") -> ApprovalResponse:
    return ApprovalResponse(request_id=request_id, approved=False, responder="admin")


class TestApprovalCacheUnit:
    """Unit tests for ApprovalCache key generation and strategies."""

    def test_cache_miss_returns_none(self):
        cache = ApprovalCache()
        assert cache.get("exec", "rule-1", "s1") is None

    def test_cache_hit_returns_response(self):
        cache = ApprovalCache(strategy=ApprovalStrategy.PER_RULE)
        cache.put("exec", "rule-1", "s1", _approved())
        resp = cache.get("exec", "rule-1", "s2")
        assert resp is not None
        assert resp.approved is True

    def test_strategy_per_session_same_session(self):
        cache = ApprovalCache(strategy=ApprovalStrategy.PER_SESSION)
        cache.put("exec", "rule-1", "s1", _approved())
        # Same session -> hit
        assert cache.get("exec", "rule-1", "s1") is not None

    def test_strategy_per_session_diff_session(self):
        cache = ApprovalCache(strategy=ApprovalStrategy.PER_SESSION)
        cache.put("exec", "rule-1", "s1", _approved())
        # Different session -> miss
        assert cache.get("exec", "rule-1", "s2") is None

    def test_strategy_per_rule_global(self):
        cache = ApprovalCache(strategy=ApprovalStrategy.PER_RULE)
        cache.put("exec", "rule-1", "s1", _approved())
        # Different session, different tool -> still hit because per_rule is global
        resp = cache.get("read", "rule-1", "s99")
        assert resp is not None

    def test_strategy_per_tool_same_tool(self):
        cache = ApprovalCache(strategy=ApprovalStrategy.PER_TOOL)
        cache.put("exec", "rule-1", "s1", _approved())
        # Same tool, same session, different rule -> hit
        resp = cache.get("exec", "rule-2", "s1")
        assert resp is not None

    def test_strategy_per_tool_diff_session(self):
        cache = ApprovalCache(strategy=ApprovalStrategy.PER_TOOL)
        cache.put("exec", "rule-1", "s1", _approved())
        # Different session -> miss
        assert cache.get("exec", "rule-1", "s2") is None

    def test_strategy_once_no_cache(self):
        cache = ApprovalCache(strategy=ApprovalStrategy.ONCE)
        cache.put("exec", "rule-1", "s1", _approved())
        # ONCE never caches
        assert cache.get("exec", "rule-1", "s1") is None

    def test_clear_session(self):
        cache = ApprovalCache(strategy=ApprovalStrategy.PER_SESSION)
        cache.put("exec", "rule-1", "s1", _approved())
        cache.put("exec", "rule-1", "s2", _approved())
        cache.clear(session_id="s1")
        assert cache.get("exec", "rule-1", "s1") is None
        assert cache.get("exec", "rule-1", "s2") is not None

    def test_clear_all(self):
        cache = ApprovalCache(strategy=ApprovalStrategy.PER_SESSION)
        cache.put("exec", "rule-1", "s1", _approved())
        cache.put("exec", "rule-1", "s2", _approved())
        cache.clear()
        assert cache.get("exec", "rule-1", "s1") is None
        assert cache.get("exec", "rule-1", "s2") is None

    def test_override_strategy_per_call(self):
        cache = ApprovalCache(strategy=ApprovalStrategy.PER_RULE)
        cache.put("exec", "rule-1", "s1", _approved(), strategy=ApprovalStrategy.PER_SESSION)
        # Get with PER_RULE -> miss (was stored with PER_SESSION key)
        assert cache.get("exec", "rule-1", "s1", strategy=ApprovalStrategy.PER_RULE) is None
        # Get with PER_SESSION -> hit
        assert cache.get("exec", "rule-1", "s1", strategy=ApprovalStrategy.PER_SESSION) is not None


class TestApprovalCacheEngineIntegration:
    """Integration tests with ShieldEngine."""

    def _make_engine(self, strategy: ApprovalStrategy = ApprovalStrategy.PER_RULE) -> tuple:
        rules = RuleSet(
            shield_name="test",
            version=1,
            rules=[
                RuleConfig(
                    id="approve-exec",
                    when={"tool": "exec"},
                    then=Verdict.APPROVE,
                    approval_strategy=strategy.value,
                )
            ],
        )
        backend = InMemoryBackend()
        cache = ApprovalCache(strategy=strategy)
        engine = ShieldEngine(rules, approval_backend=backend, approval_cache=cache)
        return engine, backend

    def test_engine_batch_approve_integration(self):
        engine, backend = self._make_engine(ApprovalStrategy.PER_RULE)
        # First call: returns APPROVE with approval_id for async polling
        result1 = engine.check("exec", {"cmd": "ls"})
        assert result1.verdict == Verdict.APPROVE
        assert result1.approval_id is not None

        # Simulate approval response
        backend.respond(result1.approval_id, approved=True)
        status = engine.get_approval_status(result1.approval_id)
        assert status["status"] == "approved"

        # Manually populate the cache (simulating what the client layer does after polling)
        from policyshield.approval.base import ApprovalResponse

        cache_resp = ApprovalResponse(request_id=result1.approval_id, approved=True)
        engine._approval_cache.put("exec", "approve-exec", "default", cache_resp, strategy=ApprovalStrategy.PER_RULE)

        # Second call: auto-approved from cache
        result2 = engine.check("exec", {"cmd": "ls"})
        assert result2.verdict == Verdict.ALLOW

    def test_engine_once_strategy_no_cache(self):
        engine, backend = self._make_engine(ApprovalStrategy.ONCE)
        # Each call requires actual approval (ONCE strategy never caches)
        result1 = engine.check("exec", {"cmd": "ls"})
        assert result1.verdict == Verdict.APPROVE
        assert result1.approval_id is not None

        # Second call: should also return APPROVE (ONCE strategy)
        result2 = engine.check("exec", {"cmd": "ls"})
        assert result2.verdict == Verdict.APPROVE
        assert result2.approval_id is not None
        # Different approval_id each time
        assert result2.approval_id != result1.approval_id
