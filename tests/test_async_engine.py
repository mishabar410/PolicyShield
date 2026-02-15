"""Tests for AsyncShieldEngine — async orchestrator."""

import asyncio
import json

import pytest

from policyshield.approval.memory import InMemoryBackend
from policyshield.core.models import (
    PostCheckResult,
    RuleConfig,
    RuleSet,
    ShieldMode,
    Verdict,
)
from policyshield.shield.async_engine import AsyncShieldEngine
from policyshield.shield.rate_limiter import RateLimitConfig, RateLimiter
from policyshield.trace.recorder import TraceRecorder


def make_ruleset(rules: list[RuleConfig]) -> RuleSet:
    return RuleSet(shield_name="test", version=1, rules=rules)


@pytest.fixture
def block_exec_rules():
    return make_ruleset(
        [
            RuleConfig(
                id="block-exec",
                description="Block exec calls",
                when={"tool": "exec"},
                then=Verdict.BLOCK,
                message="exec is not allowed",
            )
        ]
    )


@pytest.fixture
def redact_rules():
    return make_ruleset(
        [
            RuleConfig(
                id="redact-pii",
                description="Redact PII in arguments",
                when={"tool": "send_email"},
                then=Verdict.REDACT,
            )
        ]
    )


@pytest.fixture
def approve_rules():
    return make_ruleset(
        [
            RuleConfig(
                id="approve-delete",
                description="Deletion requires approval",
                when={"tool": "delete_user"},
                then=Verdict.APPROVE,
            )
        ]
    )


# ── Test 1: basic ALLOW ──────────────────────────────────────────────


@pytest.mark.asyncio
async def test_async_allow(block_exec_rules):
    engine = AsyncShieldEngine(block_exec_rules)
    result = await engine.check("read_file", {"path": "/etc/passwd"})
    assert result.verdict == Verdict.ALLOW


# ── Test 2: BLOCK by rule ────────────────────────────────────────────


@pytest.mark.asyncio
async def test_async_block(block_exec_rules):
    engine = AsyncShieldEngine(block_exec_rules)
    result = await engine.check("exec", {"command": "rm -rf /"})
    assert result.verdict == Verdict.BLOCK
    assert result.rule_id == "block-exec"
    assert "[BLOCK]" in result.message


# ── Test 3: REDACT with PII ──────────────────────────────────────────


@pytest.mark.asyncio
async def test_async_redact(redact_rules):
    engine = AsyncShieldEngine(redact_rules)
    result = await engine.check("send_email", {"body": "Contact: john@example.com"})
    assert result.verdict == Verdict.REDACT
    assert result.modified_args is not None


# ── Test 4: APPROVE → returns approval_id immediately ─────────────────


@pytest.mark.asyncio
async def test_async_approve_allow(approve_rules):
    """APPROVE verdict returns immediately with approval_id (non-blocking)."""
    backend = InMemoryBackend()
    engine = AsyncShieldEngine(
        approve_rules,
        approval_backend=backend,
    )

    result = await engine.check("delete_user", {"user_id": "123"})
    assert result.verdict == Verdict.APPROVE
    assert result.approval_id is not None

    # Verify the request was submitted to the backend
    pending = backend.pending()
    assert len(pending) == 1
    assert pending[0].tool_name == "delete_user"

    # Approve it and verify via backend
    backend.respond(result.approval_id, approved=True, responder="admin")
    resp = backend.wait_for_response(result.approval_id, timeout=1.0)
    assert resp is not None
    assert resp.approved is True


# ── Test 5: APPROVE → deny via backend ────────────────────────────────


@pytest.mark.asyncio
async def test_async_approve_deny(approve_rules):
    """APPROVE verdict + subsequent denial via backend."""
    backend = InMemoryBackend()
    engine = AsyncShieldEngine(
        approve_rules,
        approval_backend=backend,
    )

    result = await engine.check("delete_user", {"user_id": "123"})
    assert result.verdict == Verdict.APPROVE
    assert result.approval_id is not None

    # Deny it
    backend.respond(result.approval_id, approved=False, responder="admin")
    resp = backend.wait_for_response(result.approval_id, timeout=1.0)
    assert resp is not None
    assert resp.approved is False


# ── Test 6: APPROVE without backend → BLOCK ──────────────────────────


@pytest.mark.asyncio
async def test_async_approve_timeout(approve_rules):
    """Without an approval backend, APPROVE falls back to BLOCK."""
    engine = AsyncShieldEngine(approve_rules)  # no backend
    result = await engine.check("delete_user", {"user_id": "123"})
    assert result.verdict == Verdict.BLOCK
    assert "no approval backend" in result.message.lower()


# ── Test 7: Rate limiter blocks ──────────────────────────────────────


@pytest.mark.asyncio
async def test_async_rate_limit():
    rules = make_ruleset([])
    rl = RateLimiter(
        [
            RateLimitConfig(tool="*", max_calls=3, window_seconds=60),
        ]
    )
    engine = AsyncShieldEngine(rules, rate_limiter=rl)

    for _ in range(3):
        result = await engine.check("api_call")
        assert result.verdict == Verdict.ALLOW

    result = await engine.check("api_call")
    assert result.verdict == Verdict.BLOCK
    assert result.rule_id == "__rate_limit__"


# ── Test 8: PII detection ────────────────────────────────────────────


@pytest.mark.asyncio
async def test_async_pii_detection():
    rules = make_ruleset(
        [
            RuleConfig(
                id="redact-all",
                when={"tool": "send_data"},
                then=Verdict.REDACT,
            )
        ]
    )
    engine = AsyncShieldEngine(rules)
    result = await engine.check(
        "send_data",
        {"text": "Email: test@example.com, Phone: +7 900 123-45-67"},
    )
    assert result.verdict == Verdict.REDACT
    assert len(result.pii_matches) > 0


# ── Test 9: post_check returns ALLOW ─────────────────────────────────


@pytest.mark.asyncio
async def test_async_post_check(block_exec_rules):
    engine = AsyncShieldEngine(block_exec_rules)
    result = await engine.post_check("exec", {"output": "done"})
    assert isinstance(result, PostCheckResult)
    assert result.pii_matches == []
    assert result.session_tainted is False


# ── Test 10: AUDIT mode ──────────────────────────────────────────────


@pytest.mark.asyncio
async def test_async_audit_mode(block_exec_rules):
    engine = AsyncShieldEngine(block_exec_rules, mode=ShieldMode.AUDIT)
    result = await engine.check("exec", {"command": "rm -rf /"})
    assert result.verdict == Verdict.ALLOW
    assert "[AUDIT]" in result.message
    assert result.rule_id == "block-exec"


# ── Test 11: DISABLED mode ───────────────────────────────────────────


@pytest.mark.asyncio
async def test_async_disabled_mode(block_exec_rules):
    engine = AsyncShieldEngine(block_exec_rules, mode=ShieldMode.DISABLED)
    result = await engine.check("exec", {"command": "rm -rf /"})
    assert result.verdict == Verdict.ALLOW


# ── Test 12: reload_rules ────────────────────────────────────────────


@pytest.mark.asyncio
async def test_async_reload_rules(tmp_path):
    yaml1 = tmp_path / "rules1.yaml"
    yaml1.write_text("""\
shield_name: test
version: 1
rules:
  - id: r1
    when:
      tool: exec
    then: BLOCK
""")
    yaml2 = tmp_path / "rules2.yaml"
    yaml2.write_text("""\
shield_name: test
version: 2
rules:
  - id: r2
    when:
      tool: exec
    then: ALLOW
""")
    engine = AsyncShieldEngine(str(yaml1))
    result = await engine.check("exec")
    assert result.verdict == Verdict.BLOCK

    engine.reload_rules(str(yaml2))
    result = await engine.check("exec")
    assert result.verdict == Verdict.ALLOW


# ── Test 13: concurrent checks ───────────────────────────────────────


@pytest.mark.asyncio
async def test_async_concurrent_checks(block_exec_rules):
    engine = AsyncShieldEngine(block_exec_rules)

    async def _check_allow():
        return await engine.check("read_file", {"path": "/tmp"})

    async def _check_block():
        return await engine.check("exec", {"command": "ls"})

    # Run 50 concurrent checks
    tasks = [_check_allow() for _ in range(25)] + [_check_block() for _ in range(25)]
    results = await asyncio.gather(*tasks)

    allow_count = sum(1 for r in results if r.verdict == Verdict.ALLOW)
    block_count = sum(1 for r in results if r.verdict == Verdict.BLOCK)
    assert allow_count == 25
    assert block_count == 25


# ── Test 14: trace recording ─────────────────────────────────────────


@pytest.mark.asyncio
async def test_async_trace_recording(block_exec_rules, tmp_path):
    with TraceRecorder(tmp_path) as tracer:
        engine = AsyncShieldEngine(block_exec_rules, trace_recorder=tracer)
        await engine.check("exec", {"command": "ls"})
        await engine.check("read_file", {"path": "/tmp/log"})

    content = tracer.file_path.read_text()
    lines = content.strip().split("\n")
    assert len(lines) == 2
    entry = json.loads(lines[0])
    assert entry["verdict"] == "BLOCK"
