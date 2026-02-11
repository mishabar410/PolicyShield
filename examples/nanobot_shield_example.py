#!/usr/bin/env python3
"""PolicyShield + nanobot: Standalone ShieldedToolRegistry example.

This shows how to use ShieldedToolRegistry without a running nanobot
agent loop — useful for batch scripts, one-off checks, or testing.

Usage:
    python examples/nanobot_shield_example.py
"""

from __future__ import annotations

import asyncio

from policyshield.core.models import ShieldMode
from policyshield.integrations.nanobot.installer import install_shield
from policyshield.integrations.nanobot.registry import ShieldedToolRegistry


def main() -> None:
    # ── Create a shielded registry from a rules file ────────────────
    registry = install_shield(
        rules_path="examples/nanobot_rules.yaml",
        mode=ShieldMode.ENFORCE,
        fail_open=True,
    )
    assert isinstance(registry, ShieldedToolRegistry)

    # Register some simple tools (standalone mode)
    registry.register_func("echo", lambda message="": message)
    registry.register_func("exec", lambda command="": f"ran: {command}")
    registry.register_func(
        "send_message",
        lambda body="": f"sent: {body}",
    )

    # ── Test 1: Allowed call ────────────────────────────────────────
    print("--- Test 1: echo (allowed) ---")
    result = asyncio.run(registry.execute("echo", {"message": "hello world"}))
    print(f"  Result: {result}")
    assert result == "hello world"

    # ── Test 2: Blocked call (rm command) ───────────────────────────
    print("\n--- Test 2: exec with rm (blocked) ---")
    result = asyncio.run(registry.execute("exec", {"command": "rm -rf /"}))
    print(f"  Result: {result}")
    assert "BLOCKED" in result

    # ── Test 3: Redacted call ───────────────────────────────────────
    print("\n--- Test 3: send_message with PII (redacted) ---")
    result = asyncio.run(
        registry.execute("send_message", {"body": "Email: user@example.com"})
    )
    print(f"  Result: {result}")
    # PII should be redacted in args, but tool still executes
    assert "sent:" in result

    # ── Test 4: Allowed exec (no rm) ────────────────────────────────
    print("\n--- Test 4: exec with ls (allowed) ---")
    result = asyncio.run(registry.execute("exec", {"command": "ls -la /tmp"}))
    print(f"  Result: {result}")
    assert "ran:" in result

    # ── Test 5: Constraints summary ─────────────────────────────────
    print("\n--- Test 5: Constraints summary ---")
    summary = registry.get_constraints_summary()
    print(summary)
    assert "PolicyShield Constraints" in summary

    # ── Test 6: Blocked tools filtering ─────────────────────────────
    print("\n--- Test 6: Unconditionally blocked tools ---")
    blocked = registry._get_unconditionally_blocked_tools()
    print(f"  Blocked: {blocked}")
    # No unconditional blocks (all rules have args conditions)
    # exec rules have args.command.contains conditions

    print("\n✅ All tests passed!")


if __name__ == "__main__":
    main()
