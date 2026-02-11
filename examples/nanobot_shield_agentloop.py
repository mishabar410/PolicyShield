#!/usr/bin/env python3
"""PolicyShield + nanobot AgentLoop integration example.

Shows how to configure an AgentLoop with PolicyShield enforcement.
This is the recommended approach for production deployments.

Usage:
    # This is a reference example - requires a running nanobot environment
    # with an LLM provider configured.
    python examples/nanobot_shield_agentloop.py
"""

from __future__ import annotations

# NOTE: This example requires nanobot and its dependencies to be installed.
# It demonstrates the API — running it requires a configured LLM provider.


def show_agentloop_config() -> None:
    """Print the AgentLoop configuration for PolicyShield."""

    print("=" * 60)
    print("PolicyShield + nanobot AgentLoop Integration")
    print("=" * 60)
    print()
    print("To enable PolicyShield in an AgentLoop, pass shield_config:")
    print()
    print("""
    from nanobot.agent.loop import AgentLoop

    loop = AgentLoop(
        bus=bus,
        provider=provider,
        workspace=workspace,
        shield_config={
            "rules_path": "path/to/rules.yaml",
            "mode": "ENFORCE",        # ENFORCE | AUDIT | DISABLED
            "fail_open": True,        # True = errors don't block calls
        },
    )
    """)
    print("This will:")
    print("  1. Create a ShieldEngine from your rules.yaml")
    print("  2. Wrap the ToolRegistry with ShieldedToolRegistry")
    print("  3. Propagate session IDs for rate limiting")
    print("  4. Inject policy constraints into the LLM system prompt")
    print("  5. Filter blocked tools from LLM definitions")
    print("  6. Scan tool results for PII (post-call)")
    print()
    print("Example rules.yaml:")
    print()
    print("""
    shield_name: my-agent
    version: 1
    rules:
      - id: block-destructive
        description: Block destructive shell commands
        when:
          tool: exec
          args:
            command:
              contains: "rm "
        then: BLOCK
        message: Destructive commands are not allowed

      - id: redact-messages
        description: Redact PII from outgoing messages
        when:
          tool: send_message
        then: REDACT
    """)
    print()
    print("For standalone testing (no LLM required), see:")
    print("  examples/nanobot_shield_example.py")
    print()
    print("✅ Configuration reference complete!")


if __name__ == "__main__":
    show_agentloop_config()
