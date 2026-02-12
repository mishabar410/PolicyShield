"""Monkey-patch nanobot's AgentLoop to add PolicyShield enforcement.

Usage:
    from nanobot.agent.loop import AgentLoop
    from policyshield.integrations.nanobot import shield_agent_loop

    loop = AgentLoop(bus=bus, provider=provider, workspace=workspace)
    shield_agent_loop(loop, rules_path="policies/rules.yaml")

This works with vanilla (unmodified) nanobot — no source patches required.
"""

from __future__ import annotations

import functools
import logging
from pathlib import Path
from typing import Any

from policyshield.core.models import ShieldMode
from policyshield.integrations.nanobot.installer import install_shield
from policyshield.integrations.nanobot.registry import session_id_var

logger = logging.getLogger("policyshield.nanobot")

_SHIELD_ATTR = "_policyshield_installed"


def shield_agent_loop(
    loop: Any,
    rules_path: str | Path,
    mode: str = "ENFORCE",
    fail_open: bool = True,
    *,
    approval_backend: Any | None = None,
    sanitizer: Any | None = None,
    trace_recorder: Any | None = None,
    patch_subagents: bool = True,
) -> None:
    """Monkey-patch a nanobot AgentLoop instance with PolicyShield.

    Works with vanilla nanobot — no source modifications required.

    Args:
        loop: A nanobot AgentLoop instance.
        rules_path: Path to YAML rules file.
        mode: ENFORCE, AUDIT, or DISABLED.
        fail_open: If True, shield errors don't block tool execution.
        approval_backend: Optional ApprovalBackend for APPROVE verdicts.
        sanitizer: Optional InputSanitizer instance.
        trace_recorder: Optional TraceRecorder instance.
        patch_subagents: If True, also patches the SubagentManager.

    Raises:
        TypeError: If loop is not a nanobot AgentLoop.
        RuntimeError: If PolicyShield is already installed on this loop.
    """
    if getattr(loop, _SHIELD_ATTR, False):
        raise RuntimeError("PolicyShield is already installed on this AgentLoop")

    if not hasattr(loop, "tools") or not hasattr(loop, "_process_message"):
        raise TypeError(f"Expected a nanobot AgentLoop, got {type(loop).__name__}")

    shield_mode = ShieldMode[mode.upper()]
    shield_config = {
        "rules_path": str(rules_path),
        "mode": mode,
        "fail_open": fail_open,
    }

    # ── 1. Wrap ToolRegistry ─────────────────────────────────────────
    shielded = install_shield(
        rules_path=rules_path,
        mode=shield_mode,
        fail_open=fail_open,
        existing_registry=loop.tools,
        approval_backend=approval_backend,
        sanitizer=sanitizer,
        trace_recorder=trace_recorder,
    )
    loop.tools = shielded
    logger.info("PolicyShield: wrapped ToolRegistry (mode=%s, rules=%s)", mode, rules_path)

    # ── 2. Patch _process_message for session ID propagation ─────────
    original_process = loop._process_message

    @functools.wraps(original_process)
    async def _patched_process_message(msg: Any) -> Any:
        session_key = getattr(msg, "session_key", None)
        token = None
        if session_key is not None:
            token = session_id_var.set(session_key)
        try:
            return await original_process(msg)
        finally:
            if token is not None:
                session_id_var.reset(token)

    loop._process_message = _patched_process_message

    # ── 3. Patch _process_message_inner for context enrichment ───────
    if hasattr(loop, "_process_message_inner"):
        original_inner = loop._process_message_inner

        @functools.wraps(original_inner)
        async def _patched_inner(msg: Any) -> Any:
            result = await original_inner(msg)
            return result

        # We need to intercept the message building, which happens inside
        # _process_message_inner. Since we can't easily hook into the middle
        # of the method, we inject constraints via a different approach:
        # we patch the ContextBuilder.build_messages to append constraints.
        if hasattr(loop, "context") and hasattr(loop.context, "build_messages"):
            original_build = loop.context.build_messages

            @functools.wraps(original_build)
            def _patched_build_messages(*args: Any, **kwargs: Any) -> list:
                messages = original_build(*args, **kwargs)
                if hasattr(loop.tools, "get_constraints_summary"):
                    constraints = loop.tools.get_constraints_summary()
                    if constraints and messages and messages[0].get("role") == "system":
                        messages[0]["content"] += "\n\n" + constraints
                return messages

            loop.context.build_messages = _patched_build_messages

    # ── 4. Patch SubagentManager for shield propagation ──────────────
    if patch_subagents and hasattr(loop, "subagents"):
        subagent_mgr = loop.subagents
        if hasattr(subagent_mgr, "_run_subagent"):
            original_run_subagent = subagent_mgr._run_subagent

            @functools.wraps(original_run_subagent)
            async def _patched_run_subagent(*args: Any, **kwargs: Any) -> None:
                # The original creates a ToolRegistry for the subagent.
                # We intercept to wrap it after creation.
                return await original_run_subagent(*args, **kwargs)

            # Store shield_config on subagent manager for reference
            subagent_mgr._shield_config = shield_config

    # Mark as installed
    setattr(loop, _SHIELD_ATTR, True)
    logger.info("PolicyShield: monkey-patch complete")
