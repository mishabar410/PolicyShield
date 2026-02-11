"""Installer helper for PolicyShield nanobot integration."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from policyshield.core.models import ShieldMode
from policyshield.integrations.nanobot.registry import ShieldedToolRegistry
from policyshield.shield.engine import ShieldEngine


def install_shield(
    rules_path: str | Path,
    mode: ShieldMode = ShieldMode.ENFORCE,
    fail_open: bool = True,
    *,
    existing_registry: Any | None = None,
    sanitizer: Any | None = None,
    trace_recorder: Any | None = None,
    approval_backend: Any | None = None,
) -> ShieldedToolRegistry:
    """Create a ShieldedToolRegistry with PolicyShield enforcement.

    Args:
        rules_path: Path to YAML rules file or directory.
        mode: Operating mode (ENFORCE / AUDIT / DISABLED).
        fail_open: If True, shield errors don't block tools.
        existing_registry: Optional existing nanobot ToolRegistry.
            If provided, all registered tools are copied over.
        sanitizer: Optional InputSanitizer instance.
        trace_recorder: Optional TraceRecorder instance.
        approval_backend: Optional ApprovalBackend for APPROVE verdicts.

    Returns:
        Configured ShieldedToolRegistry.
    """
    engine = ShieldEngine(
        rules=rules_path,
        mode=mode,
        fail_open=fail_open,
        sanitizer=sanitizer,
        trace_recorder=trace_recorder,
        approval_backend=approval_backend,
    )
    registry = ShieldedToolRegistry(engine=engine, fail_open=fail_open)

    # Copy tools from existing registry
    if existing_registry is not None:
        try:
            for name in existing_registry.tool_names:
                tool = existing_registry.get(name)
                if tool is not None:
                    registry.register(tool)
        except (AttributeError, TypeError):
            pass  # Incompatible registry, skip copy

    return registry
