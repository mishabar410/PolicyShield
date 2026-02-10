"""Installer helper for PolicyShield nanobot integration."""

from __future__ import annotations

from pathlib import Path

from policyshield.core.models import ShieldMode
from policyshield.integrations.nanobot.registry import ShieldedToolRegistry
from policyshield.shield.engine import ShieldEngine


def install_shield(
    rules_path: str | Path,
    mode: ShieldMode = ShieldMode.ENFORCE,
    fail_open: bool = True,
) -> ShieldedToolRegistry:
    """Create and configure a ShieldedToolRegistry.

    Args:
        rules_path: Path to YAML rules file or directory.
        mode: Operating mode.
        fail_open: If True, shield errors don't block tools.

    Returns:
        Configured ShieldedToolRegistry.
    """
    engine = ShieldEngine(
        rules=rules_path,
        mode=mode,
        fail_open=fail_open,
    )
    return ShieldedToolRegistry(engine=engine, fail_open=fail_open)
