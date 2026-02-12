"""Nanobot integration for PolicyShield."""

from policyshield.integrations.nanobot.context import session_id_var
from policyshield.integrations.nanobot.installer import install_shield
from policyshield.integrations.nanobot.monkey_patch import shield_agent_loop
from policyshield.integrations.nanobot.registry import PolicyViolation, ShieldedToolRegistry

# Lazy import to avoid import error when nanobot is not installed
try:
    from policyshield.integrations.nanobot.cli_wrapper import patch_agent_loop_class
except ImportError:
    patch_agent_loop_class = None  # type: ignore[assignment, misc]

__all__ = [
    "PolicyViolation",
    "ShieldedToolRegistry",
    "install_shield",
    "patch_agent_loop_class",
    "session_id_var",
    "shield_agent_loop",
]
