"""CLI wrapper for running nanobot with PolicyShield enforcement.

Provides class-level monkey-patching of AgentLoop.__init__ and
a helper to invoke nanobot's CLI with custom arguments.
"""

from __future__ import annotations

import functools
import sys
from typing import Any


def patch_agent_loop_class(
    rules_path: str,
    mode: str = "ENFORCE",
    fail_open: bool = True,
) -> Any:
    """Monkey-patch AgentLoop.__init__ at the class level.

    After this call, every new AgentLoop() instance will automatically
    be shielded with PolicyShield.

    Args:
        rules_path: Path to YAML rules file.
        mode: Enforcement mode (ENFORCE, AUDIT, DISABLED).
        fail_open: Whether to allow calls when shielding fails.

    Returns:
        The original ``AgentLoop.__init__`` (for restoration in tests).

    Raises:
        ImportError: If nanobot is not installed.
    """
    from nanobot.agent.loop import AgentLoop  # type: ignore[import-untyped]
    from policyshield.integrations.nanobot.monkey_patch import shield_agent_loop

    original_init = AgentLoop.__init__

    @functools.wraps(original_init)
    def patched_init(self: Any, *args: Any, **kwargs: Any) -> None:
        original_init(self, *args, **kwargs)
        try:
            shield_agent_loop(
                self,
                rules_path=rules_path,
                mode=mode,
                fail_open=fail_open,
            )
        except RuntimeError:
            # Already shielded (e.g. subagent inheriting from parent)
            pass

    AgentLoop.__init__ = patched_init  # type: ignore[method-assign]
    return original_init


def run_nanobot_cli(nanobot_args: list[str]) -> int:
    """Invoke nanobot's CLI with the given arguments.

    Args:
        nanobot_args: Arguments to forward to nanobot CLI.

    Returns:
        Exit code from the nanobot CLI.

    Raises:
        ImportError: If nanobot is not installed.
    """
    from nanobot.cli.commands import app as nanobot_app  # type: ignore[import-untyped]

    sys.argv = ["nanobot"] + nanobot_args
    try:
        nanobot_app(standalone_mode=False)
        return 0
    except SystemExit as e:
        return e.code if isinstance(e.code, int) else 0
