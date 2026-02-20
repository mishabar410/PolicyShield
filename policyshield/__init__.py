"""PolicyShield — Declarative firewall for AI agent tool calls."""

import sys

if sys.version_info < (3, 10):
    raise RuntimeError(
        f"PolicyShield requires Python 3.10+, but you're running {sys.version}. "
        "Please upgrade Python or use a virtual environment with 3.10+."
    )

__version__ = "0.11.0"

from policyshield.core.models import (  # noqa: E402, F401
    RuleConfig,
    RuleSet,
    ShieldMode,
    ShieldResult,
    Verdict,
)
from policyshield.shield.engine import ShieldEngine  # noqa: E402, F401
from policyshield.shield.async_engine import AsyncShieldEngine  # noqa: E402, F401

__all__ = [
    "__version__",
    "AsyncShieldEngine",
    "RuleConfig",
    "RuleSet",
    "ShieldEngine",
    "ShieldMode",
    "ShieldResult",
    "Verdict",
]
