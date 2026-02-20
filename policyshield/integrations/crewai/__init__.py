"""CrewAI integration for PolicyShield."""

try:
    from policyshield.integrations.crewai.wrapper import (
        CrewAIShieldTool,
        shield_all_crewai_tools,
    )

    __all__ = ["CrewAIShieldTool", "shield_all_crewai_tools"]
except ImportError:
    __all__ = ["CrewAIShieldTool", "shield_all_crewai_tools"]

    def __getattr__(name: str):  # type: ignore[misc]
        if name in __all__:
            raise ImportError(
                f"Cannot import '{name}' — crewai is not installed. "
                "Install it with: pip install crewai"
            )
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
