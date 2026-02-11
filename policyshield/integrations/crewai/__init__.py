"""CrewAI integration for PolicyShield."""

try:
    from policyshield.integrations.crewai.wrapper import (
        CrewAIShieldTool,
        shield_all_crewai_tools,
    )
except ImportError:
    pass  # crewai not installed — imports will fail at usage time

__all__ = ["CrewAIShieldTool", "shield_all_crewai_tools"]
