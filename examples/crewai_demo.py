"""Example: using PolicyShield with CrewAI agents.

Wrap any CrewAI tool with PolicyShield to enforce security policies
before agent tool calls execute.
"""

from __future__ import annotations


def policyshield_guard(tool_name: str, args: dict) -> dict:
    """Check tool call against PolicyShield rules.

    Returns the check result with verdict, or raises if blocked.
    """
    from policyshield import ShieldEngine

    engine = ShieldEngine(rules="policies/rules.yaml")
    result = engine.check(tool_name, args)

    if result.verdict.value == "BLOCK":
        raise PermissionError(f"PolicyShield blocked {tool_name}: {result.message}")

    if result.modified_args:
        return result.modified_args
    return args


# Usage with CrewAI:
#
# from crewai import Agent, Task, Crew
# from crewai_tools import SerperSearchTool
#
# search = SerperSearchTool()
#
# # Wrap tool before passing to agent
# original_run = search._run
# def guarded_run(**kwargs):
#     safe_args = policyshield_guard("search_internet", kwargs)
#     return original_run(**safe_args)
# search._run = guarded_run
#
# agent = Agent(
#     role="Researcher",
#     tools=[search],
#     ...
# )

if __name__ == "__main__":
    # Quick demo without CrewAI dependency
    from policyshield import ShieldEngine

    engine = ShieldEngine(rules="examples/policyshield.yaml")
    result = engine.check("search_internet", {"query": "AI safety research"})
    print(f"Verdict: {result.verdict.value}")
    print(f"Message: {result.message}")
