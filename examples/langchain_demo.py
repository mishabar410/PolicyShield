"""LangChain integration demo for PolicyShield.

Usage:
    pip install policyshield[langchain]
    python examples/langchain_demo.py
"""

from __future__ import annotations

from langchain_core.tools import BaseTool

from policyshield.core.models import RuleConfig, RuleSet, Verdict
from policyshield.integrations.langchain import PolicyShieldTool, shield_all_tools
from policyshield.shield.engine import ShieldEngine


# 1. Define a simple tool
class ShellTool(BaseTool):
    name: str = "exec"
    description: str = "Execute a shell command"

    def _run(self, command: str = "") -> str:
        return f"[SIMULATED] Executed: {command}"


class ReadFileTool(BaseTool):
    name: str = "read_file"
    description: str = "Read a file from disk"

    def _run(self, path: str = "") -> str:
        return f"[SIMULATED] Read: {path}"


# 2. Set up PolicyShield rules
rules = RuleSet(
    shield_name="langchain-demo",
    version=1,
    rules=[
        RuleConfig(
            id="block-dangerous-exec",
            when={"tool": "exec", "args_match": {"command": {"regex": r"rm\s+-rf"}}},
            then=Verdict.BLOCK,
            message="Destructive commands are forbidden",
        ),
    ],
)

engine = ShieldEngine(rules)


def main():
    # 3. Wrap individual tools
    shell = ShellTool()
    safe_shell = PolicyShieldTool(wrapped_tool=shell, engine=engine)

    print("=== Individual Wrapping ===")
    try:
        result = safe_shell._run(command="ls -la")
        print(f"✓ ls -la: {result}")
    except Exception as e:
        print(f"✗ ls -la: {e}")

    try:
        result = safe_shell._run(command="rm -rf /")
        print(f"✓ rm -rf /: {result}")
    except Exception as e:
        print(f"✗ rm -rf /: {e}")

    # 4. Wrap all tools at once
    print("\n=== Bulk Wrapping ===")
    tools = [ShellTool(), ReadFileTool()]
    safe_tools = shield_all_tools(tools, engine)

    for tool in safe_tools:
        print(f"  Protected: {tool.name} ({tool.description})")

    # safe read
    result = safe_tools[1]._run(path="/tmp/log.txt")
    print(f"✓ read_file: {result}")


if __name__ == "__main__":
    main()
