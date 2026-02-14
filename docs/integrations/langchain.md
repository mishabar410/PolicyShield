# LangChain Integration

## Installation

```bash
pip install "policyshield[langchain]"
```

## Usage

Wrap individual tools with `PolicyShieldTool`:

```python
from policyshield.shield.engine import ShieldEngine
from policyshield.integrations.langchain import PolicyShieldTool, shield_all_tools

engine = ShieldEngine(rules="policies/rules.yaml")

# Wrap a single tool
safe_tool = PolicyShieldTool(wrapped_tool=my_tool, engine=engine)

# Or wrap all tools at once
safe_tools = shield_all_tools([tool1, tool2, tool3], engine)
```

Use with an agent:

```python
from langchain.agents import AgentExecutor

agent = AgentExecutor(agent=my_agent, tools=safe_tools)
result = agent.invoke({"input": "Delete all files"})
# PolicyShield will block destructive tool calls based on your rules
```
