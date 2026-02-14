# CrewAI Integration

## Installation

```bash
pip install "policyshield[crewai]"
```

## Usage

Wrap CrewAI tools with PolicyShield enforcement:

```python
from policyshield.shield.engine import ShieldEngine
from policyshield.integrations.crewai import shield_all_crewai_tools

engine = ShieldEngine(rules="policies/rules.yaml")

# Wrap all tools at once
safe_tools = shield_all_crewai_tools([tool1, tool2], engine)

# Use with CrewAI agent
from crewai import Agent

agent = Agent(
    role="Researcher",
    tools=safe_tools,
)
```
