# CrewAI Integration

## Installation

```bash
pip install "policyshield[crewai]"
```

## Usage

```python
from crewai import Agent
from policyshield.integrations.crewai import PolicyShieldGuardrail

guardrail = PolicyShieldGuardrail.from_yaml("policies/rules.yaml")
agent = Agent(
    role="Researcher",
    tools=[...],
    guardrails=[guardrail],
)
```
