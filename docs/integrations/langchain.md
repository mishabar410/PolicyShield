# LangChain Integration

## Installation

```bash
pip install "policyshield[langchain]"
```

## Usage

```python
from langchain.agents import AgentExecutor
from policyshield.integrations.langchain import PolicyShieldCallbackHandler

handler = PolicyShieldCallbackHandler.from_yaml("policies/rules.yaml")
agent = AgentExecutor(agent=..., tools=..., callbacks=[handler])
```

## Configuration

```python
handler = PolicyShieldCallbackHandler.from_yaml(
    "policies/rules.yaml",
    mode="ENFORCE",
    fail_open=True,
)
```
