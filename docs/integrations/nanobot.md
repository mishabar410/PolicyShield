# Nanobot Integration

## Installation

```bash
pip install "policyshield[nanobot]"
```

## CLI Usage

```bash
policyshield nanobot --rules policies/rules.yaml -- agent chat
```

## Options

```bash
policyshield nanobot \
  --rules policies/rules.yaml \
  --mode AUDIT \
  --fail-open \
  -- agent chat --model gpt-4
```

## Programmatic Usage

```python
from policyshield.integrations.nanobot import shield_agent_loop
from nanobot.agent.loop import AgentLoop

loop = AgentLoop(...)
shield_agent_loop(loop, rules_path="policies/rules.yaml")
```
