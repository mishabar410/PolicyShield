# 534 — Integration Examples

## Goal

Add complete, runnable integration examples for popular frameworks.

## Context

- Current examples: `standalone_check.py`, `langchain_demo.py`, `crewai_demo.py`, `fastapi_middleware.py`
- Need: full project examples with README, requirements.txt, docker support
- Each example should be copy-pasteable and work out of the box

## Code

### New directories under `examples/`:

#### `examples/autogen_agent/`

AutoGen agent with PolicyShield integration:
- `agent.py` — AutoGen agent with tool guard
- `policies/rules.yaml` — rules for the agent
- `README.md` — setup instructions

#### `examples/langchain_agent/` (expand existing)

- Add `agent.py` with full ReAct agent + PolicyShield guard
- Add `README.md`

#### `examples/fastapi_service/`

Full FastAPI service with PolicyShield middleware:
- `main.py` — FastAPI app with PolicyShield check on each tool route
- `policies/rules.yaml`
- `requirements.txt`
- `README.md`

#### `examples/mcp_proxy/`

MCP proxy setup example:
- `config.json` — MCP client config pointing to PolicyShield proxy
- `rules.yaml`
- `README.md`

### Each example README follows template

```markdown
# Example: {Framework} + PolicyShield

## Setup
pip install policyshield[server]
...

## Run
python agent.py

## What happens
1. Agent tries to call `exec_command` → BLOCKED
2. Agent tries `read_file` → ALLOWED
3. Agent tries `write_file` → APPROVAL required
```

## Tests

- Validate each `rules.yaml` passes `policyshield validate`
- Check no import errors in example Python files

## Self-check

```bash
for d in examples/*/; do
  if [ -f "$d/policies/rules.yaml" ]; then
    policyshield validate "$d/policies/rules.yaml"
  fi
done
```

## Commit

```
feat(examples): add AutoGen, FastAPI service, and MCP proxy examples
```
