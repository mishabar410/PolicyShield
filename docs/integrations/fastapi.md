# HTTP Server / FastAPI

PolicyShield includes a built-in HTTP server for policy enforcement. This is the recommended way to integrate with non-Python frameworks (e.g., OpenClaw, TypeScript agents).

## Starting the server

```bash
pip install "policyshield[server]"
policyshield server --rules ./rules.yaml --port 8100 --mode enforce
```

## Endpoints

### POST `/api/v1/check`

Pre-call policy check. Returns ALLOW, BLOCK, REDACT, or APPROVE.

```bash
curl -X POST http://localhost:8100/api/v1/check \
  -H "Content-Type: application/json" \
  -d '{
    "tool": "exec",
    "args": {"command": "rm -rf /"},
    "session_id": "session-1"
  }'
```

Response:

```json
{
  "verdict": "BLOCK",
  "message": "Destructive shell command blocked",
  "rule_id": "no-destructive-shell"
}
```

### POST `/api/v1/post-check`

Post-call PII scanning on tool output.

```bash
curl -X POST http://localhost:8100/api/v1/post-check \
  -H "Content-Type: application/json" \
  -d '{
    "tool": "web_fetch",
    "output": "Found email: john@corp.com and SSN: 123-45-6789"
  }'
```

### GET `/api/v1/health`

Health check with rules count and mode.

```bash
curl http://localhost:8100/api/v1/health
```

### GET `/api/v1/constraints`

Human-readable policy summary, useful for injecting into LLM system prompts.

```bash
curl http://localhost:8100/api/v1/constraints
```

## Docker

```bash
docker build -f Dockerfile.server -t policyshield-server .
docker run -p 8100:8100 -v ./rules.yaml:/app/rules.yaml policyshield-server
```

## Custom FastAPI usage

You can also use the ShieldEngine directly in your own FastAPI app:

```python
from fastapi import FastAPI, HTTPException
from policyshield.shield.engine import ShieldEngine

app = FastAPI()
engine = ShieldEngine(rules="policies/rules.yaml")

@app.post("/agent/tool-call")
async def tool_call(request: dict):
    result = engine.check(
        tool_name=request["tool"],
        args=request.get("args", {}),
    )
    if result.verdict.value == "BLOCK":
        raise HTTPException(403, result.message)
    return {"verdict": result.verdict.value, "args": result.modified_args or request.get("args")}
```
