# FastAPI Agent Example

A minimal example of a FastAPI service with PolicyShield enforcement.

## Files

- `app.py` — FastAPI application with `/evaluate` and `/rules` endpoints
- `policies/rules.yaml` — Example security rules
- `policies/test_rules.yaml` — Test cases for the rules

## Running

```bash
pip install policyshield fastapi uvicorn
uvicorn examples.fastapi_agent.app:app --reload
```

## Endpoints

### `GET /health`
Health check.

### `POST /evaluate`
Evaluate a tool call against the policy rules.

```bash
curl -X POST http://localhost:8000/evaluate \
  -H "Content-Type: application/json" \
  -d '{"tool": "delete_file", "args": {"path": "/etc/passwd"}}'
```

### `GET /rules`
List loaded rules.
