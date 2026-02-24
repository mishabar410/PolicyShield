# 532 — OpenAPI Schema Expansion

## Goal

Enhance the OpenAPI export with descriptions, examples, error schemas, and versioned API info.

## Context

- Current `policyshield openapi` outputs raw FastAPI schema
- Needs: richer descriptions, request/response examples, error types, security schemes
- Goal: publishable API documentation

## Code

### Modify: `policyshield/server/app.py`

Add to `create_app()`:

```python
app = FastAPI(
    title="PolicyShield",
    version=__version__,
    description="Declarative firewall for AI agent tool calls",
    openapi_tags=[
        {"name": "check", "description": "Tool call validation"},
        {"name": "admin", "description": "Kill switch, reload, approvals"},
        {"name": "observability", "description": "Health, metrics"},
    ],
)
```

### Modify: `policyshield/server/models.py`

Add `model_config` with JSON schema examples:

```python
class CheckRequest(BaseModel):
    model_config = ConfigDict(json_schema_extra={
        "examples": [{"tool_name": "exec_command", "args": {"cmd": "ls -la"}, "session_id": "sess-123"}]
    })
```

Add error response models:

```python
class ErrorResponse(BaseModel):
    error: str
    message: str
    request_id: str | None = None
```

### Tag all endpoints

```python
@app.post("/api/v1/check", tags=["check"], responses={415: {"model": ErrorResponse}, 422: {"model": ErrorResponse}})
```

## Tests

- Test OpenAPI schema includes tags
- Test examples present in schema
- Test error responses documented

## Self-check

```bash
policyshield openapi --rules examples/policyshield.yaml | python -c "import json,sys; s=json.load(sys.stdin); print(f'Tags: {len(s.get(\"tags\",[]))}, Paths: {len(s[\"paths\"])}')"
```

## Commit

```
feat: enrich OpenAPI schema with tags, examples, and error types
```
