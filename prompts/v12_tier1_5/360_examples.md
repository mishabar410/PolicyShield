# Prompt 360 — Integration Examples

## Цель

Написать 3 runnable примера интеграции: standalone, FastAPI middleware, OpenClaw plugin.

## Контекст

- Нет примеров → разработчики не понимают как интегрировать
- Нужно: `examples/` директория с самодостаточными файлами

## Что сделать

### 1. `examples/standalone_check.py`

```python
"""Standalone check — simplest usage."""
from policyshield.shield.sync_engine import ShieldEngine

engine = ShieldEngine(rules="rules.yaml")
result = engine.check("send_email", {"to": "user@example.com", "body": "Hello"})
print(f"Verdict: {result.verdict.value}")
print(f"Message: {result.message}")
```

### 2. `examples/fastapi_middleware.py`

```python
"""FastAPI middleware integration example."""
from fastapi import FastAPI, Request
from policyshield.client import PolicyShieldClient

app = FastAPI()
shield = PolicyShieldClient(base_url="http://localhost:8000/api/v1")

@app.middleware("http")
async def policy_check(request: Request, call_next):
    # Check tool calls through PolicyShield
    result = shield.check(request.url.path, dict(request.query_params))
    if result.verdict == "BLOCK":
        return JSONResponse(status_code=403, content={"error": "blocked"})
    return await call_next(request)
```

### 3. `examples/docker-compose.yaml`

```yaml
services:
  policyshield:
    image: python:3.12-slim
    command: policyshield serve --host 0.0.0.0
    ports: ["8000:8000"]
    volumes: ["./rules.yaml:/app/rules.yaml"]
    environment:
      POLICYSHIELD_API_TOKEN: ${API_TOKEN}
```

## Тесты

```python
class TestExamples:
    @pytest.mark.parametrize("example", ["standalone_check.py", "fastapi_middleware.py"])
    def test_example_imports(self, example):
        """Verify example files have valid Python syntax."""
        import ast
        with open(f"examples/{example}") as f:
            ast.parse(f.read())
```

## Коммит

```
docs: add integration examples (standalone, FastAPI, Docker)
```
