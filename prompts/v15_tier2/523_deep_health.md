# 523 — Deep Health Checks

## Goal

Add `/readyz` endpoint that checks subsystem health: Telegram bot, trace writer, regex compilation, rule loading.

## Context

- Current `/health` only confirms the server is responding
- K8s and load balancers need deeper checks to determine readiness
- `/readyz` should verify all critical subsystems are functional

## Code

### Modify: `policyshield/server/app.py`

```python
@app.get("/api/v1/readyz")
async def readyz():
    checks = {}

    # Rules loaded?
    checks["rules"] = {"ok": engine.rule_count > 0, "count": engine.rule_count}

    # Trace writer?
    if engine._trace_recorder:
        try:
            checks["trace"] = {"ok": engine._trace_recorder.file_path is not None}
        except Exception as e:
            checks["trace"] = {"ok": False, "error": str(e)}

    # Telegram bot connected?
    if hasattr(engine, '_approval_backend'):
        backend = engine._approval_backend
        if hasattr(backend, 'is_connected'):
            checks["approval"] = {"ok": backend.is_connected()}

    all_ok = all(c.get("ok", True) for c in checks.values())
    status_code = 200 if all_ok else 503
    return JSONResponse({"status": "ready" if all_ok else "not_ready", "checks": checks}, status_code=status_code)
```

## Tests

- Test `/readyz` returns 200 when all healthy
- Test `/readyz` returns 503 when rules not loaded
- Test `/readyz` includes subsystem details

## Self-check

```bash
pytest tests/test_server_app.py -v -k readyz
curl http://localhost:8100/api/v1/readyz | python -m json.tool
```

## Commit

```
feat: add /readyz deep health check endpoint
```
