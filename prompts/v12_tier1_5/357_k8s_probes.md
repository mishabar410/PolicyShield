# Prompt 357 — Kubernetes Liveness / Readiness Probes

## Цель

Расширить `/health` endpoint для поддержки K8s probes: `/healthz` (liveness) и `/readyz` (readiness).

## Контекст

- K8s ожидает отдельные endpoints для liveness (процесс жив) и readiness (готов принимать трафик)
- Liveness: всегда `200` если процесс работает
- Readiness: `200` если engine загружен и не shutting down

## Что сделать

```python
# app.py

@app.get("/healthz")
async def liveness():
    """Kubernetes liveness probe — always OK if process is running."""
    return {"status": "alive"}

@app.get("/readyz")
async def readiness():
    """Kubernetes readiness probe — OK if engine is loaded and not shutting down."""
    if _shutting_down.is_set():
        return JSONResponse(status_code=503, content={"status": "shutting_down"})
    if engine.rule_count == 0:
        return JSONResponse(status_code=503, content={"status": "no_rules_loaded"})
    return {"status": "ready", "rules": engine.rule_count}
```

## Тесты

```python
class TestK8sProbes:
    def test_liveness_always_200(self, client):
        resp = client.get("/healthz")
        assert resp.status_code == 200

    def test_readiness_ok_when_ready(self, client):
        resp = client.get("/readyz")
        assert resp.status_code == 200

    def test_readiness_503_during_shutdown(self):
        # Set _shutting_down → readiness should return 503
        pass

    def test_probes_no_auth_required(self, secured_client):
        resp = secured_client.get("/healthz")
        assert resp.status_code == 200  # No auth needed
```

## Самопроверка

```bash
pytest tests/test_dx.py::TestK8sProbes -v
pytest tests/ -q
```

## Коммит

```
feat(server): add /healthz and /readyz for Kubernetes probes
```
