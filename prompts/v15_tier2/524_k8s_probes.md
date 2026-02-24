# 524 — Kubernetes Probes

## Goal

Add separate `/livez` and `/readyz` endpoints optimized for Kubernetes liveness and readiness probes.

## Context

- `/livez` = is the process alive? (lightweight, always 200 unless deadlocked)
- `/readyz` = is the service ready to accept traffic? (check subsystems)
- K8s uses these to decide restart vs. traffic routing

## Code

### Modify: `policyshield/server/app.py`

```python
@app.get("/api/v1/livez")
async def livez():
    """Liveness probe — always returns 200 if the process is running."""
    return {"status": "alive"}
```

`/readyz` already implemented in prompt 523.

### Modify: `Dockerfile.server`

Update HEALTHCHECK to use `/livez`:

```dockerfile
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8100/api/v1/livez')"
```

### Add K8s manifest example: `examples/k8s/deployment.yaml`

```yaml
livenessProbe:
  httpGet:
    path: /api/v1/livez
    port: 8100
  initialDelaySeconds: 5
  periodSeconds: 10
readinessProbe:
  httpGet:
    path: /api/v1/readyz
    port: 8100
  initialDelaySeconds: 5
  periodSeconds: 10
```

## Tests

- Test `/livez` returns 200
- Test `/readyz` returns 200 when ready, 503 when not

## Self-check

```bash
pytest tests/test_server_app.py -v -k "livez or readyz"
```

## Commit

```
feat: add /livez and /readyz Kubernetes probes
```
