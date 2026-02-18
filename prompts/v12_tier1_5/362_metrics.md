# Prompt 362 — Metric Alerts (Prometheus Endpoint)

## Цель

Добавить `/metrics` endpoint в Prometheus формате: request count, latency histogram, verdict distribution.

## Контекст

- Production мониторинг невозможен без метрик
- Нужно: `/metrics` с counter/histogram в Prometheus text format
- Без external dependency (no prometheus_client) — simple plaintext

## Что сделать

### 1. Simple metrics collector

```python
# server/metrics.py
from collections import Counter, defaultdict
import threading
from time import monotonic

class MetricsCollector:
    def __init__(self):
        self._lock = threading.Lock()
        self._request_count = 0
        self._verdict_counts: Counter = Counter()
        self._latency_sum = 0.0
        self._latency_count = 0

    def record(self, verdict: str, latency_ms: float):
        with self._lock:
            self._request_count += 1
            self._verdict_counts[verdict] += 1
            self._latency_sum += latency_ms
            self._latency_count += 1

    def to_prometheus(self) -> str:
        with self._lock:
            lines = [
                f"# HELP policyshield_requests_total Total check requests",
                f"# TYPE policyshield_requests_total counter",
                f"policyshield_requests_total {self._request_count}",
                f"# HELP policyshield_latency_ms_avg Average latency in ms",
                f"# TYPE policyshield_latency_ms_avg gauge",
                f"policyshield_latency_ms_avg {(self._latency_sum / max(self._latency_count, 1)):.2f}",
            ]
            for verdict, count in self._verdict_counts.items():
                lines.append(f'policyshield_verdicts_total{{verdict="{verdict}"}} {count}')
            return "\n".join(lines) + "\n"
```

### 2. `/metrics` endpoint

```python
# app.py
from starlette.responses import PlainTextResponse

_metrics = MetricsCollector()

@app.get("/metrics")
async def metrics():
    return PlainTextResponse(_metrics.to_prometheus(), media_type="text/plain")
```

## Тесты

```python
class TestMetrics:
    def test_metrics_format(self):
        from policyshield.server.metrics import MetricsCollector
        m = MetricsCollector()
        m.record("ALLOW", 5.0)
        m.record("BLOCK", 3.0)
        output = m.to_prometheus()
        assert "policyshield_requests_total 2" in output
        assert 'verdict="ALLOW"' in output

    def test_metrics_endpoint(self, client):
        resp = client.get("/metrics")
        assert resp.status_code == 200
        assert "policyshield_requests_total" in resp.text
```

## Коммит

```
feat(server): add /metrics endpoint with Prometheus format
```
