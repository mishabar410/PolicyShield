# Prompt 331 — Graceful Shutdown

## Цель

При SIGTERM/SIGINT: отклонить новые запросы, дождаться текущих, flush traces, shutdown approval backend.

## Контекст

- `app.py` lifespan context manager уже делает базовый shutdown, но не отклоняет новые запросы
- При `docker stop` → SIGTERM → сервер прерывает in-flight requests → потеря данных
- Нужно: shutdown_event, middleware для отклонения, drain period

## Что сделать

```python
# app.py
import signal

# В create_app():
_shutting_down = asyncio.Event()

@asynccontextmanager
async def lifespan(app: FastAPI):
    yield
    _shutting_down.set()
    logger.info("Shutting down — draining in-flight requests...")
    # Wait for in-flight (backpressure semaphore reaching max)
    await asyncio.sleep(1)  # Brief drain window
    if engine._tracer:
        engine._tracer.flush()
    if hasattr(engine, '_approval_backend') and engine._approval_backend:
        if hasattr(engine._approval_backend, 'stop'):
            engine._approval_backend.stop()
    logger.info("PolicyShield server stopped")

@app.middleware("http")
async def reject_during_shutdown(request: Request, call_next):
    if _shutting_down.is_set() and request.url.path != "/api/v1/health":
        return JSONResponse(status_code=503, content={"error": "shutting_down", "verdict": "BLOCK"})
    return await call_next(request)
```

## Тесты

```python
class TestGracefulShutdown:
    def test_health_available_during_shutdown(self):
        pass  # health always returns 200

    def test_check_rejected_during_shutdown(self):
        pass  # Should return 503

    def test_traces_flushed_on_shutdown(self):
        pass  # Verify flush() called
```

## Самопроверка

```bash
pytest tests/test_lifecycle.py::TestGracefulShutdown -v
pytest tests/ -q
```

## Коммит

```
feat(server): add graceful shutdown with request draining
```
