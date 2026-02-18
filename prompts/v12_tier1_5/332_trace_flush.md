# Prompt 332 — Trace Flush on Shutdown

## Цель

Гарантировать flush trace buffer при shutdown / SIGTERM, чтобы последние записи не были потеряны.

## Контекст

- `trace/recorder.py` использует batched writes (`_buffer`) — при crash буфер теряется
- Lifespan уже вызывает `flush()`, но нужен ещё atexit handler как fallback
- Нужно: atexit + signal handler + explicit flush()

## Что сделать

```python
# trace/recorder.py
import atexit

class TraceRecorder:
    def __init__(self, ...):
        # ... existing init ...
        atexit.register(self._atexit_flush)

    def _atexit_flush(self):
        """Flush remaining buffer on process exit."""
        try:
            self.flush()
        except Exception:
            pass  # Best effort on exit
```

## Тесты

```python
class TestTraceFlush:
    def test_flush_writes_buffered_entries(self, tmp_path):
        from policyshield.trace.recorder import TraceRecorder
        from policyshield.core.models import Verdict
        recorder = TraceRecorder(output_dir=tmp_path)
        recorder.record("s1", "test", Verdict.ALLOW)
        # Not flushed yet — check buffer
        assert len(recorder._buffer) > 0
        recorder.flush()
        assert len(recorder._buffer) == 0
        files = list(tmp_path.glob("*.jsonl"))
        assert len(files) == 1
```

## Самопроверка

```bash
pytest tests/test_lifecycle.py::TestTraceFlush -v
pytest tests/ -q
```

## Коммит

```
fix(trace): add atexit flush handler for crash safety
```
