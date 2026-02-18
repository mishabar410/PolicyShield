# Prompt 340 — Telegram Poller Graceful Shutdown

## Цель

Добавить graceful shutdown для Telegram approval poller — остановить polling loop и очистить ресурсы.

## Контекст

- `approval/telegram.py` — поллинг в фоновом потоке, при SIGTERM не останавливается
- Thread остаётся zombie → утечка ресурсов при restart
- Нужно: `stop_event` для поллера, вызов `stop()` из lifespan

## Что сделать

```python
# approval/telegram.py
import threading

class TelegramApprovalBackend:
    def __init__(self, ...):
        self._stop_event = threading.Event()
        self._poll_thread: threading.Thread | None = None

    def start(self):
        self._stop_event.clear()
        self._poll_thread = threading.Thread(target=self._poll_loop, daemon=True)
        self._poll_thread.start()

    def _poll_loop(self):
        while not self._stop_event.is_set():
            try:
                self._poll_updates()
            except Exception as e:
                logger.error("Telegram poll error: %s", e)
            self._stop_event.wait(timeout=2.0)  # Interruptible sleep

    def stop(self):
        """Gracefully stop the polling thread."""
        self._stop_event.set()
        if self._poll_thread and self._poll_thread.is_alive():
            self._poll_thread.join(timeout=5.0)
            if self._poll_thread.is_alive():
                logger.warning("Telegram poller thread did not stop in time")
        self._poll_thread = None
```

## Тесты

```python
class TestTelegramPollerShutdown:
    def test_stop_event_stops_poller(self):
        # Verify _stop_event.set() causes _poll_loop to exit
        pass

    def test_stop_joins_thread(self):
        # Verify thread is joined on stop()
        pass

    def test_double_stop_is_safe(self):
        # stop() twice should not crash
        pass
```

## Самопроверка

```bash
pytest tests/test_lifecycle.py::TestTelegramPollerShutdown -v
pytest tests/ -q
```

## Коммит

```
fix(telegram): add graceful poller shutdown with stop_event
```
