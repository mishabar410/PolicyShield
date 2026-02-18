# Prompt 104 — Event Ring Buffer

## Цель

Добавить кольцевой буфер событий в `SessionState` — хранит последние N tool calls с timestamp для temporal matching в chain rules.

## Контекст

- Chain rules проверяют последовательности: «если `read_file` вызван, а потом `send_message` в течение 60 сек → BLOCK»
- Для этого нужно хранить историю tool calls внутри сессии
- Кольцевой буфер (ring buffer) с фиксированным размером — O(1) вставка, не растёт бесконечно
- `SessionState` из `core/models.py` — dataclass, нужно добавить поле
- `SessionManager.increment()` уже вызывается при каждом check — использовать для записи

## Что сделать

### 1. Создать `policyshield/shield/ring_buffer.py`

```python
"""Fixed-size ring buffer for temporal event tracking."""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone


@dataclass(frozen=True)
class ToolEvent:
    """A recorded tool call event."""
    tool: str
    timestamp: datetime
    verdict: str
    args_summary: str = ""  # Truncated repr of args for debugging


class EventRingBuffer:
    """Fixed-size ring buffer for tool call events.

    Uses collections.deque with maxlen for O(1) append.
    Thread safety is handled by the caller (SessionManager).
    """

    def __init__(self, max_size: int = 100) -> None:
        self._buffer: deque[ToolEvent] = deque(maxlen=max_size)

    def add(self, tool: str, verdict: str, args_summary: str = "") -> None:
        """Record a tool event."""
        event = ToolEvent(
            tool=tool,
            timestamp=datetime.now(timezone.utc),
            verdict=verdict,
            args_summary=args_summary[:200],  # Truncate args
        )
        self._buffer.append(event)

    def find_recent(
        self,
        tool: str,
        *,
        within_seconds: float | None = None,
        verdict: str | None = None,
    ) -> list[ToolEvent]:
        """Find recent events matching criteria.

        Args:
            tool: Tool name to search for.
            within_seconds: Only events within this many seconds from now.
            verdict: Filter by verdict.

        Returns:
            List of matching events (oldest first).
        """
        now = datetime.now(timezone.utc)
        results = []
        for event in self._buffer:
            if event.tool != tool:
                continue
            if verdict and event.verdict != verdict:
                continue
            if within_seconds is not None:
                age = (now - event.timestamp).total_seconds()
                if age > within_seconds:
                    continue
            results.append(event)
        return results

    def has_recent(
        self,
        tool: str,
        *,
        within_seconds: float | None = None,
    ) -> bool:
        """Check if a tool was called recently."""
        return len(self.find_recent(tool, within_seconds=within_seconds)) > 0

    @property
    def events(self) -> list[ToolEvent]:
        """Return all events in order (oldest first)."""
        return list(self._buffer)

    def __len__(self) -> int:
        return len(self._buffer)

    def clear(self) -> None:
        self._buffer.clear()
```

### 2. Добавить ring buffer в `SessionState` (`core/models.py`)

В `SessionState` dataclass добавить:

```python
from policyshield.shield.ring_buffer import EventRingBuffer

@dataclass
class SessionState:
    # ... existing fields ...
    event_buffer: EventRingBuffer = field(default_factory=EventRingBuffer)
```

> **Внимание:** EventRingBuffer — не frozen dataclass, это mutable объект. Использовать `field(default_factory=...)`.

### 3. Обновить `SessionManager.increment()`

В `shield/session.py`, после `session.increment(tool_name)`:

```python
def increment(self, session_id: str, tool_name: str, verdict: str = "allow") -> SessionState:
    session = self.get_or_create(session_id)
    with self._lock:
        session.increment(tool_name)
        session.event_buffer.add(tool_name, verdict)
    return session
```

> Нужно добавить параметр `verdict` в `increment()` и прокинуть его из engine.

### 4. Тесты

#### `tests/test_ring_buffer.py`

```python
import time
from policyshield.shield.ring_buffer import EventRingBuffer


def test_add_and_retrieve():
    buf = EventRingBuffer(max_size=10)
    buf.add("read_file", "allow")
    buf.add("write_file", "block")
    assert len(buf) == 2
    assert buf.events[0].tool == "read_file"
    assert buf.events[1].tool == "write_file"


def test_max_size():
    buf = EventRingBuffer(max_size=3)
    for i in range(5):
        buf.add(f"tool_{i}", "allow")
    assert len(buf) == 3
    assert buf.events[0].tool == "tool_2"  # Oldest kept
    assert buf.events[2].tool == "tool_4"  # Newest


def test_find_recent_by_tool():
    buf = EventRingBuffer(max_size=10)
    buf.add("read_file", "allow")
    buf.add("write_file", "block")
    buf.add("read_file", "allow")

    results = buf.find_recent("read_file")
    assert len(results) == 2


def test_find_recent_by_verdict():
    buf = EventRingBuffer(max_size=10)
    buf.add("read_file", "allow")
    buf.add("read_file", "block")

    results = buf.find_recent("read_file", verdict="block")
    assert len(results) == 1


def test_has_recent_within_seconds():
    buf = EventRingBuffer(max_size=10)
    buf.add("read_file", "allow")
    assert buf.has_recent("read_file", within_seconds=5)
    assert not buf.has_recent("write_file", within_seconds=5)


def test_clear():
    buf = EventRingBuffer(max_size=10)
    buf.add("read_file", "allow")
    buf.clear()
    assert len(buf) == 0


def test_args_truncation():
    buf = EventRingBuffer(max_size=10)
    buf.add("tool", "allow", args_summary="x" * 500)
    assert len(buf.events[0].args_summary) == 200
```

## Самопроверка

```bash
pytest tests/test_ring_buffer.py -v
pytest tests/ -q
```

## Коммит

```
feat(session): add event ring buffer for temporal tracking

- Add EventRingBuffer with fixed-size deque (O(1) append)
- Add ToolEvent dataclass: tool, timestamp, verdict, args_summary
- find_recent(): search by tool, time window, verdict
- Integrate into SessionState as event_buffer field
- Pass verdict to SessionManager.increment() for buffer recording
```
