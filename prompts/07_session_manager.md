# Промпт 07 — Session Manager

## Контекст

Модель `SessionState` создана в промпте 02. Теперь нужен менеджер, который управляет сессиями: создание, получение, обновление счётчиков, taint tracking. Спецификация — раздел 7 `TECHNICAL_SPEC.md`.

Session Manager — отдельный компонент, который будет использоваться ShieldEngine (промпт 08). Он должен работать автономно.

## Задача

Создай файл `policyshield/shield/session.py`:

### Класс `SessionManager`

**Конструктор:**
- `ttl_seconds: int = 3600` — время жизни сессии. Сессия, к которой не обращались дольше TTL, считается неактивной.
- `max_sessions: int = 1000` — максимальное число активных сессий (защита от утечки памяти).
- Внутреннее хранилище: `dict[str, SessionState]`
- Для каждой сессии хранить `last_accessed: datetime`

**Метод `get_or_create(session_id: str) -> SessionState`:**
- Если сессия существует и не истекла — вернуть
- Если сессия существует, но истекла — удалить, создать новую
- Если сессии нет — создать новую
- Если достигнут `max_sessions` — удалить самую старую (по last_accessed)

**Метод `increment(session_id: str, tool_name: str) -> None`:**
- Увеличить `tool_counts[tool_name]` и `total_calls` в сессии
- Обновить `last_accessed`

**Метод `add_taint(session_id: str, pii_type: PIIType) -> None`:**
- Добавить taint label в `session.taints`

**Метод `get_taints(session_id: str) -> set[PIIType]`:**
- Вернуть текущие taints для сессии. Если сессии нет — вернуть пустой set.

**Метод `cleanup() -> int`:**
- Удалить все истёкшие сессии. Вернуть число удалённых.

**Метод `stats() -> dict`:**
- Вернуть: `{"active_sessions": int, "total_calls": int (суммарно по всем сессиям)}`

## Thread Safety

Все операции с внутренним словарём должны быть потокобезопасны. Используй `threading.Lock`. Это важно, т.к. nanobot может обработывать несколько сообщений параллельно.

## Тесты

Напиши `tests/test_session.py`:

1. **get_or_create новой сессии** — вернёт SessionState с `total_calls=0`
2. **get_or_create существующей** — вернёт ту же сессию
3. **increment** — после `increment("s1", "exec")` дважды: `tool_counts["exec"] == 2`, `total_calls == 2`
4. **TTL expiry** — создать SessionManager(ttl_seconds=0), get_or_create, подождать (или mock time), get_or_create → новая сессия (total_calls=0). Используй `unittest.mock.patch` для `datetime.now`, не делай `time.sleep`.
5. **max_sessions eviction** — SessionManager(max_sessions=2), создать 3 сессии → первая удалена
6. **add_taint / get_taints** — добавить EMAIL, проверить наличие
7. **cleanup** — создать 2 сессии с ttl=0, вызвать cleanup → вернёт 2, active_sessions == 0
8. **stats** — создать 2 сессии, инкрементить — проверить stats()
9. **Thread safety** — запустить 10 потоков, каждый делает increment на одну сессию. Проверить total_calls == 10. (Используй `concurrent.futures.ThreadPoolExecutor`)

## Защитные условия

- SessionManager не зависит от Matcher, PII, VerdictBuilder — использует только модели из core
- Не используй глобальные переменные — всё хранится внутри экземпляра
- Все предыдущие тесты проходят

## Проверки перед коммитом

```bash
ruff check policyshield/
pytest tests/ -v
```

## Коммит

```
git add -A && git commit -m "feat(shield): session manager — TTL, eviction, taints, thread-safe"
```
