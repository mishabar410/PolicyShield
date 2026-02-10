# Промпт 08 — Trace Recorder

## Контекст

Модель `TraceRecord` создана в промпте 02. Теперь нужен компонент, который пишет аудитный лог в JSONL-формат. Спецификация — раздел 8 `TECHNICAL_SPEC.md`.

Trace Recorder — автономный компонент: принимает TraceRecord, пишет в файл. Будет вызываться из ShieldEngine (промпт 09).

## Задача

Создай файл `policyshield/trace/recorder.py`:

### Класс `TraceRecorder`

**Конструктор:**
- `output_dir: Path` — директория для файлов трейса. Создать если не существует.
- `buffer_size: int = 50` — количество записей, после которого буфер сбрасывается на диск (батчинг).
- `privacy_mode: bool = True` — если True, аргументы tool call записываются как SHA256-hash, а не открытым текстом.

**Формат имени файла:** `shield_trace_{date}.jsonl` — один файл в день.

**Метод `record(trace: TraceRecord) -> None`:**
- Добавить в буфер
- Если буфер >= buffer_size — вызвать flush()

**Метод `flush() -> None`:**
- Записать все записи из буфера в файл. Каждая запись — одна строка JSON.
- Формат JSON-строки:
  ```json
  {"ts": "ISO8601", "session": "...", "tool": "...", "verdict": "ALLOW|BLOCK|...", "rule": "rule_id or null", "pii": ["EMAIL", ...], "latency_ms": 1.23, "args_hash": "sha256 or null"}
  ```
- Очистить буфер

**Метод `close() -> None`:**
- Вызвать flush() для оставшихся записей

**Context manager:**
- Реализовать `__enter__` / `__exit__` для автоматического flush при выходе

### Утилитные функции

**`compute_args_hash(args: dict) -> str`:**
- Сериализовать args в JSON (sorted keys) → SHA256 → hex-строка

## Тесты

Напиши `tests/test_trace.py`:

1. **Запись одного TraceRecord** — record + flush → файл существует, содержит одну строку valid JSON
2. **Batch flush** — создать recorder(buffer_size=3), записать 3 записи → файл содержит 3 строки. Записать ещё 2, `flush()` → 5 строк.
3. **JSONL содержимое** — записать запись с verdict=BLOCK, rule="no-pii" → прочитать файл, распарсить JSON, проверить поля
4. **Privacy mode** — при `privacy_mode=True` поле `args_hash` — SHA256 (64 hex символа). При `privacy_mode=False` — null.
5. **Context manager** — `with TraceRecorder(...) as tr: tr.record(...)` → после выхода файл содержит записи
6. **Имя файла** — проверить что файл назван `shield_trace_{today}.jsonl`
7. **Несколько дней** (mock datetime.now) — записи разных "дней" попадают в разные файлы
8. **compute_args_hash** — детерминированность: одинаковые args → одинаковый hash. Разные args → разный hash.
9. **Пустой flush** — flush при пустом буфере не создаёт мусора в файле

## Защитные условия

- Trace Recorder не зависит от Matcher, PII, Verdict — только от моделей core
- Файловые операции: всегда append (не перезаписывай существующие trace-файлы)
- Используй `tmp_path` в тестах — не пиши реальные файлы
- Все предыдущие тесты проходят

## Проверки перед коммитом

```bash
ruff check policyshield/
pytest tests/ -v
```

## Коммит

```
git add -A && git commit -m "feat(trace): JSONL trace recorder — batched writes, privacy mode, context manager"
```
