# Prompt 08 — Trace Stats

## Цель

Добавить CLI-команду `policyshield trace stats <file>` для агрегированной статистики из JSONL-файла трейса. Вывод: общее количество вызовов, распределение по вердиктам, топ правил, топ tools, timeline.

## Контекст

- Существующий trace CLI: `trace show`, `trace violations` в `cli/main.py`
- Trace формат: JSONL с полями `timestamp`, `tool`, `verdict`, `rule_id`, `session_id`, `pii_types`, `latency_ms`

## Что сделать

### 1. Создать `policyshield/trace/analyzer.py`

```python
@dataclass
class TraceStats:
    """Aggregated statistics from trace records."""
    total_calls: int
    verdict_counts: dict[str, int]          # {"ALLOW": 150, "BLOCK": 12, ...}
    tool_counts: dict[str, int]             # {"exec": 80, "web_fetch": 50, ...}
    rule_hit_counts: dict[str, int]         # {"no-shell": 10, "no-pii": 5, ...}
    pii_type_counts: dict[str, int]         # {"EMAIL": 8, "SSN": 2, ...}
    session_count: int
    avg_latency_ms: float
    p95_latency_ms: float
    p99_latency_ms: float
    time_range: tuple[str, str] | None      # (first, last) timestamps
    block_rate: float                       # blocked / total

class TraceAnalyzer:
    """Analyze JSONL trace files and produce statistics."""
    
    @staticmethod
    def from_file(path: str | Path) -> TraceStats:
        """Load and analyze a JSONL trace file."""
    
    @staticmethod
    def from_records(records: list[dict]) -> TraceStats:
        """Analyze pre-loaded trace records."""
```

### 2. Добавить CLI: `trace stats`

В `cli/main.py`:

```bash
policyshield trace stats ./traces/trace.jsonl
```

Вывод:
```
📊 Trace Statistics
──────────────────────────────────
  Total calls:     162
  Sessions:        5
  Time range:      2025-02-11 10:00 → 2025-02-11 14:30
  Block rate:      7.4%

📋 Verdicts
  ALLOW:     150  (92.6%)
  BLOCK:      10  (6.2%)
  APPROVE:     2  (1.2%)

🔧 Top Tools
  exec:        80  (49.4%)
  web_fetch:   50  (30.9%)
  read_file:   32  (19.8%)

🛑 Top Rules (non-ALLOW)
  no-pii-web:      5 hits
  no-destructive:  3 hits
  rate-limit:      2 hits

⚡ Latency
  avg:   1.2ms
  p95:   3.5ms
  p99:   8.1ms

🔒 PII Detected
  EMAIL:  8
  SSN:    2
```

### 3. Добавить `--format json` опцию

```bash
policyshield trace stats ./traces/trace.jsonl --format json
```

Выводит `TraceStats` как JSON для программного использования.

### 4. Тесты: `tests/test_trace_analyzer.py`

Минимум 10 тестов:

```
test_empty_trace_file                      — пустой файл → total_calls=0
test_single_record                         — 1 запись → корректные счётчики
test_verdict_distribution                  — 10 ALLOW + 2 BLOCK → правильные %
test_tool_counts                           — разные tools → правильный подсчёт
test_rule_hit_counts                       — правила с вердиктом ≠ ALLOW → подсчитаны
test_pii_type_counts                       — записи с pii_types → подсчитаны
test_session_count                         — 3 уникальных session_id → session_count=3
test_latency_percentiles                   — p95 и p99 корректно вычислены
test_block_rate_calculation                — block_rate = blocked/total
test_cli_trace_stats                       — CLI: trace stats → exit 0, корректный вывод
test_cli_trace_stats_json                  — CLI: trace stats --format json → валидный JSON
```

## Самопроверки

```bash
pytest tests/ -q
ruff check policyshield/ tests/
pytest tests/ --cov=policyshield --cov-fail-under=85

# Ручная проверка (нужен trace файл из demo)
policyshield trace stats demo_traces/trace_*.jsonl
policyshield trace stats demo_traces/trace_*.jsonl --format json
```

## Коммит

```
feat(trace): add trace stats command with aggregated statistics

- Add TraceAnalyzer with verdict/tool/rule/PII/latency stats
- Add `policyshield trace stats` CLI command
- Support --format json for programmatic use
- Add 10+ tests for trace analysis
```
