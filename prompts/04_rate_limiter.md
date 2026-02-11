# Prompt 04 — Rate Limiter Engine

## Цель

Реализовать полноценный rate limiter как отдельный компонент: sliding window, per-tool лимиты, per-session лимиты, конфигурация из YAML.

## Контекст

- Сейчас rate limiting работает примитивно: `session.tool_count.web_fetch > 10` в `when` секции правила
- Это требует от пользователя знать внутреннюю структуру session state
- Нужно: первоклассная поддержка rate limiting в YAML DSL

## Что сделать

### 1. Создать `policyshield/shield/rate_limiter.py`

```python
@dataclass
class RateLimit:
    """A single rate limit configuration."""
    tool: str              # tool name или "*" для всех
    max_calls: int         # максимум вызовов
    window_seconds: float  # окно (0 = per-session без окна)
    scope: str = "session" # "session" или "global"

class RateLimiter:
    """Sliding window rate limiter for tool calls."""
    
    def __init__(self, limits: list[RateLimit]):
        ...
    
    def check(self, tool_name: str, session_id: str) -> RateLimitResult:
        """Check if tool call is allowed within rate limits.
        
        Returns:
            RateLimitResult with is_allowed, remaining, reset_at
        """
    
    def record(self, tool_name: str, session_id: str) -> None:
        """Record a tool call for rate tracking."""
    
    def cleanup(self) -> None:
        """Remove expired entries from sliding window."""

@dataclass
class RateLimitResult:
    is_allowed: bool
    limit: RateLimit | None = None   # какой лимит сработал
    remaining: int = 0                # осталось вызовов
    reset_after_seconds: float = 0.0  # через сколько секунд сбросится
```

**Sliding window:** хранить `deque` временных меток для каждого `(tool, session_id)`. При `check()` — убрать старые записи за пределами окна, посчитать оставшиеся.

### 2. YAML DSL: секция `rate_limits`

```yaml
shield_name: my-rules
version: 1

rate_limits:
  - tool: web_fetch
    max_calls: 20
    window: 60        # 20 вызовов в 60 секунд
  - tool: exec
    max_calls: 50
    window: 300       # 50 вызовов в 5 минут
  - tool: "*"
    max_calls: 200
    window: 3600      # 200 вызовов любого tool в час

rules:
  - id: no-shell-rm
    # ... обычные правила
```

### 3. Обновить парсер

В `parser.py` — парсить `rate_limits` секцию, создавать `list[RateLimit]`.
Добавить `rate_limits: list[RateLimit] = []` в `RuleSet`.

### 4. Интеграция в `ShieldEngine`

В `_do_check()`:
- После matching правил и PII — проверить rate limits
- Если `RateLimitResult.is_allowed == False`:
  - Вернуть `ShieldResult(verdict=BLOCK, message=f"Rate limit exceeded: {limit.max_calls} calls per {limit.window_seconds}s for {tool}")`
- После check (если ALLOW) — вызвать `rate_limiter.record()`

### 5. Тесты: `tests/test_rate_limiter.py`

Минимум 10 тестов:

```
test_under_limit_allowed                  — 5/10 вызовов → ALLOW
test_at_limit_blocked                     — 10/10 вызовов → 11-й BLOCK
test_sliding_window_expires               — подождать окно → снова ALLOW
test_per_tool_isolation                   — лимит на web_fetch не влияет на exec
test_per_session_isolation                — лимит session-A не влияет на session-B
test_wildcard_tool_limit                  — tool: "*" считает все tools
test_remaining_count                      — remaining корректно уменьшается
test_reset_after_seconds                  — reset_after_seconds > 0 при блокировке
test_yaml_rate_limits_parsed              — YAML с rate_limits → правильные RateLimit объекты
test_engine_rate_limit_integration        — ShieldEngine блокирует при превышении лимита
```

## Самопроверки

```bash
pytest tests/ -q
ruff check policyshield/ tests/
pytest tests/ --cov=policyshield --cov-fail-under=85
```

## Коммит

```
feat(rate-limit): add sliding window rate limiter with YAML config

- Add RateLimiter with per-tool per-session sliding window
- Add rate_limits section to YAML DSL
- Integrate rate limiting into ShieldEngine check pipeline
- Add 10+ tests for rate limiter
```
