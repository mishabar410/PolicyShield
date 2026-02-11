# Prompt 07 — Batch Approve

## Цель

Реализовать кэш одобрений: когда человек одобрил tool call, повторные похожие вызовы автоматически одобряются без повторного запроса. Поддержка стратегий: approve-once, approve-per-session, approve-by-pattern.

## Контекст

- `ApprovalBackend` из Prompt 05
- `ShieldEngine` вызывает `backend.submit()` + `backend.wait_for_response()` для APPROVE вердиктов
- Цель: уменьшить число запросов к человеку для повторяющихся действий

## Что сделать

### 1. Создать `policyshield/approval/cache.py`

```python
class ApprovalStrategy(str, Enum):
    """How to cache approval decisions."""
    ONCE = "once"                   # одобрить только этот конкретный вызов
    PER_SESSION = "per_session"     # одобрить все такие вызовы в этой сессии
    PER_RULE = "per_rule"           # одобрить все вызовы этого правила в сессии
    PER_TOOL = "per_tool"           # одобрить все вызовы этого tool в сессии

class ApprovalCache:
    """Cache for approval decisions to avoid repeated prompts."""
    
    def __init__(self, strategy: ApprovalStrategy = ApprovalStrategy.PER_RULE):
        self._cache: dict[str, ApprovalResponse] = {}
    
    def get(self, tool_name: str, rule_id: str, session_id: str) -> ApprovalResponse | None:
        """Check if there's a cached approval for this combination."""
    
    def put(self, tool_name: str, rule_id: str, session_id: str, response: ApprovalResponse) -> None:
        """Cache an approval response."""
    
    def clear(self, session_id: str | None = None) -> None:
        """Clear cache, optionally for a specific session only."""
    
    def _make_key(self, tool_name: str, rule_id: str, session_id: str) -> str:
        """Generate cache key based on strategy."""
```

**Стратегии (генерация ключей):**
- `ONCE`: `f"{session_id}:{rule_id}:{tool_name}:{args_hash}"` — только точный match
- `PER_SESSION`: `f"{session_id}:{rule_id}"` — все вызовы этого правила в сессии
- `PER_RULE`: `f"{rule_id}"` — все вызовы этого правила глобально
- `PER_TOOL`: `f"{session_id}:{tool_name}"` — все вызовы этого tool в сессии

### 2. YAML DSL: настройка стратегии

```yaml
rules:
  - id: approve-downloads
    when:
      tool: exec
      args_match:
        command: { regex: "curl|wget" }
    then: approve
    approval_strategy: per_session  # auto-approve после первого одобрения в сессии
    severity: medium
```

Если `approval_strategy` не указана, используется значение по умолчанию из `ShieldEngine`.

### 3. Обновить `RuleConfig` в `models.py`

```python
class RuleConfig(BaseModel):
    # ... existing fields ...
    approval_strategy: str | None = None  # "once", "per_session", "per_rule", "per_tool"
```

### 4. Интеграция в `ShieldEngine`

В `_do_check()`, перед вызовом `backend.submit()`:

1. Проверить `approval_cache.get(tool, rule_id, session_id)`
2. Если cached response найден и `approved` → return ALLOW (без запроса)
3. Если cached response найден и NOT approved → return BLOCK
4. Иначе: submit + wait как раньше
5. После получения response: `approval_cache.put(tool, rule_id, session_id, response)`

### 5. Тесты: `tests/test_approval_cache.py`

Минимум 10 тестов:

```
test_cache_miss_returns_none               — пустой кэш → None
test_cache_hit_returns_response            — put → get → response
test_strategy_per_session_same_session     — одобрить в session-A → следующий вызов в session-A auto-approved
test_strategy_per_session_diff_session     — одобрить в session-A → session-B не затронута
test_strategy_per_rule_global              — одобрить rule-X → все сессии auto-approved
test_strategy_per_tool_same_tool           — одобрить exec → все exec в сессии auto-approved
test_strategy_once_no_cache                — ONCE → каждый вызов запрашивает заново
test_clear_session                         — clear(session_id) → кэш для сессии пуст
test_clear_all                             — clear() → весь кэш пуст
test_engine_batch_approve_integration      — ShieldEngine с cache: первый → approve, второй → auto-allow
```

## Самопроверки

```bash
pytest tests/ -q
ruff check policyshield/ tests/
pytest tests/ --cov=policyshield --cov-fail-under=85
```

## Коммит

```
feat(approve): add approval cache with batch approve strategies

- Add ApprovalCache with strategies: once, per_session, per_rule, per_tool
- Add approval_strategy field to RuleConfig YAML DSL
- Integrate cache into ShieldEngine approval flow
- Auto-approve repeated similar calls without re-prompting
- Add 10+ tests for cache strategies
```
