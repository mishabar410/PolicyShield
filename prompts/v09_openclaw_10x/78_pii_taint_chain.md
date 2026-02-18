# Prompt 77 — PII Taint Chain

## Цель

Реализовать механизм «taint chain»: если PII обнаружен в output tool call (`after_tool_call`), отметить сессию как «tainted» и блокировать последующие исходящие вызовы до ручной проверки.

## Контекст

- `after_tool_call` в OpenClaw SDK возвращает `void` — невозможно модифицировать или заблокировать результат
- Это значит, что PII в output уже отправлен agent'у
- Но мы можем **предотвратить дальнейшую утечку**: если agent попытается отправить сообщение или сделать web-запрос с PII-данными
- Механизм: `post_check` обнаружил PII → сервер ставит флаг `pii_tainted: true` на сессию → следующий `check` на исходящие инструменты → BLOCK

## Что сделать

### 1. Обновить `policyshield/shield/session.py`

Добавить поле `pii_tainted` в `SessionState`:

```python
@dataclass
class SessionState:
    call_count: int = 0
    pii_tainted: bool = False
    taint_details: str | None = None
    # ... existing fields ...

    def set_taint(self, reason: str) -> None:
        self.pii_tainted = True
        self.taint_details = reason

    def clear_taint(self) -> None:
        self.pii_tainted = False
        self.taint_details = None
```

### 2. Обновить `policyshield/shield/base_engine.py`

В `_do_post_check()` — если PII найден в output, ставить taint:

```python
def _do_post_check(self, tool_name: str, output: str, session_id: str) -> PostCheckResult:
    pii_matches = self.pii_detector.scan(output)
    if pii_matches:
        session = self.session_manager.get(session_id)
        pii_types = ", ".join(m.pii_type.value for m in pii_matches)
        session.set_taint(f"PII detected in {tool_name} output: {pii_types}")
        self.trace_recorder.record_event(
            "pii_taint",
            session_id=session_id,
            tool_name=tool_name,
            details=f"Session tainted: {pii_types}",
        )
    return PostCheckResult(pii_matches=pii_matches)
```

В `_do_check_sync()` — перед основной логикой, проверить taint:

```python
def _do_check_sync(self, tool_name: str, args: dict, session_id: str, sender: str | None) -> ShieldResult:
    session = self.session_manager.get(session_id)

    # Check PII taint — block outgoing calls if session is tainted
    if session.pii_tainted and tool_name in self._outgoing_tools:
        return ShieldResult(
            verdict=Verdict.BLOCK,
            message=f"Session tainted: {session.taint_details}. Outgoing calls blocked until reviewed.",
            rule_id="__pii_taint__",
        )

    # ... rest of existing logic ...
```

### 3. Добавить конфигурацию `outgoing_tools`

В YAML правилах:

```yaml
version: "1"
default_verdict: allow

taint_chain:
  enabled: true
  outgoing_tools:
    - send_message
    - web_fetch
    - http_request
    - email_send
```

В `base_engine.py`:

```python
self._outgoing_tools: set[str] = set(
    self.rule_set.config.get("taint_chain", {}).get("outgoing_tools", [])
)
self._taint_enabled: bool = self.rule_set.config.get("taint_chain", {}).get("enabled", False)
```

### 4. Обновить OpenClaw preset rules

В `policyshield/presets/openclaw.yaml` добавить:

```yaml
taint_chain:
  enabled: true
  outgoing_tools:
    - send_message
    - web_fetch
    - exec
```

### 5. Добавить API эндпоинт для сброса taint

В `policyshield/server/app.py`:

```python
class ClearTaintRequest(BaseModel):
    session_id: str

@app.post("/api/v1/clear-taint")
async def clear_taint(req: ClearTaintRequest):
    session = engine.session_manager.get(req.session_id)
    session.clear_taint()
    return {"status": "ok", "session_id": req.session_id}
```

### 6. Тесты

#### `tests/test_taint_chain.py`

```python
def test_taint_blocks_outgoing_after_pii():
    engine = ShieldEngine(rules=..., taint_chain_config=...)
    # Normal call passes
    r1 = engine.check("web_search", {"query": "test"}, session_id="s1")
    assert r1.verdict == Verdict.ALLOW

    # PII detected in output → taint
    engine.post_check("web_search", "user email is john@corp.com", session_id="s1")

    # Outgoing call is now blocked
    r2 = engine.check("send_message", {"text": "hello"}, session_id="s1")
    assert r2.verdict == Verdict.BLOCK
    assert "tainted" in r2.message

    # Non-outgoing call still allowed
    r3 = engine.check("read_file", {"path": "/tmp/x"}, session_id="s1")
    assert r3.verdict == Verdict.ALLOW

def test_clear_taint():
    engine = ShieldEngine(rules=..., taint_chain_config=...)
    engine.post_check("tool", "john@corp.com output", session_id="s1")
    session = engine.session_manager.get("s1")
    assert session.pii_tainted
    session.clear_taint()
    r = engine.check("send_message", {"text": "hello"}, session_id="s1")
    assert r.verdict == Verdict.ALLOW

def test_taint_disabled_by_default():
    engine = ShieldEngine(rules=...)  # no taint_chain config
    engine.post_check("tool", "john@corp.com output", session_id="s1")
    r = engine.check("send_message", {"text": "hello"}, session_id="s1")
    assert r.verdict == Verdict.ALLOW  # taint disabled, passes through
```

## Самопроверка

```bash
# Тесты taint chain
pytest tests/test_taint_chain.py -v

# Все тесты
pytest tests/ -q

# TypeScript (плагин не изменён, но проверяем)
cd plugins/openclaw && npx tsc --noEmit
```

## Коммит

```
feat(engine): add PII taint chain — block outgoing calls after PII leak

- Add pii_tainted flag to SessionState
- Post-check: set taint when PII detected in tool output
- Pre-check: block outgoing tools (configurable list) when session tainted
- Add /api/v1/clear-taint endpoint for manual taint reset
- Add taint_chain config in YAML rules (enabled, outgoing_tools)
- Add taint_chain to OpenClaw preset rules
- Disabled by default — opt-in via taint_chain.enabled: true
```
