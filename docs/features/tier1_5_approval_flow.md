# 🔥 Tier 1.5 — Approval Flow

Всё, что связано с human-in-the-loop: таймауты, утечки памяти, аудит, санитизация.

### Approval Timeout & Escalation 🔴 `v1.0-blocker`

Когда вердикт APPROVE, а человек не ответил — что происходит? **Сейчас — ничего, approval висит вечно.** Это баг, не фича.

```yaml
approval:
  timeout: 300s
  on_timeout: BLOCK         # или AUTO_APPROVE
  escalation:
    after: 600s
    notify: [admin@corp.com]
```

- **Усилия**: Средние (таймеры, escalation chain)
- **Ценность**: 🔥🔥🔥 — без этого approval flow в production сломан

### Approval Audit Trail 🔴 `v1.0-blocker`

Трейсы записывают verdict, но не записывают **кто** одобрил/отклонил и **когда**. Для compliance критично.

```json
{
  "verdict": "APPROVE",
  "approval": {
    "status": "approved",
    "approved_by": "@admin",
    "approved_at": "2026-02-18T00:40:00Z",
    "channel": "telegram",
    "response_time_ms": 12400
  }
}
```

- **Усилия**: Маленькие (~40 строк, расширить trace record)
- **Ценность**: 🔥🔥🔥 — compliance, SOC 2, аудит — без этого v1.0 нелегитимен

### Stale Approval Garbage Collection 🔴 `v1.0-blocker`

`_pending` и `_responses` в `TelegramApprovalBackend` и `InMemoryBackend` **растут бесконечно**. Нет TTL/GC для забытых approvals. В long-running сервере → memory leak.

Даже с Approval Timeout: если timeout триггерит `BLOCK`, запись в `_responses` dict остаётся навсегда.

```python
# Сейчас: approval хранится вечно
self._pending: dict[str, ApprovalRequest] = {}
self._responses: dict[str, ApprovalResponse] = {}

# Нужно: периодический GC или TTL
class ApprovalEntry:
    request: ApprovalRequest
    created_at: float
    
# GC: удалять entries старше approval_ttl (e.g. 1 hour)
```

- **Усилия**: Маленькие (~40 строк, TTL + периодический sweep)
- **Ценность**: 🔥🔥🔥 — memory leak в production = тикающая бомба

### Concurrent Approval Race Condition 🔴 `v1.0-blocker`

В `telegram.py` и `memory.py` метод `respond()` не проверяет, **повторный ли это ответ**. Если два человека нажмут ✅/❌ на один approval в Telegram — оба ответа обрабатываются, второй `respond()` перезаписывает первый. Cache в `_resolved_approvals` тоже перезаписывается. Для compliance критично: аудит покажет не того, кто ответил первым.

```python
# Сейчас: любой respond() перезаписывает предыдущий
def respond(self, request_id, approved, responder="", comment=""):
    response = ApprovalResponse(...)
    self._responses[request_id] = response  # ← перезаписывает без проверки

# Нужно: idempotent respond — первый ответ выигрывает
def respond(self, request_id, approved, responder="", comment=""):
    with self._lock:
        if request_id in self._responses:
            return  # Already responded — ignore duplicate
        ...
```

- **Усилия**: Маленькие (~5 строк, guard в начале respond() в обоих бэкендах)
- **Ценность**: 🔥🔥🔥 — race condition в approval flow = compliance violation, неопределённый результат одобрения

### Args Sanitization в Approval Flow 🔴 `v1.0-blocker`

При `APPROVE` verdict полные `args` сохраняются в `_pending` и **отправляются открытым текстом в Telegram**, включая PII, секреты, API ключи. PII-детектор мог сработать → вердикт REDACT/APPROVE → но в Telegram ушли **оригинальные** args. Endpoint `/pending-approvals` тоже возвращает полные `args` без санитизации.

```python
# telegram.py — args отправляются как есть в Telegram
text = f"**Tool:** `{request.tool_name}`\n**Args:** {request.args}"
# ↑ args могут содержать: SSN, credit cards, API keys, passwords

# Нужно: sanitize перед отправкой
sanitized_args = pii_detector.redact_dict(request.args)
text = f"**Tool:** `{request.tool_name}`\n**Args:** {sanitized_args}"
```

- **Усилия**: Средние (~50 строк, sanitize args перед отправкой в approval backend + в API response)
- **Ценность**: 🔥🔥🔥 — утечка PII/секретов через Telegram = information disclosure через канал, который по определению выходит наружу

### Approval Polling Timeout (HTTP Handler) 🔴 `v1.0-blocker`

`engine.check()` покрыт Engine Check Timeout, но **отдельный вектор**: если клиент вызывает `check-approval` и approval backend зависает — нет timeout'а на уровне HTTP handler'а. `asyncio.wait_for` нигде не используется в server handlers.

В `telegram.py` дефолтный `wait_for_response(timeout=300s)`, в `base_engine.py:357` — `timeout=0.0` при polling. Но если Telegram API не отвечает на `getUpdates` — poll thread зависает, ответы не приходят, клиент ждёт бесконечно.

```yaml
server:
  approval_poll_timeout: 30s   # максимальное время ожидания на /check-approval
```

- **Усилия**: Маленькие (~15 строк, `asyncio.wait_for` в handler + httpx timeout в telegram)
- **Ценность**: 🔥🔥🔥 — зависание одного approval блокирует HTTP worker, каскадный отказ

### `_approval_meta` Unbounded Growth 🔴

`base_engine.py:87` хранит `_approval_meta: dict[str, dict]` для cache population после resolution. `_resolved_approvals` имеет `_max_resolved_approvals` + eviction, но `_approval_meta` **растёт бесконечно** — нет cleanup для meta-записей, если approval никогда не будет resolved (timeout без явного respond, crash бэкенда).

**Не покрывается** "Stale Approval GC" (та про `_pending`/`_responses` в бэкендах). Это про мету **в самом engine**.

```python
# Сейчас: meta хранится вечно, если approval не resolved
self._approval_meta: dict[str, dict] = {}

# Нужно: TTL sweep или ограничение размера
class ApprovalMetaEntry:
    data: dict
    created_at: float

# GC: удалять entries старше 1 часа
```

- **Усилия**: Маленькие (~10 строк, TTL sweep + max size)
- **Ценность**: 🔥🔥🔥 — memory leak в engine при approval timeouts
