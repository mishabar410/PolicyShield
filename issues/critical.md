# 🔴 Критические проблемы (Critical)

Всего: **35** issues

[← Вернуться к оглавлению](ISSUES.md)

---

### 1. LLM Guard работает ТОЛЬКО в async-движке

**Файлы:** [async_engine.py](file:///Users/misha/PolicyShield/policyshield/shield/async_engine.py#L202-L214) vs [base_engine.py](file:///Users/misha/PolicyShield/policyshield/shield/base_engine.py#L303-L311)

Когда в `async_engine._do_check()` ни одно правило не совпало (match == None), вызывается LLM Guard:
```python
# async_engine.py — строки 203-214
if self._llm_guard is not None and getattr(self._llm_guard, "enabled", False):
    guard_result = await self._llm_guard.analyze(tool_name, args)
    if guard_result.is_threat and guard_result.risk_score >= self._llm_guard.risk_threshold:
        return ShieldResult(verdict=Verdict.BLOCK, ...)
```

В sync-движке (`_do_check_sync` в `base_engine.py`) **этот код отсутствует полностью**. Пользователь `ShieldEngine` (sync) никогда не получает LLM Guard защиту, хотя конструктор принимает `llm_guard` параметр.

> [!CAUTION]
> **Влияние:** Пользователи sync API (`ShieldEngine`, `@shield` decorator, `PolicyShieldClient`) остаются без AI-защиты, даже если LLM Guard настроен. Это ложное чувство безопасности.

---

### 2. Три (!) несовместимых HTTP-клиента

Есть **три разных** клиентских реализации, каждая с несовместимым API:

| Файл | Класс | base_url по умолчанию | Параметр токена | Retry | Approval |
|------|-------|-----------------------|-----------------|-------|----------|
| [client.py](file:///Users/misha/PolicyShield/policyshield/client.py) | `PolicyShieldClient` | `localhost:8000/api/v1` | `token` | ✅ 3 retries | ❌ |
| [sdk/client.py](file:///Users/misha/PolicyShield/policyshield/sdk/client.py) | `PolicyShieldClient` | `localhost:8100` | `api_token` | ❌ | ✅ `wait_for_approval` |
| [async_client.py](file:///Users/misha/PolicyShield/policyshield/async_client.py) | `AsyncPolicyShieldClient` | `localhost:8000/api/v1` | `token` | ✅ 2 retries | ❌ |
| [sdk/client.py](file:///Users/misha/PolicyShield/policyshield/sdk/client.py) | `AsyncPolicyShieldClient` | `localhost:8100` | `api_token` | ❌ | ❌ |

> [!CAUTION]
> **Конкретные баги:**
> - README документирует `from policyshield.sdk.client import PolicyShieldClient` — этот клиент НЕ имеет retry
> - `policyshield/client.py` (non-SDK) — другой `CheckResult` dataclass (меньше полей: нет `pii_types`, `approval_id`)
> - `sdk/client.AsyncPolicyShieldClient.kill()` вызывает `/api/v1/kill-switch` — несуществующий endpoint (сервер: `/api/v1/kill`)
> - `sdk/client.PolicyShieldClient.wait_for_approval()` вызывает `GET /api/v1/approval/{id}/status` — несуществующий endpoint (сервер: `POST /api/v1/check-approval`)

---

### 3. Sync/Async дупликация с расхождениями

**Файлы:** [base_engine.py](file:///Users/misha/PolicyShield/policyshield/shield/base_engine.py#L195-L382) и [async_engine.py](file:///Users/misha/PolicyShield/policyshield/shield/async_engine.py#L93-L295)

Комментарий в `async_engine.py` прямо говорит:
```
# Note: ``_do_check`` intentionally duplicates most of
# ``BaseShieldEngine._do_check_sync`` with ``await asyncio.to_thread()``
# wrappers.  Any logic change in the sync path must be mirrored here.
```

Но кроме LLM Guard (пункт 1), есть ещё расхождения:
- **Circuit breaker** в approval: проверяется в sync `_handle_approval_sync` (lines 399-408), но **отсутствует** в async `_handle_approval` (lines 297-364)
- Async approval **не проверяет** `_circuit_breaker.is_available()` при отправке — может повиснуть на мёртвом backend

---

### 14. SDK Client не передаёт `context` при `check()`

**Файлы:** [sdk/client.py](file:///Users/misha/PolicyShield/policyshield/sdk/client.py#L54-L67)

Оба клиента (sync и async) в `sdk/client.py` **не принимают и не передают** параметр `context`:

```python
# sdk/client.py — строки 54-67
def check(self, tool_name, args=None, session_id="default", sender=None):
    payload = {"tool_name": tool_name, "args": args or {}, "session_id": session_id}
    if sender:
        payload["sender"] = sender
    # ❌ context ОТСУТСТВУЕТ в payload
```

Сервер и движок полностью поддерживают `context` (time_of_day, day_of_week, произвольные ключи), но SDK-клиент **не позволяет его передать**. Пользователи SDK не могут использовать context-based правила.

> [!CAUTION]
> **Влияние:** Любые правила с `when.context` (time_of_day, day_of_week, environment, region) **всегда будут пропускать** вызовы через SDK-клиент, т.к. `context=None` при evaluation. Это фактически **обход security policy**.

---

### 15. `_resolve_extends` — shallow merge ломает вложенные `when` блоки

**Файл:** [parser.py#L259-L299](file:///Users/misha/PolicyShield/policyshield/core/parser.py#L259-L299)

```python
# Merge: parent values as defaults, child overrides
merged = {**parent, **rule}
```

Используется **shallow merge** через `{**parent, **rule}`. Если parent определяет `when: {tool: "file_*", args: {path: {regex: "/etc/.*"}}}`, а child-правило хочет только добавить `sender` в `when`:

```yaml
# parent:
- id: parent_rule
  when:
    tool: "file_*"
    args: {path: {regex: "/etc/.*"}}
  then: BLOCK

# child:
- id: child_rule
  extends: parent_rule
  when:
    sender: "admin"  # хочет ДОБАВИТЬ sender
```

Результат: `when` полностью **заменяется** на `{sender: "admin"}`, а `tool` и `args` из parent **исчезают**. Правило перестаёт фильтровать по tool/args и срабатывает на **всё** от admin.

> [!CAUTION]
> **Влияние:** Extends-правила с вложенным `when` теряют наследованные ограничения, что может превратить block-правило в широко срабатывающий блокировщик (или наоборот — пропустить опасные вызовы).

---

### 16. Webhook approval backend: `submit()` блокирует вызывающий поток

**Файл:** [approval/webhook.py#L95-L104](file:///Users/misha/PolicyShield/policyshield/approval/webhook.py#L95-L104)

```python
def submit(self, request: ApprovalRequest) -> None:
    self._requests[request.request_id] = request
    if self._mode == "sync":
        resp = self._sync_request(request)   # ← HTTP POST, blocking!
    else:
        resp = self._poll_request(request)    # ← polling loop up to 300s!
    self._responses[request.request_id] = resp
```

В `poll` mode `submit()` **блокирует** до 300 секунд (`_poll_timeout`), выполняя busy-polling цикл с `time.sleep()`. Async engine вызывает `await asyncio.to_thread(self._approval_backend.submit, req)`, что блокирует один worker thread, но при sync engine (`ShieldEngine`) это блокирует **весь вызов check()** на 300s.

> [!CAUTION]
> **Влияние:** В sync mode с webhook в `poll` режиме, один approval запрос блокирует весь поток на 5 минут. В server context это может привести к исчерпанию worker pool и DoS.

---

### 27. Shadow evaluation не получает `context` — ложные diff-логи

**Файлы:** [base_engine.py#L354-L362](file:///Users/misha/PolicyShield/policyshield/shield/base_engine.py#L354-L362), [async_engine.py#L266-L275](file:///Users/misha/PolicyShield/policyshield/shield/async_engine.py#L266-L275)

```python
# base_engine.py — shadow evaluation
shadow_match = shadow_matcher.find_best_match(
    tool_name=tool_name,
    args=args,
    session_state=session_state,
    sender=sender,
    event_buffer=event_buffer,
    # ❌ context= ОТСУТСТВУЕТ
)
```

Shadow-правила с `when.context` (time_of_day, environment, region) **никогда не совпадут**, потому что `context=None`. Это даёт ложные diff-логи «SHADOW: verdict_diff» и делает невозможным тестирование context-aware правил через shadow mode перед production deploy.

> [!CAUTION]
> **Влияние:** Shadow mode — основной механизм безопасного тестирования новых правил. Без `context` он даёт **ложные результаты** для context-aware правил.

---

### 28. `@shield` decorator не передаёт `sender` и `context`

**Файл:** [decorators.py#L52-L89](file:///Users/misha/PolicyShield/policyshield/decorators.py#L52-L89)

```python
# async_wrapper
result = await engine.check(name, all_kwargs, session_id=session_id)
# ❌ sender= и context= не передаются

# sync_wrapper
result = engine.check(name, all_kwargs, session_id=session_id)
# ❌ sender= и context= не передаются
```

Декоратор `@shield()` **не принимает и не передаёт** `sender` и `context`. Любая функция, защищённая декоратором, игнорирует sender-based и context-based правила. Та же проблема что Issue #14 (SDK), но для decorator API.

> [!CAUTION]
> **Влияние:** Пользователи decorator API (`@shield`, `@guard`) не могут использовать sender и context-based правила — безопасность **обходится**.

---

### 29. `compile-and-apply` удаляет невинные правила по совпадению tool-паттерна

**Файл:** [app.py#L637-L646](file:///Users/misha/PolicyShield/policyshield/server/app.py#L637-L646)

```python
# Remove existing rules that conflict (same tool)
for r in existing_rules:
    if r.get("id") in new_ids:
        continue  # replaced by new rule ← OK
    tool = r.get("when", {}).get("tool") if isinstance(r.get("when"), dict) else None
    if tool and tool in new_tools:
        continue  # conflicting tool — removed ← 💥 ОПАСНО
    merged_rules.append(r)
```

Если новое правило таргетирует `tool: "file_read"`, **ВСЕ** существующие правила с тем же tool удаляются, даже если у них другой sender, args или verdict. Разные правила для одного tool — нормальная практика (ALLOW для admin, BLOCK для anonymous).

> [!CAUTION]
> **Влияние:** Один `compile-and-apply` запрос может **удалить критические security rules**, оставив tool незащищённым.

---

### 40. Async SDK kill-switch → несуществующий endpoint

**Файлы:** [sdk/client.py](file:///Users/misha/PolicyShield/policyshield/sdk/client.py#L82-L86) (sync) vs [sdk/client.py](file:///Users/misha/PolicyShield/policyshield/sdk/client.py#L168-L172) (async)

Sync клиент отправляет `POST /api/v1/kill`, async — `POST /api/v1/kill-switch`. Сервер (`app.py`) регистрирует `/api/v1/kill`. **Async SDK kill switch всегда получает 404**, и `raise_for_status()` бросает `httpx.HTTPStatusError`.

```python
# Sync — правильно:
def kill(self, reason: str = "SDK kill switch") -> dict:
    resp = self._client.post("/api/v1/kill", json={"reason": reason})

# Async — НЕПРАВИЛЬНО:
async def kill(self, reason: str = "SDK kill switch") -> dict:
    resp = await self._client.post("/api/v1/kill-switch", json={"reason": reason})
```

> [!CAUTION]
> **Влияние:** В аварийной ситуации async-приложение не сможет активировать kill switch через SDK. Единственный workaround — прямой HTTP вызов.

---

### 41. Async SDK — отсутствуют 3 ключевых метода

**Файл:** [sdk/client.py](file:///Users/misha/PolicyShield/policyshield/sdk/client.py#L127-L188)

| Метод | `PolicyShieldClient` | `AsyncPolicyShieldClient` |
|---|---|---|
| `post_check()` | ✅ L69-76 | ❌ |
| `reload()` | ✅ L94-98 | ❌ |
| `wait_for_approval()` | ✅ L100-114 | ❌ |

Пользователи, мигрирующие на async, теряют PII post-check, hot-reload, и polling approval без какого-либо предупреждения.

---

### 42. `guard()` — default engine всегда sync, crash на async

**Файл:** [decorators.py](file:///Users/misha/PolicyShield/policyshield/decorators.py#L115-L126)

```python
def _get_default_engine() -> Any:
    from policyshield.shield.engine import ShieldEngine  # sync only!
    _default_engine = ShieldEngine(rules=rules_path)
    return _default_engine
```

Декоратор `shield()` в L55 вызывает `await engine.check(...)` для async функций. Если engine — sync `ShieldEngine`, `check()` возвращает `ShieldResult` (не корутину), и `await` бросает `TypeError: object ShieldResult is not awaitable`.

---

### 43. Webhook approval — новый TCP на каждый poll tick

**Файл:** [webhook.py](file:///Users/misha/PolicyShield/policyshield/approval/webhook.py#L244-L271)

В `_poll_request()` каждая итерация poll loop создаёт `httpx.Client(...)` в `with` блоке:

```python
while time.monotonic() < deadline:
    with httpx.Client(timeout=self._timeout) as client:  # новый TCP каждые 2с!
        poll_resp = client.get(poll_url, ...)
```

При `poll_timeout=300s` и `poll_interval=2s` это **150 TCP connections** на один approval request. Сравним: `TelegramApprovalBackend` правильно переиспользует `self._client`.

---

### 44. LLM Guard cache — мутация shared объекта

**Файл:** [llm_guard.py](file:///Users/misha/PolicyShield/policyshield/shield/llm_guard.py#L120-L123)

```python
cached = self._get_cached(cache_key)
if cached is not None:
    cached.cached = True  # мутация объекта в кэше!
    return cached
```

`GuardResult` — mutable dataclass, хранится в `self._cache` по ссылке. Мутация `cached.cached = True` модифицирует объект прямо в кэше. При конкурентных запросах два потока могут одновременно мутировать один и тот же объект — data race без lock.

---

### 62. Telegram-бот — нулевая аутентификация

**Файл:** [telegram_bot.py](file:///Users/misha/PolicyShield/policyshield/bot/telegram_bot.py)

Любой пользователь Telegram, обнаруживший бота, может отправить `/kill` и активировать kill switch, заблокировав все tool-вызовы глобально. Нет allowlist по `chat_id`, нет проверки admin-статуса, нет rate limiting на командах.

Команды `/kill`, `/resume`, `/deploy` доступны **любому анонимному пользователю**.

> [!CAUTION]
> **Влияние:** Полный DoS — любой анонимный пользователь может отключить весь enforcement-слой PolicyShield. Также может деплоить произвольные правила через `/deploy`.

---

### 63. Payload size bypass через подмену Content-Length

**Файл:** [app.py](file:///Users/misha/PolicyShield/policyshield/server/app.py#L197-L231)

Middleware доверяет заголовку `Content-Length` когда он присутствует и ненулевой. Атакующий может выставить `Content-Length: 500` (в пределах лимита), а тело отправить chunked на 100MB. Чтение body через `request.body()` выполняется **только** когда Content-Length отсутствует или равен нулю.

```python
# Строка 220: body считывается ТОЛЬКО когда CL отсутствует
if not content_length or cl_int == 0:
    body = await request.body()  # <-- пропускается при спуфинге CL
```

> [!CAUTION]
> **Влияние:** Memory exhaustion / DoS — атакующий полностью обходит лимиты на размер body.

---

### 75. MCP Proxy — fake forwarding, вызов upstream отсутствует

**Файл:** [mcp_proxy.py#L49-L75](file:///Users/misha/PolicyShield/policyshield/mcp_proxy.py#L49-L75)

`MCPProxy.check_and_forward()` выполняет PolicyShield `check()`, но **никогда не вызывает upstream MCP сервер**. Метод возвращает `{"status": "forwarded"}`, хотя реальный forward к `self._upstream_proc` не реализован.

```python
# mcp_proxy.py — check_and_forward
result = self._engine.check(tool_name, args, session_id=session_id)
if result.verdict == Verdict.BLOCK:
    return {"blocked": True, ...}
return {"blocked": False, "status": "forwarded", ...}  # ← forwarding НЕ происходит
```

> [!CAUTION]
> **Влияние:** Все разрешённые MCP tool-вызовы молча отбрасываются — proxy обманывает клиента ответом "forwarded". Это не просто stub (Issue #8), а **активный обман** API consumer'а.

**Связь с Issue #8:** Issue #8 отмечает stub, но не фиксирует критичность fake response.

---

### 76. MCP Server: `kill`/`reload` через `to_thread` вместо native async — deadlock risk

**Файл:** [mcp_server.py#L149-L157](file:///Users/misha/PolicyShield/policyshield/mcp_server.py#L149-L157)

```python
await asyncio.to_thread(engine.kill, reason=reason)     # sync kill()
await asyncio.to_thread(engine.resume)                    # sync resume()
await asyncio.to_thread(engine.reload_rules)              # sync reload_rules()
```

`engine.kill()`, `engine.resume()`, `engine.reload_rules()` — sync-методы на `AsyncShieldEngine`, который **уже имеет** async-варианты (`async_kill()`, `async_reload()`). Sync-методы захватывают `threading.Lock`, который может конфликтовать с async `check()` → потенциальный deadlock.

> [!CAUTION]
> **Влияние:** При конкурентных `check()` и `kill()`/`reload()` через MCP Server возможен deadlock event loop.

---

### 77. `compile-and-apply` — idempotency key не проверяет description

**Файл:** [app.py](file:///Users/misha/PolicyShield/policyshield/server/app.py)

Endpoint `/api/v1/compile-and-apply` принимает `idempotency_key`, но при **повторном запросе** с тем же ключом возвращает кэшированный результат **без проверки, совпадает ли `description`**. Два вызова с одинаковым `idempotency_key`, но разным `description`, вернут результат первого вызова.

> [!CAUTION]
> **Влияние:** Злоумышленник или ошибка может привести к применению неправильных правил при повторном использовании idempotency key с другим описанием.

---

### 78. SessionManager + SessionBackend — два параллельных хранилища с рассинхронизацией

**Файлы:** [session.py](file:///Users/misha/PolicyShield/policyshield/shield/session.py), [session_backend.py](file:///Users/misha/PolicyShield/policyshield/shield/session_backend.py)

`SessionManager` хранит сессии в `self._sessions: dict[str, SessionState]`, при этом **параллельно** инициализирует `self._backend` (InMemory или Redis). Однако **ни один метод** SessionManager не использует `_backend` для чтения/записи — **все** операции (`get_or_create`, `increment`, `add_taint`, `remove`) идут через `self._sessions`.

```python
# session.py
self._backend = backend or InMemorySessionBackend(max_size=max_sessions)
# ↑ создаётся, но НИКОГДА не вызывается для get/put/delete
```

> [!CAUTION]
> **Влияние:** Redis backend **полностью мёртвый** — пользователь конфигурирует Redis URL, ожидает distributed sessions, но получает in-memory-only. Issue #10/#48 документирует это как Low/High, но реальная критичность — **обман пользователя** и **потеря данных** в distributed deployments.

---

### 79. Matcher: `eq`/`contains` предикаты — некорректное сравнение через `pattern.pattern`

**Файл:** [matcher.py#L87, L239-L247](file:///Users/misha/PolicyShield/policyshield/shield/matcher.py#L87)

При компиляции правил значение для `eq`/`contains` предикатов передаётся в `re.compile(value)`. При матчинге сравнение использует `pattern.pattern` — строковое представление regex:

```python
# Компиляция (строка 87):
compiled.arg_patterns.append((field_name, predicate, re.compile(value)))

# Матчинг (строка 241):
if arg_str != pattern.pattern:  # BUG: для строк с regex-метасимволами
    return False
```

Для строк содержащих regex-метасимволы (`.`, `(`, `)`, `[`, `*`, etc.) `re.compile(value).pattern` может отличаться от оригинального `value`, что вызывает **некорректные false negatives** при `eq` сравнении.

> [!CAUTION]
> **Влияние:** Правила с `eq` или `contains` предикатами, содержащими спецсимволы regex, могут никогда не совпасть или совпасть некорректно.

---

### 100. Telegram Bot: инъекция в Markdown через YAML preview

**Файл:** [telegram_bot.py](file:///Users/misha/PolicyShield/policyshield/bot/telegram_bot.py#L282-L313)

Бот отправляет `result.yaml_text` напрямую в Markdown-сообщение через code block без экранирования. Если YAML содержит тройные backtick'и, это ломает Markdown-парсинг Telegram, позволяя инжектировать произвольный контент, включая кликабельные фишинговые ссылки.

```python
# L312: yaml_preview вставляется напрямую, без escape
f"📝 *Compiled rules* ...:\n\n```yaml\n{yaml_preview}\n```\n\nDeploy to server?"
```

> [!CAUTION]
> **Влияние:** Атакующий может через NL→YAML компилятор подсунуть текст, ломающий Markdown и добавляющий фишинговые ссылки в сообщение бота.

---

### 101. Telegram Bot: `_deploy` перезаписывает весь файл правил вместо merge

**Файл:** [telegram_bot.py](file:///Users/misha/PolicyShield/policyshield/bot/telegram_bot.py#L348-L351)

Deploy через Telegram **полностью заменяет** файл правил на скомпилированный YAML. Все ранее настроенные правила уничтожаются:

```python
self._rules_path.write_text(yaml_text, encoding="utf-8")  # L350: полная перезапись
```

> [!CAUTION]
> **Влияние:** Каждый deploy через бот удаляет все существующие правила. **Отличие от Issue #29:** compile-and-apply делает неправильный merge, а Telegram bot — полную замену. Другой code path, более разрушительное поведение.

---

### 102. Session Manager: мутация `SessionState.total_calls/tool_counts` вне lock

**Файл:** [session.py](file:///Users/misha/PolicyShield/policyshield/shield/session.py#L84-L97)

`increment()` освобождает lock **перед** возвратом, но возвращает мутабельный `SessionState`. Engine продолжает читать `session.total_calls` и `session.tool_counts` вне lock:

```python
def increment(self, session_id: str, tool_name: str) -> SessionState:
    with self._lock:
        session = self._get_or_create_unlocked(session_id)
        session.increment(tool_name)
    return session  # L97: мутабельный объект вне lock
```

> [!CAUTION]
> **Влияние:** При параллельных `check()` на одну сессию — double-counting и race на `total_calls`. **Отличие от Issue #32:** Issue #32 описывает race на `taints`, здесь — `total_calls`/`tool_counts`.

---

### 103. Sanitizer `_flatten_to_string`: OOM через dict с 100K+ мелких ключей

**Файл:** [sanitizer.py](file:///Users/misha/PolicyShield/policyshield/shield/sanitizer.py#L210-L215)

Проверка размера считает только последние 10 элементов. Dict с 100K ключей по 1 символу = проверка проходится, OOM:

```python
if sum(len(p) for p in parts[-10:]) + len(parts) > _max_size and len(parts) > 100:
    return  # Проверяет только последние 10 элементов!
```

> [!CAUTION]
> **Влияние:** Exploitable OOM DoS. **Отличие от Issue #53 (Medium):** Issue #53 описывает неэффективность формулы. Здесь — конкретный attack vector: 100K+ мелких ключей полностью обходят проверку.

---

### 104. Rate Limiter: engine использует `check()`+`record()` вместо атомарного `check_and_record()`

**Файл:** [base_engine.py](file:///Users/misha/PolicyShield/policyshield/shield/base_engine.py)

`_do_check_sync()` вызывает `rate_limiter.check()` и `rate_limiter.record()` раздельно. Параллельные потоки проходят лимит между check и record:

```python
rl_result = self._rate_limiter.check(tool_name, session_id)  # неатомарная проверка
# ... логика ...
self._rate_limiter.record(tool_name, session_id)  # запись отдельно
```

> [!CAUTION]
> **Влияние:** Bypass rate limit при параллельных запросах. **Отличие от Issue #90 (Medium):** Issue #90 описывает API design. Здесь — **engine сам использует небезопасный path** в production.

---

### 125. `_default_engine` в decorators — глобальный singleton без cleanup

**Файл:** [decorators.py](file:///Users/misha/PolicyShield/policyshield/decorators.py#L111-L126)

```python
_default_engine: Any = None
_default_engine_lock: threading.Lock = threading.Lock()

def _get_default_engine() -> Any:
    global _default_engine
    with _default_engine_lock:
        if _default_engine is not None:
            return _default_engine
        rules_path = os.environ.get("POLICYSHIELD_RULES", "policies/rules.yaml")
        _default_engine = ShieldEngine(rules=rules_path)
        return _default_engine
```

Комбинация проблем:
1. **Module-level mutable global** — тесты и приложения с разными конфигурациями разделяют один engine
2. **Нет API для сброса** — `_default_engine` невозможно очистить или пересоздать без monkey-patching
3. **Watcher/Tracer не закрываются** — если default engine создаёт watcher/tracer, они утекают при завершении
4. **Env-var читается однократно** — изменение `POLICYSHIELD_RULES` после первого вызова `@guard()` игнорируется

> [!CAUTION]
> **Влияние:** State leakage между тестами. В production — невозможность переконфигурировать default engine. **Отличие от Issue #42:** Issue #42 описывает sync→async crash, здесь — lifecycle и state management проблемы самого singleton.

---

### 126. MCP Proxy `check_and_forward()` — APPROVE проваливается к "forwarded", bypass approval

**Файл:** [mcp_proxy.py](file:///Users/misha/PolicyShield/policyshield/mcp_proxy.py#L49-L75)

```python
async def check_and_forward(self, tool_name, arguments, session_id="mcp-proxy"):
    result = await self.engine.check(tool_name, arguments, session_id=session_id)
    if result.verdict.value == "BLOCK":
        return {"blocked": True, ...}
    # APPROVE — проваливается сюда → "forwarded" без approval!
    return {"blocked": False, "verdict": result.verdict.value, ...}
```

Вердикт APPROVE обрабатывается как ALLOW — MCP Proxy полностью обходит human-in-the-loop approval.

> [!CAUTION]
> **Влияние:** Полный bypass approval workflow через MCP Proxy. **Отличие от Issues #47/#64/#65:** те про CrewAI/LangChain, здесь — MCP Proxy (другой transport).

---

### 144. Webhook `submit()` exhausts `asyncio.to_thread` pool при concurrent approvals

**Файл:** [webhook.py](file:///Users/misha/PolicyShield/policyshield/approval/webhook.py#L95-L104)

`WebhookApprovalBackend.submit()` выполняет HTTP-запрос **синхронно** (строки 100-102). В `async_engine.py` метод `_do_check()` вызывает `submit()` через `await asyncio.to_thread(...)`. Каждый approval request блокирует один thread из дефолтного pool (обычно 8 workers) на 30-300 секунд. При 8+ одновременных approval-запросах **весь thread pool исчерпывается** и все `asyncio.to_thread()` вызовы (включая PII scan, rule matching) встают в очередь.

```python
def submit(self, request: ApprovalRequest) -> None:
    if self._mode == "sync":
        resp = self._sync_request(request)   # 30s блокировка
    else:
        resp = self._poll_request(request)    # 300s блокировка!
```

> [!CAUTION]
> **Влияние:** Полный thread pool starvation при burst approvals. Отличие от #16: здесь не просто блокировка одного вызова, а **каскадная деградация всего async engine** из-за исчерпания shared thread pool.

---

### 145. PII `_scan_list` + `scan_dict` — memory DoS через unbounded matches

**Файл:** [pii.py](file:///Users/misha/PolicyShield/policyshield/shield/pii.py#L291-L325)

`_scan_list` ограничивает **глубину** вложенности (20), но не ограничивает **ширину** (количество элементов на уровне). `scan_dict` аналогично не ограничивает общее число matches:

```python
def _scan_list(self, items: list, prefix: str, _depth: int = 0):
    if _depth > 20:
        return []  # только глубина!
    for i, item in enumerate(items):  # len(items) не лимитирован
        if isinstance(item, str):
            matches.extend(self.scan(item, field_name))  # unbounded
```

List из 1M строк по 50K символов: regex scan всех строк + миллионы `PIIMatch` объектов в памяти.

> [!CAUTION]
> **Влияние:** Memory DoS — исчерпание RAM без каких-либо ограничений. Отличие от #112 (CPU DoS): здесь конкретно **memory exhaustion** через unbounded list элементов и accumulation `PIIMatch` объектов.

---

### 146. Watcher `_reload` callback races с `check()` — stale `MatcherEngine`

**Файл:** [watcher.py](file:///Users/misha/PolicyShield/policyshield/shield/watcher.py#L132-L136), [base_engine.py](file:///Users/misha/PolicyShield/policyshield/shield/base_engine.py#L726-L738)

`_reload()` в watcher вызывает `self._callback(new_ruleset)`, что приводит к `_swap_rules()` в `base_engine.py`. `_swap_rules()` использует `self._rules_lock`, но:
1. Parsing (`load_rules`) выполняется **вне lock**
2. Старый `MatcherEngine` может быть **в процессе итерации** по правилам в другом потоке
3. Между `_has_changes()` и `_reload()` нет атомарности — файл может измениться

```python
# watcher.py — _watch_loop
if self._has_changes():
    self._reload()        # callback без синхронизации с check()
self._consecutive_failures = 0
```

> [!CAUTION]
> **Влияние:** Data race между hot-reload и текущими проверками. Отличие от #6 (file lock) и #25 (TOCTOU): здесь race condition между **watcher callback и engine check()**, а не между файловыми операциями.

---

### 127. Telegram Bot `_pending` dict — кросс-chat state collision

**Файл:** [telegram_bot.py](file:///Users/misha/PolicyShield/policyshield/bot/telegram_bot.py#L74)

```python
self._pending: dict[int, str] = {}  # chat_id → yaml_text
```

`_pending` индексируется по `chat_id`. Если пользователь отправляет два compile-запроса подряд до нажатия Deploy/Cancel, второй **перезаписывает** первый. При нажатии "Deploy" к первому сообщению (callback на message_id первого preview), деплоится **YAML второго запроса**, а не того, что показан в preview.

> [!CAUTION]
> **Влияние:** Пользователь видит preview одних правил, а деплоит другие. Потенциальная подмена security policy.

---

### 128. Server `verify_token` — timing side-channel (нет constant-time сравнения)

**Файл:** [app.py](file:///Users/misha/PolicyShield/policyshield/server/app.py#L63-L100)

```python
if auth_header != f"Bearer {required}":
    raise HTTPException(status_code=401, ...)
```

Сравнение токенов через `!=` (строковое сравнение) подвержено timing attack. `hmac.compare_digest` используется в webhook signature verification, но **не** для API token. Атакующий может побайтно подобрать токен, измеряя время ответа.

> [!CAUTION]
> **Влияние:** API token и Admin token можно подобрать через timing attack, получив доступ к `/kill`, `/reload`, `/compile-and-apply`.

---

### 154. `compile-and-apply` — non-atomic YAML write, watcher видит partial file

**Файл:** [server/app.py](file:///Users/misha/PolicyShield/policyshield/server/app.py#L649-L658)

`compile-and-apply` пишет YAML через `rules_path.write_text(...)` (строка 652). Это **неатомарная** операция на уровне ОС: файл сначала truncate'ится до 0 байт, затем пишется новое содержимое. Если `RuleWatcher` поллит **между truncate и write** — он увидит пустой или частичный файл:

```python
# server/app.py L652-653
rules_path.write_text(
    yaml.dump(existing_data, ...),  # неатомарно: truncate + write
    encoding="utf-8",
)
# ❗ watcher может увидеть пустой файл здесь
engine.reload_rules()  # L658
```

Правильный подход: write-to-temp + `os.rename()` (atomic на одной FS).

> [!CAUTION]
> **Влияние:** Watcher может подхватить пустой/corrupt файл → crash или потеря всех правил. **Отличие от #6:** #6 про file lock (конкурентный доступ), здесь — non-atomic write (частичная видимость).

---

### 155. `BudgetTracker._session_spend` — unbounded dict, нет eviction

**Файл:** [budget.py](file:///Users/misha/PolicyShield/policyshield/shield/budget.py#L37)

`_session_spend: dict[str, float]` накапливает записи для каждого `session_id` без какого-либо TTL или eviction. В production с 100K+ уникальными sessions — unbounded memory growth:

```python
class BudgetTracker:
    def __init__(self, ...):
        self._session_spend: dict[str, float] = {}  # ❗ нет max_size, нет TTL
        self._hourly_entries: list[tuple[float, float]] = []  # чистится в check_budget

    def record_spend(self, session_id, tool_name):
        self._session_spend[session_id] = ...  # никогда не удаляется!
```

`_hourly_entries` чистится в `check_budget()`, но `_session_spend` — **никогда**.

> [!CAUTION]
> **Влияние:** Unbounded memory в long-running production. Полностью новый issue — `BudgetTracker` не упоминается ни в одном существующем issue.

---
