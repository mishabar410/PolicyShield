# 🟡 Средние проблемы (Medium) ✅

Всего: **0** issues (все 29 исправлены ✅)

[← Вернуться к оглавлению](../ISSUES.md)

---

### ~~67. Dockerfile — несовпадение версий Python~~ ✅ Fixed

**Файлы:** [Dockerfile](file:///Users/misha/PolicyShield/Dockerfile) (Python 3.13) vs [Dockerfile.server](file:///Users/misha/PolicyShield/Dockerfile.server) (Python 3.12)

Два Dockerfile'а используют разные версии Python:
- `Dockerfile` — `python:3.13-slim` с multi-stage сборкой
- `Dockerfile.server` — `python:3.12-slim` без multi-stage, `pip install` выполняется от root до создания non-root user

Дополнительно, `Dockerfile.server` копирует `examples/fastapi_agent/policies/rules.yaml` как правила по умолчанию — **example-правила зашиты в production-образ**.

---

### ~~92. Shell injection detector — false positives на backtick-текст~~ ✅ Fixed

**Файл:** [detectors.py#L84-L96](file:///Users/misha/PolicyShield/policyshield/shield/detectors.py#L84-L96)

Regex `` `[^`]+` `` (backtick command substitution) срабатывает на **любой** строке в backticks — Markdown code blocks, SQL идентификаторы, template literals. AI-инструменты часто генерируют backtick-форматированный текст → массовые false positives.

> [!WARNING]
> **Влияние:** Легитимные tool-вызовы блокируются из-за backtick-форматирования в аргументах.

---

### ~~114. LangChain wrapper: `post_check` полностью отсутствует~~ ✅ Fixed

**Файл:** [langchain/wrapper.py](file:///Users/misha/PolicyShield/policyshield/integrations/langchain/wrapper.py#L52-L80)

В отличие от CrewAI wrapper, LangChain вообще **не вызывает** `post_check()`. Output rule и PII redaction не применяются к результатам tool.

> [!WARNING]
> **Влияние:** PII leakage в LangChain pipelines.

---

### ~~117. Watcher: удаление YAML-файлов не обрабатывается~~ ✅ Fixed

**Файл:** [watcher.py](file:///Users/misha/PolicyShield/policyshield/shield/watcher.py#L55-L73)

`_scan_mtimes()` возвращает mtime dict только существующих файлов. `_has_changes()` сравнивает **только** текущий mtime с предыдущим, но **не детектирует** исчезнувшие ключи. Удалённый rule-файл продолжает действовать.

> [!WARNING]
> **Влияние:** Удаление rule-файла не отражается в engine до рестарта.

---

### ~~152. InMemoryBackend `get_status()` timeout race с `respond()`~~ ✅ Fixed

**Файл:** [approval/memory.py](file:///Users/misha/PolicyShield/policyshield/approval/memory.py#L82-L117)

При timeout detection в `get_status()`: создаётся `ApprovalResponse`, удаляется request, устанавливается event. Если `respond()` вызывается одновременно, он может перезаписать timeout response, нарушая first-response-wins гарантию.

> [!WARNING]
> **Влияние:** Легитимный ответ approve/deny может быть тихо отброшен, а timeout auto-response применится вместо реального решения человека.

---

### ~~161. `compile-and-apply` — `rules_path` может быть директорией~~ ✅ Fixed

**Файл:** [app.py#L612](file:///Users/misha/PolicyShield/policyshield/server/app.py#L612)

```python
existing_data = yaml.safe_load(rules_path.read_text(encoding="utf-8"))
```

`engine._rules_path` может быть директорией (default: `./policies/`). `read_text()` на директории поднимет `IsADirectoryError`. В `load_rules()` (`parser.py#L141`) директория обрабатывается корректно, но `compile-and-apply` предполагает файл.

---

### ~~162. Вложенные thread pool + event loop при LLM Guard~~ ✅ Fixed

**Файлы:** [engine.py#L55-L65](file:///Users/misha/PolicyShield/policyshield/shield/engine.py#L55-L65) + [base_engine.py#L317-L319](file:///Users/misha/PolicyShield/policyshield/shield/base_engine.py#L317-L319)

`ShieldEngine.check()` использует `ThreadPoolExecutor` для timeout. Внутри `_do_check_sync()`, если LLM Guard enabled, вызывается `asyncio.run()`, который создаёт ещё один event loop. Итого: thread pool → thread → new event loop → HTTP-вызов LLM API. Трёхуровневая вложенность execution contexts.

---

### ~~163. `_evict_oldest` в `SessionManager` не синхронизирует backend~~ ✅ Fixed

**Файл:** [session.py#L205-L220](file:///Users/misha/PolicyShield/policyshield/shield/session.py#L205-L220)

```python
def _evict_oldest(self) -> None:
    lru_id = min(self._sessions, key=lambda sid: (...))
    del self._sessions[lru_id]
    # ← нет self._backend.delete(lru_id)
```

При eviction по ёмкости сессия удаляется из in-memory dict, но не из backend. В `get()` и `_get_or_create_unlocked()` при expired сессиях backend вызывается. Но при capacity eviction — нет.

---

### ~~164. `_SlidingWindow` в `RateLimiter` не thread-safe~~ ✅ Fixed

**Файл:** [rate_limiter.py](file:///Users/misha/PolicyShield/policyshield/shield/rate_limiter.py)

`_SlidingWindow` использует `collections.deque` без синхронизации. `RateLimiter.check_and_record()` вызывается из `_do_check_sync()` без `self._lock`. В async engine — из thread pool. Concurrent `deque.append()` + iteration при complex operations может привести к data race.

---

### ~~165. Content-Type middleware пропускает пустой header~~ ✅ Fixed

**Файл:** [app.py#L188](file:///Users/misha/PolicyShield/policyshield/server/app.py#L188)

```python
if ct and "application/json" not in ct:
```

Если `Content-Type` header отсутствует (пустая строка), проверка пропускается (`if ct` → False). Middleware создаёт впечатление строгой валидации, которая фактически отсутствует для запросов без Content-Type.

---

### ~~173. Session TTL по `created_at` вместо last access — активные сессии удаляются~~ ✅ Fixed

**Файл:** [session.py#L187-L189](file:///Users/misha/PolicyShield/policyshield/shield/session.py#L187-L189)

```python
def _is_expired(self, session: SessionState) -> bool:
    return datetime.now(timezone.utc) - session.created_at > timedelta(seconds=self._ttl_seconds)
```

Сессия истекает через `ttl_seconds` от **создания**, а не от **последнего обращения**. Активная сессия с постоянными запросами будет удалена через час, потеряв все counters, taints и event buffer. Стандартный паттерн TTL — по last access, как в Redis `EXPIRE`.

> [!WARNING]
> **Влияние:** Активные long-running сессии теряют state без предупреждения. Taint chain разрывается, rate limit counters сбрасываются.

---

### ~~174. Content-Type check middleware не покрывает compile endpoints~~ ✅ Fixed

**Файл:** [app.py#L175-L181](file:///Users/misha/PolicyShield/policyshield/server/app.py#L175-L181)

```python
_json_only_paths = {
    "/api/v1/check",
    "/api/v1/post-check",
    "/api/v1/check-approval",
    "/api/v1/clear-taint",
    "/api/v1/respond-approval",
}
```

Отсутствуют `/api/v1/compile` и `/api/v1/compile-and-apply`. Эти POST endpoints ожидают JSON, но не защищены Content-Type валидацией.

---

### ~~175. Backpressure middleware не покрывает `compile-and-apply`~~ ✅ Fixed

**Файл:** [app.py#L223](file:///Users/misha/PolicyShield/policyshield/server/app.py#L223)

```python
if request.url.path in ("/api/v1/check", "/api/v1/post-check", "/api/v1/check-approval"):
```

`compile-and-apply` — самый тяжёлый endpoint (LLM API call + file I/O + rule reload). Не защищён backpressure semaphore. Множественные параллельные вызовы могут перегрузить сервер и исчерпать OpenAI rate limits.

---

### ~~176. CrewAI wrapper: `post_check` coroutine не await'ится с async engine~~ ✅ Fixed

**Файл:** [crewai/wrapper.py#L112-L116](file:///Users/misha/PolicyShield/policyshield/integrations/crewai/wrapper.py#L112-L116)

```python
self.engine.post_check(
    tool_name=self.name,
    result={"output": output} if isinstance(output, str) else output,
    session_id=self.session_id,
)
```

`self.engine` может быть `AsyncShieldEngine`, у которого `post_check()` — корутина. Вызов без `await` возвращает `coroutine` object, не выполняя PII-проверку. Python выведет предупреждение `RuntimeWarning: coroutine 'post_check' was never awaited`.

> [!WARNING]
> **Влияние:** PII в tool output'е не обнаруживается при использовании CrewAI с async engine.

---

### ~~177. `ThreadPoolExecutor` создаётся на каждый sync check call~~ ✅ Fixed

**Файл:** [engine.py#L59-L62](file:///Users/misha/PolicyShield/policyshield/shield/engine.py#L59-L62)

```python
if self._engine_timeout and self._engine_timeout > 0:
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
```

По дефолту `POLICYSHIELD_ENGINE_TIMEOUT=5.0` → каждый вызов `check()` создаёт и уничтожает `ThreadPoolExecutor`. При высоком RPS это значительный overhead на threading. Связано с Issue #157, но отдельная проблема: даже без таймаутов, per-call allocation дорогой. Решение — shared pool на уровне engine.

---

### ~~188. MCP Server `admin_token` — не декларирован в `inputSchema`~~ ✅ Fixed

**Файл:** [mcp_server.py#L153-L167](file:///Users/misha/PolicyShield/policyshield/mcp_server.py#L153-L167)

```python
if admin_token and arguments.get("admin_token") != admin_token:
    return [TextContent(type="text", text=json.dumps({"error": "Unauthorized"}))]
```

`admin_token` не указан в `inputSchema` инструментов `kill_switch`, `resume`, `reload`. MCP клиент не знает, что нужно передавать этот параметр → auth полностью broken.

> [!WARNING]
> **Влияние:** Admin auth на MCP сервере не работает — клиент никогда не отправит `admin_token` в arguments.

---

### ~~189. Server `_admin_limiter` — per-IP rate limit не работает за reverse proxy~~ ✅ Fixed

**Файл:** [app.py#L278](file:///Users/misha/PolicyShield/policyshield/server/app.py#L278)

```python
client_ip = request.client.host if request.client else "unknown"
```

За reverse proxy (nginx, ALB, CloudFront) `request.client.host` всегда == proxy IP. Все пользователи шарят один rate limit bucket. Не используется `X-Forwarded-For` или `X-Real-IP`.

> [!WARNING]
> **Влияние:** Admin rate limiting бесполезен за proxy — один клиент блокирует всех, или все обходят limit.

---

### ~~190. Telegram Bot `_deploy()` fallback — тихо перезаписывает правила при ошибке merge~~ ✅ Fixed

**Файл:** [telegram_bot.py#L398-L415](file:///Users/misha/PolicyShield/policyshield/bot/telegram_bot.py#L398-L415)

```python
except Exception:
    # Fallback: write raw yaml_text (still atomic)
```

Если merge логика падает (YAML parse error, file permissions, etc.), исключение тихо подавляется и записывается raw `yaml_text` — полностью **перезаписывая** все существующие правила. Пользователь не информируется о потере merge.

> [!WARNING]
> **Влияние:** Silent data loss — существующие правила перезаписываются без уведомления при любой ошибке merge.

---

### ~~191. Три `CheckResult` dataclass с несовместимыми полями~~ ✅ Fixed

**Файлы:**
- [client.py#L11-L19](file:///Users/misha/PolicyShield/policyshield/client.py#L11-L19) — `verdict`, `message`, `rule_id`, `modified_args`, `request_id`
- [sdk/client.py#L17-L29](file:///Users/misha/PolicyShield/policyshield/sdk/client.py#L17-L29) — добавляет `pii_types`, `approval_id`, `shield_version`

Связано с Issue #155, но дополнительный аспект: два **разных** `CheckResult` dataclass с несовместимыми полями. Код, переключающийся между клиентами, получает разные типы. `pii_types` недоступен при использовании `client.py`.

---

### ~~192. `AsyncPolicyShieldClient` (async_client.py) — отсутствуют критические методы~~ ✅ Fixed

**Файл:** [async_client.py](file:///Users/misha/PolicyShield/policyshield/async_client.py)

`async_client.py` не имеет: `post_check`, `reload`, `kill`, `resume`, `wait_for_approval`. `sdk/client.py` имеет полный API. Пользователь `async_client.py` не может выполнить PII scanning, emergency kill, или rule reload.

---

### ~~193. MCP Proxy `check_and_forward()` — string comparison для enum~~ ✅ Fixed

**Файл:** [mcp_proxy.py#L58-L67](file:///Users/misha/PolicyShield/policyshield/mcp_proxy.py#L58-L67)

```python
if result.verdict.value == "BLOCK":  # string comparison
```

Использует `.value == "BLOCK"` вместо `result.verdict == Verdict.BLOCK`. Работает, но fragile — если enum values изменятся, сравнение сломается без ошибки. Inconsistent с остальным кодом.

---

### ~~194. Plugin hooks — sync-only в async engine path~~ ✅ Fixed

**Файл:** [async_engine.py#L103-L109](file:///Users/misha/PolicyShield/policyshield/shield/async_engine.py#L103-L109)

```python
for hook_fn in _get_pre_hooks():
    try:
        hook_fn(tool_name=tool_name, args=args, ...)  # sync call in async path
```

`get_pre_check_hooks()` и `get_post_check_hooks()` вызываются синхронно в `_do_check()` (async engine). Если hook выполняет I/O (logging в файл, HTTP webhook, DB write), он блокирует event loop.

> [!WARNING]
> **Влияние:** Plugin hooks с I/O блокируют async event loop, вызывая latency spikes.

---

### ~~205. `shield()` decorator — `session_id` захватывается при декорировании~~ ✅ Fixed

**Файл:** [decorators.py#L28-L48](file:///Users/misha/PolicyShield/policyshield/decorators.py#L28-L48)

```python
def shield(engine, tool_name=None, session_id="default", on_block="raise", context=None):
    def decorator(func):
        ...
        async def async_wrapper(*args, **kwargs):
            result = await engine.check(name, all_kwargs, session_id=session_id, context=context)
```

`session_id` и `context` захватываются **один раз** при применении декоратора через замыкание. Все вызовы используют один и тот же `session_id="default"` — невозможно передать per-request `session_id` без обхода декоратора. Для multi-tenant/multi-session приложений декоратор бесполезен.

> [!WARNING]
> **Влияние:** Все запросы попадают в одну сессию → ломается per-session rate limiting, taint tracking и session-based conditions.

---

### ~~206. `TelegramApprovalBackend.wait_for_response()` — удаляет response~~ ✅ Fixed

**Файл:** [telegram.py#L115-L118](file:///Users/misha/PolicyShield/policyshield/approval/telegram.py#L115-L118)

```python
with self._lock:
    self._events.pop(request_id, None)
    return self._responses.pop(request_id, None)  # ← удаляет!
```

В отличие от `InMemoryBackend` (сохраняет responses для concurrent poll), `TelegramApprovalBackend` **удаляет** response после первого `wait_for_response()`. Повторный вызов (retry, timeout, стандартное polling) получит `None` — несогласованное поведение между backends.

> [!WARNING]
> **Влияние:** Потеря результата approval при retry/polling, ложный "pending" status с Telegram backend.

---

### ~~207. `_do_check` — `event_buffer` вне atomic snapshot~~ ✅ Fixed

**Файлы:** [async_engine.py#L184-L201](file:///Users/misha/PolicyShield/policyshield/shield/async_engine.py#L184-L201), [base_engine.py#L286-L300](file:///Users/misha/PolicyShield/policyshield/shield/base_engine.py#L286-L300)

```python
with self._lock:
    matcher = self._matcher
    rule_set = self._rule_set
    pii_detector = self._pii

# event_buffer запрашивается ПОСЛЕ release lock
event_buffer = self._session_mgr.get_event_buffer(session_id)
match = await asyncio.to_thread(matcher.find_best_match, ..., event_buffer=event_buffer)
```

`event_buffer` получается **вне** atomic snapshot. Если hot-reload происходит между lock release и `get_event_buffer()`, matcher и event_buffer оказываются из разных "поколений" конфигурации.

> [!WARNING]
> **Влияние:** Некорректная оценка chain rules при совпадении hot-reload и check evaluation.

---

### ~~213. `mode` setter не thread-safe (free-threading risk)~~ ✅ Fixed

**Файл:** [base_engine.py](file:///Users/misha/PolicyShield/policyshield/shield/base_engine.py)

```python
@mode.setter
def mode(self, value: ShieldMode) -> None:
    self._mode = value  # нет self._lock!
```

`_mode` читается в `check()` без lock (`if self._mode == ShieldMode.DISABLED`), а setter не использует `self._lock`. С GIL (CPython) это безопасно, но в Python 3.13+ free-threading режиме — data race. Все остальные mutable state (`_matcher`, `_rule_set`, `_pii`) защищены lock'ом.

> [!WARNING]
> **Влияние:** Потенциальный data race в будущем при переходе на free-threading Python. Inconsistency с остальным state management.

---

### ~~214. Plugin hooks — partial execution при timeout в sync engine~~ ✅ Fixed

**Файл:** [engine.py#L54-L78](file:///Users/misha/PolicyShield/policyshield/shield/engine.py#L54-L78) + [base_engine.py#L408-L417](file:///Users/misha/PolicyShield/policyshield/shield/base_engine.py#L408-L417)

В sync engine, `_do_check_sync()` оборачивается в `ThreadPoolExecutor` с timeout. Pre-check hooks вызываются в начале `_do_check_sync()`, а post-check hooks — в конце. Если timeout срабатывает **между** pre и post hooks:

1. Pre-check hooks уже выполнились (side effects committed)
2. Post-check hooks **не** выполнились
3. Engine возвращает fail-open/fail-closed verdict, но hook state — inconsistent

> [!WARNING]
> **Влияние:** Plugins получают non-atomic hook execution — pre-hooks видят call, post-hooks нет. Особенно критично для audit/compliance plugins.

---

### ~~215. Server `reload()` endpoint — sync I/O блокирует event loop~~ ✅ Fixed

**Файл:** [app.py#L460-L467](file:///Users/misha/PolicyShield/policyshield/server/app.py#L460-L467)

```python
@app.post("/api/v1/reload", response_model=ReloadResponse, dependencies=auth)
async def reload() -> ReloadResponse:
    engine.reload_rules()  # sync: file I/O + YAML parsing + lock
```

`reload_rules()` синхронно вызывает `load_rules()` (чтение файлов, YAML parse) + `_swap_rules()` (threading.Lock). В async FastAPI handler'е это блокирует event loop. Issue #182 описывает эту проблему для MCP server, но в FastAPI server (`app.py`) — та же ошибка не документирована.

> [!WARNING]
> **Влияние:** Все in-flight HTTP запросы замораживаются на время перезагрузки правил. При большом количестве правил — ощутимый latency spike.

---

### ~~216. `LLMGuard._http_client` не закрывается при engine shutdown~~ ✅ Fixed

**Файл:** [llm_guard.py](file:///Users/misha/PolicyShield/policyshield/shield/llm_guard.py)

`LLMGuard` lazy-инициализирует `httpx.AsyncClient` и имеет метод `close()` для cleanup. Но:
1. `BaseShieldEngine` не вызывает `self._llm_guard.close()` в деструкторе
2. `server/app.py` lifespan не вызывает `engine._llm_guard.close()`
3. `LLMGuard.close()` — async метод, который不能 быть вызван синхронно

Отличается от #203 (TOCTOU при lazy init) — здесь проблема в отсутствии cleanup при завершении.

> [!WARNING]
> **Влияние:** Resource leak (unclosed TCP connection pool) при каждом shutdown/restart сервера.

---
