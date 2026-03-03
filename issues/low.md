# 🔵 Низкоприоритетные замечания (Low)

Всего: **28** issues

[← Вернуться к оглавлению](ISSUES.md)

---

### 10. `SessionManager._backend` — never used

[session.py](file:///Users/misha/PolicyShield/policyshield/shield/session.py#L32) — `self._backend` инициализируется (`InMemorySessionBackend`), но:
- Все операции (`get_or_create`, `increment`, `add_taint`) работают с `self._sessions` dict **напрямую**
- Backend используется **только** в `stats()` для получения `backend_stats`
- `SessionBackend` — мёртвый абстрактный интерфейс, не интегрирован

---

### 11. Sanitizer size check — O(n²)

[sanitizer.py#L214](file:///Users/misha/PolicyShield/policyshield/shield/sanitizer.py#L214):
```python
if sum(len(p) for p in parts[-10:]) + len(parts) > _max_size and len(parts) > 100:
```
Это проверяет только последние 10 элементов — **не суммарный размер**. Атакующий может обойти лимит, подавая множество коротких строк.

---

### 12. `post_check` skips PII for large `str(result)`

[base_engine.py#L603](file:///Users/misha/PolicyShield/policyshield/shield/base_engine.py#L603):
```python
output_str = str(result) if not isinstance(result, str) else result
```
Для dict/list `str()` создаёт Python repr, а не JSON. Далее output_rules patterns матчатся против `repr()` строки. PII scan (`scan`/`scan_dict`) проверяет **оригинальный** `result`. Несоответствие между тем, что проверяют output rules и PII scan.

---

### 13. Production concern: `_logger` defined inside `create_app()`

[app.py#L112](file:///Users/misha/PolicyShield/policyshield/server/app.py#L112) — `_logger` определяется **внутри фабричной функции** `create_app()`, а не на уровне модуля. Это нормально функционально, но если `create_app()` вызывается несколько раз (e.g. в тестах), каждый раз создаётся новый logger reference.

---

### 26. Arg matching — `re.compile` для non-regex предикатов

**Файл:** [matcher.py#L87](file:///Users/misha/PolicyShield/policyshield/shield/matcher.py#L87)

Значение для `eq`/`contains` предикатов упаковывается в `re.compile(value)`, а потом достаётся через `.pattern`. Бессмысленная работа и сбивающая с толку архитектура. Функционально корректно, но расточительно.

---

### 58. Decorator `_rebuild_args` не работает с variadic сигнатурами

**Файл:** [decorators.py](file:///Users/misha/PolicyShield/policyshield/decorators.py#L64-L66)

Комментарий в коде документирует ограничение: функции с `*args` или `**kwargs` получат некорректные аргументы после `REDACT` модификации. Workaround отсутствует.

---

### 59. Slack `health()` — фейковая проверка

**Файл:** [slack.py](file:///Users/misha/PolicyShield/policyshield/approval/slack.py#L94-L95)

```python
def health(self) -> dict[str, Any]:
    return {"healthy": True, "backend": "slack", "webhook_configured": bool(self._webhook_url)}
```

Всегда возвращает `healthy: True` без HTTP запроса. `WebhookApprovalBackend.health()` и `TelegramApprovalBackend.health()` делают реальные проверки connectivity. Slack — нет.

---

### 60. SDK `CheckResult.verdict` — `str` вместо `Verdict` enum

**Файл:** [sdk/client.py](file:///Users/misha/PolicyShield/policyshield/sdk/client.py#L21)

```python
@dataclass
class CheckResult:
    verdict: str  # не Verdict enum!
```

Пользователи SDK сравнивают `result.verdict == "BLOCK"` (строка), в то время как engine и декораторы используют `Verdict.BLOCK` (enum). Опечатка `"block"` молча проваливается.

---

### 61. LLM Guard cache — FIFO eviction без TTL-check

**Файл:** [llm_guard.py](file:///Users/misha/PolicyShield/policyshield/shield/llm_guard.py#L208-L213)

```python
def _put_cache(self, key, result):
    if len(self._cache) >= self._max_cache_size:
        oldest = next(iter(self._cache))  # FIFO по порядку вставки
        del self._cache[oldest]
```

Eviction вытесняет самый старый по **времени вставки**, а не least-recently-used и не ближайший к expiry. Часто используемый hot entry может быть вытеснен, пока редко используемый stale entry (вставленный позже) остаётся.

---

### 71. CLI Doctor парсит rules файл дважды

**Файл:** [doctor.py](file:///Users/misha/PolicyShield/policyshield/cli/doctor.py#L89-L127)

Проверки 2 и 3 независимо вызывают `yaml.safe_load(rules_path.read_text())`, читая и парся один и тот же файл дважды вместо переиспользования результата.

---

### 72. Auto-rules — `default_verdict` параметр неиспользуемый

**Файл:** [auto_rules.py](file:///Users/misha/PolicyShield/policyshield/ai/auto_rules.py#L57-L93)

Параметр `default_verdict` принимается, но никогда не используется в логике фильтрации. Строка 79 всегда пропускает SAFE/MODERATE вне зависимости от значения default (`block` или `allow`), что делает параметр вводящим в заблуждение.

---

### 73. Trace Recorder — тихая потеря аудит-записей при сбоях диска

**Файл:** [trace/recorder.py](file:///Users/misha/PolicyShield/policyshield/trace/recorder.py#L186-L213)

Когда запись на диск не удаётся, буфер растёт до `batch_size * 10`, затем самые старые записи **тихо отбрасываются**. Нет механизма алертинга, нет callback'а, нет fallback (например, дамп в stderr). В контейнерном окружении с полным tmpfs это означает тихую потерю аудит-записей с единственным предупреждением в логе.

---

### 74. LangChain `_arun()` — async через `to_thread(sync_run)` вместо native async

**Файл:** [langchain/wrapper.py](file:///Users/misha/PolicyShield/policyshield/integrations/langchain/wrapper.py#L76-L80)

```python
async def _arun(self, *args, **kwargs):
    return await asyncio.to_thread(self._run, *args, **kwargs)
```

Async-версия просто оборачивает sync `_run` в thread. Если engine — `AsyncShieldEngine`, он не используется; всегда вызывается sync `ShieldEngine.check()`, блокируя thread. Нет возможности передать async engine через конструктор — тип жёстко привязан к `ShieldEngine`.

---

### 96. `ApprovalRequest` не маскирует PII/секреты в args

**Файл:** [approval/base.py#L23-L40](file:///Users/misha/PolicyShield/policyshield/approval/base.py#L23-L40)

`ApprovalRequest.create()` сохраняет `args` as-is. Если args содержат PII или секреты, они будут переданы в webhook/Slack/Telegram открытым текстом без маскировки.

---

### 97. Config: `load_schema()` без graceful fallback

**Файл:** [config/loader.py#L364-L366](file:///Users/misha/PolicyShield/policyshield/config/loader.py#L364-L366)

`load_schema()` читает `schema.json` из файловой системы. Если файл отсутствует или повреждён, поднимается необработанный `FileNotFoundError` или `json.JSONDecodeError` без user-friendly сообщения.

---

### 98. Trace: `cleanup_old_traces()` никогда не вызывается автоматически

**Файл:** [trace/recorder.py#L244-L260](file:///Users/misha/PolicyShield/policyshield/trace/recorder.py#L244-L260)

Метод `cleanup_old_traces()` существует, но **ни один** компонент системы не вызывает его автоматически. `retention_days` настроен, но trace файлы накапливаются бесконечно, пока пользователь не вызовет метод вручную.

---

### 99. Redis Session Backend: `count()` выполняет full SCAN — O(N)

**Файл:** [session_backend.py#L194-L200](file:///Users/misha/PolicyShield/policyshield/shield/session_backend.py#L194-L200)

```python
def count(self) -> int:
    cursor, keys = self._client.scan(0, match=f"{self._prefix}*", count=100)
    total = len(keys)
    while cursor:
        cursor, keys = self._client.scan(cursor, ...)
        total += len(keys)
    return total
```

`count()` выполняет full `SCAN` по Redis, что при большом числе ключей блокирует Redis и вызывающий поток. `stats()` вызывает `count()`, усугубляя проблему при частых health-check запросах.

---

### 120. Telegram Bot: `run_bot()` не вызывает `bot.stop()` при KeyboardInterrupt

**Файл:** [telegram_bot.py](file:///Users/misha/PolicyShield/policyshield/bot/telegram_bot.py)

`run_bot()` перехватывает `KeyboardInterrupt`, но не вызывает `bot.stop()`. `httpx.Client` и фоновые потоки не освобождаются, вызывая предупреждения о незакрытых ресурсах.

---

### 121. Approval Backend ABC: `get_status()` отсутствует → `AttributeError`

**Файл:** [approval/base.py](file:///Users/misha/PolicyShield/policyshield/approval/base.py)

ABC `ApprovalBackend` не определяет `get_status()` как abstractmethod. Engine вызывает `backend.get_status()` в approval flow. Кастомный backend без `get_status()` вызовет `AttributeError` в runtime.

---

### 122. `render_config()` пропускает `rate_limits` секцию

**Файл:** [config/loader.py](file:///Users/misha/PolicyShield/policyshield/config/loader.py)

`render_config()` преобразует `PolicyShieldConfig` обратно в YAML, но не включает `rate_limits`. Round-trip через `load_config()` → `render_config()` теряет настройки rate limiting.

---

### 123. CrewAI wrapper: `run()` alias может конфликтовать с `BaseTool.run()`

**Файл:** [crewai/wrapper.py](file:///Users/misha/PolicyShield/policyshield/integrations/crewai/wrapper.py)

`CrewAIShieldTool` определяет `run()` как alias для `_run()`. `BaseTool` в CrewAI уже имеет `run()`, который оборачивает `_run()` с дополнительной логикой. Переопределение обходит логику framework.

---

### 124. `_bind_args` fallback теряет positional аргументы

**Файл:** [decorators.py](file:///Users/misha/PolicyShield/policyshield/decorators.py#L130-L155)

Fallback в `_bind_args()` используется когда `inspect.signature` не может привязать args. Fallback возвращает только `kwargs`, полностью теряя positional аргументы. PolicyShield проверяет неполный args dict.

---

### 140. `InMemoryBackend._start_gc()` — daemon Timer при каждом reschedule

**Файл:** [memory.py](file:///Users/misha/PolicyShield/policyshield/approval/memory.py#L49-L55)

`_start_gc()` создаёт новый `threading.Timer` daemon thread при каждом reschedule. При длительной работе создаётся один daemon thread каждые 60 секунд — лишняя нагрузка на threading subsystem.

---

### 141. Telegram Bot `_client` — shared `httpx.AsyncClient` для Telegram API и Server API

**Файл:** [telegram_bot.py](file:///Users/misha/PolicyShield/policyshield/bot/telegram_bot.py#L69)

Один `httpx.AsyncClient` используется и для Telegram API (`api.telegram.org`) и для PolicyShield Server (`localhost:8100`). Timeout 30s от Telegram long-polling может заблокировать Server API calls если connection pool исчерпан.

---

### 142. `MCPProxy` — `upstream_command` always empty list

**Файл:** [mcp_proxy.py](file:///Users/misha/PolicyShield/policyshield/mcp_proxy.py#L94)

```python
proxy = MCPProxy(engine, [])  # empty list always
```

`create_mcp_proxy_server` всегда создаёт proxy с пустым `upstream_command`. Параметр в API подразумевает configurability, но фактически hardcoded.

---

### 143. `_SlidingWindow.count_in_window` — side effect в read-only метод

**Файл:** [rate_limiter.py](file:///Users/misha/PolicyShield/policyshield/shield/rate_limiter.py#L40-L45)

```python
def count_in_window(self, now: float, window: float) -> int:
    cutoff = now - window
    while self.timestamps and self.timestamps[0] <= cutoff:
        self.timestamps.popleft()  # mutates state!
    return len(self.timestamps)
```

Метод с именем `count_in_window` (подразумевающий read-only) **мутирует** deque, удаляя expired timestamps. `_SlidingWindow` сам по себе не thread-safe.

---

### 153. Telegram Bot `_pending` dict без TTL — unbounded memory growth

**Файл:** [telegram_bot.py](file:///Users/misha/PolicyShield/policyshield/bot/telegram_bot.py#L74)

`_pending: dict[int, str]` хранит compiled YAML до deploy/cancel. Если пользователь отправляет compile-запрос но никогда не нажимает Deploy/Cancel — YAML остаётся в памяти навсегда:

```python
self._pending: dict[int, str] = {}  # chat_id → yaml_text, нет TTL/eviction
```

Отличие от #127 (коллизия): здесь про **memory leak** при abandon, а не про перезапись.

> [!NOTE]
> **Влияние:** Небольшой memory leak при длительной работе бота с многочисленными пользователями.

---

### 160. LLM Guard `_cache` dict без `threading.Lock` — concurrent mutation

**Файл:** [llm_guard.py](file:///Users/misha/PolicyShield/policyshield/shield/llm_guard.py#L96)

`LLMGuard._cache` — обычный `dict` без lock. В `async_engine.py` `_call_llm_guard()` вызывается из `asyncio.to_thread`, создавая конкурентные `_get_cached()` / `_put_cache()` из разных потоков:

```python
class LLMGuard:
    def __init__(self, config):
        self._cache: dict[str, tuple[GuardResult, float]] = {}  # ❗ нет Lock

    def _get_cached(self, key):   # из thread A
        entry = self._cache.get(key)  # read

    def _put_cache(self, key, result):  # из thread B
        if len(self._cache) >= self._max_cache_size:
            oldest = next(iter(self._cache))  # ❗ может упасть
            del self._cache[oldest]
        self._cache[key] = (result, time.monotonic())
```

Отличие от #66 (TOCTOU в get+put): здесь более базовая проблема — **отсутствие lock на dict**, `RuntimeError: dictionary changed size during iteration`.

> [!NOTE]
> **Влияние:** Crash при конкурентном analyze() с eviction. Prerequisite для #66.

---

