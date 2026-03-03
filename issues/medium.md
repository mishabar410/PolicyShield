# 🟡 Средние проблемы (Medium)

Всего: **50** issues

[← Вернуться к оглавлению](ISSUES.md)

---

### 7. `_validated_when()` — context/session conditions не в `_VALID_WHEN_KEYS`

[parser.py#L13](file:///Users/misha/PolicyShield/policyshield/core/parser.py#L13):
```python
_VALID_WHEN_KEYS = {"tool", "args", "args_match", "sender", "session", "chain"}
```

Но README и matcher поддерживают `context` в `when` clause. Ключ `context` **не входит** в `_VALID_WHEN_KEYS`, и при его использовании будет warning «Unknown 'when' keys {'context'}». Работать будет (matcher подхватит), но это пугает пользователей.

---

### 8. MCP Proxy — не форвардит вызовы

[mcp_proxy.py](file:///Users/misha/PolicyShield/policyshield/mcp_proxy.py) заявлен как transparent proxy, но:
- `upstream_command` принимается но **никогда не используется**
- `subprocess.Popen` импортирован но не вызывается
- `handle_call_tool` возвращает JSON «forwarded» **не делая forwarding** — инструмент на самом деле не выполняется
- `handle_list_tools` генерирует список из **правил**, не из upstream сервера

Это по сути stub, а не proxy.

---

### 9. `RuleConfig.priority` — inverse semantics confusion

Конструктор `RuleConfig` по умолчанию `priority = 1`, а `compile-and-apply` ставит override-правилам `priority = 0`. Matcher сортирует ascending (lower = higher priority). Но это **нигде не документировано** — пользователь, написавший `priority: 10`, получит **самый низкий** приоритет, что контр-интуитивно.

---

### 22. `_resolve_extends` — child наследует `enabled: false` без предупреждения

**Файл:** [parser.py#L282](file:///Users/misha/PolicyShield/policyshield/core/parser.py#L282)

```python
merged = {**parent, **rule}
```

Если parent имеет `enabled: false`, а child **не указывает** `enabled`, он наследует `enabled: false`. Пользователь расширяет отключённый parent и не понимает, почему child-правило не работает. Не документировано в README.

---

### 23. `InMemoryBackend.health()` отсутствует — `/readyz` крашится

**Файл:** [approval/memory.py](file:///Users/misha/PolicyShield/policyshield/approval/memory.py)

`InMemoryBackend` не реализует метод `health()`. Readiness probe `/readyz` вызывает `backend.health()` ([app.py#L449](file:///Users/misha/PolicyShield/policyshield/server/app.py#L449)) — для `InMemoryBackend` это вызовет `AttributeError`.

> [!IMPORTANT]
> **Влияние:** Kubernetes readiness probe `/readyz` **крашится** если используется `InMemoryBackend` (по умолчанию для development).

---

### 24. `_check_chain` создаёт `ChainCondition` при каждом вызове

**Файл:** [matcher.py#L294-L311](file:///Users/misha/PolicyShield/policyshield/shield/matcher.py#L294-L311)

```python
def _check_chain(self, chain: list[dict], event_buffer) -> bool:
    for step in chain:
        cond = ChainCondition(**step)  # ← объект создаётся при КАЖДОМ match
```

Chain conditions **не pre-компилируются** в `CompiledRule` (в отличие от tool_pattern, arg_patterns, sender_pattern). Лишние аллокации при высокой нагрузке.

---

### 25. Watcher — TOCTOU + aggressive failure counting

**Файл:** [watcher.py#L84-L114](file:///Users/misha/PolicyShield/policyshield/shield/watcher.py#L84-L114)

После `_has_changes()` возвращает True, файл может быть удалён или изменён до `_reload()`. Ошибка считается failure. При частых изменениях файлов (git checkout, CI deploy) это может накопить failures и **остановить watcher** навсегда (after 10 consecutive failures).

---

### 35. Cross-file `extends` не работает в directory mode

**Файл:** [parser.py#L159-L227](file:///Users/misha/PolicyShield/policyshield/core/parser.py#L159-L227)

При загрузке из директории каждый файл парсится **независимо**. `_resolve_extends()` вызывается только для single-file case в `_build_ruleset()`. Правило с `extends: parent_rule`, где `parent_rule` в **другом файле**, будет молча проигнорировано.

> [!WARNING]
> **Влияние:** Пользователи с многофайловой конфигурацией не могут наследовать правила между файлами.

---

### 36. `priority` непредсказуем при extends + compile-and-apply

**Файлы:** [parser.py#L282](file:///Users/misha/PolicyShield/policyshield/core/parser.py#L282), [app.py](file:///Users/misha/PolicyShield/policyshield/server/app.py)

`compile-and-apply` ставит `priority: 0` новым правилам. `extends` наследует priority через shallow merge. Смешивание extends-правил (default priority=1) с compiled-правилами (priority=0) вызывает непредсказуемый порядок приоритетов.

---

### 37. Webhook `health()` — новый TCP на каждый health check

**Файл:** [approval/webhook.py#L133-L150](file:///Users/misha/PolicyShield/policyshield/approval/webhook.py#L133-L150)

```python
def health(self) -> dict:
    with httpx.Client(timeout=5.0) as client:  # NEW CLIENT
        resp = client.head(self._url)
```

K8s делает health check каждые 5-10s → **новое TCP-соединение** каждый раз. Лишняя нагрузка на webhook backend и ложные `unhealthy` при сетевых задержках.

---

### 38. `_rules_hash()` не включает when/priority/enabled

**Файл:** [app.py#L49-L55](file:///Users/misha/PolicyShield/policyshield/server/app.py#L49-L55)

```python
def _rules_hash(engine):
    raw = f"{ruleset.shield_name}:{ruleset.version}:{len(ruleset.rules)}"
    for r in ruleset.rules:
        raw += f"|{r.id}:{r.then.value}"  # ← только id и verdict
    return hashlib.sha256(raw.encode()).hexdigest()[:16]
```

Хэш не учитывает `when`, `priority`, `enabled`, `message`, `chain`. CD-система, проверяющая `rules_hash` после deploy, **не заметит** изменения conditions/priority.

> [!WARNING]
> **Влияние:** Изменения в правилах (кроме добавления/удаления или смены verdict) не обнаруживаются через `rules_hash`.

---

### 39. Rate limiter считает заблокированные вызовы в quota

**Файл:** [base_engine.py#L254-L261](file:///Users/misha/PolicyShield/policyshield/shield/base_engine.py#L254-L261)

Rate limiter вызывается **до** matching rules. `check_and_record` атомарно записывает вызов. Если после rate limit правило сделает BLOCK — вызов **засчитан** в quota, хотя tool не выполнился. Пользователь быстро расходует quota на заблокированные вызовы.

---

### 51. Plugin hooks — dead code

**Файл:** [plugins/\_\_init\_\_.py](file:///Users/misha/PolicyShield/policyshield/plugins/__init__.py#L48-L57)

Декораторы `@pre_check_hook` и `@post_check_hook` регистрируют callbacks в глобальные списки `_pre_check_hooks` и `_post_check_hooks`. Однако **ни `base_engine.py`, ни `async_engine.py` не импортируют** `get_pre_check_hooks()` / `get_post_check_hooks()` и не вызывают зарегистрированные хуки. Вся plugin hook система — мёртвый код.

---

### 52. PII overlapping patterns → двойной redact

**Файл:** [pii.py](file:///Users/misha/PolicyShield/policyshield/shield/pii.py#L140-L224)

`BUILTIN_PATTERNS` включает и `PHONE` (международный), и `RU_PHONE` (российский). Номер `+7 495 123 45 67` матчится обоими паттернами, создавая два `PIIMatch` для одного и того же span. `scan_dict` не дедуплицирует, и `redact_dict` может дважды редактировать перекрывающиеся span, потенциально портя строку.

---

### 53. Sanitizer `_flatten_to_string` — неэффективный size guard

**Файл:** [sanitizer.py](file:///Users/misha/PolicyShield/policyshield/shield/sanitizer.py#L214)

```python
if sum(len(p) for p in parts[-10:]) + len(parts) > _max_size and len(parts) > 100:
    return
```

Проверяется только размер **последних 10** элементов + количество элементов. Payload с множеством коротких строк (каждая < `_max_size / 10`) накопит строку далеко за пределами `_max_size` без срабатывания guard. Нужно отслеживать общий накопленный размер.

---

### 54. Watcher circuit breaker сбрасывается слишком агрессивно

**Файл:** [watcher.py](file:///Users/misha/PolicyShield/policyshield/shield/watcher.py#L90-L93)

```python
try:
    if self._has_changes():
        self._reload()
    self._consecutive_failures = 0  # сброс ВСЕГДА при отсутствии исключения
```

Счётчик ошибок сбрасывается при **любом** успешном poll, даже если файлы не изменились. Одна успешная проверка между ошибками полностью обнуляет circuit breaker, позволяя чередование failure/recovery без достижения порога остановки.

---

### 55. Webhook poll loop без circuit breaker

**Файл:** [webhook.py](file:///Users/misha/PolicyShield/policyshield/approval/webhook.py#L269-L271)

```python
except Exception as e:
    logger.warning("Poll request failed: %s", e)
    time.sleep(self._poll_interval)
```

Исключения при polling логируются как warning и выполнение продолжается. Нет счётчика ошибок или circuit breaker — при постоянно недоступном poll endpoint функция крутится полные `poll_timeout` (300с по умолчанию), блокируя вызывающий поток.

---

### 56. Telegram `stop()` — race condition с httpx.Client

**Файл:** [telegram.py](file:///Users/misha/PolicyShield/policyshield/approval/telegram.py#L161-L166)

```python
def stop(self):
    self._stop_event.set()
    self._poll_thread.join(timeout=5.0)
    self._client.close()  # poll thread может ещё использовать client!
```

`httpx.Client` **не thread-safe**. Закрытие из одного потока, пока другой поток выполняет `self._client.get(...)`, вызывает undefined behavior.

---

### 57. Env-var expansion — однопроходная подстановка

**Файл:** [config/loader.py](file:///Users/misha/PolicyShield/policyshield/config/loader.py#L72-L85)

`_expand_env` делает однопроходную regex замену. Если значение переменной содержит `${OTHER_VAR}`, вложенная ссылка **не раскроется**. `_expand_env_recursive` рекурсивно обходит dict/list, но **не рекурсивно** раскрывает строки — цепочки env-var не работают.

---

### 67. Dockerfile — несовпадение версий Python

**Файлы:** [Dockerfile](file:///Users/misha/PolicyShield/Dockerfile) (Python 3.13) vs [Dockerfile.server](file:///Users/misha/PolicyShield/Dockerfile.server) (Python 3.12)

Два Dockerfile'а используют разные версии Python:
- `Dockerfile` — `python:3.13-slim` с multi-stage сборкой
- `Dockerfile.server` — `python:3.12-slim` без multi-stage, `pip install` выполняется от root до создания non-root user

Дополнительно, `Dockerfile.server` копирует `examples/fastapi_agent/policies/rules.yaml` как правила по умолчанию — **example-правила зашиты в production-образ**.

---

### 68. Approval cache — коллизия ключей при `:` в session_id

**Файл:** [approval/cache.py](file:///Users/misha/PolicyShield/policyshield/approval/cache.py#L112-L129)

`PER_SESSION` ключ формируется как `sess:{session_id}:{rule_id}`. Если `session_id` содержит `:`, возможна коллизия с другими стратегиями. Например, session `"rule"` + rule `"__global__:foo"` даёт ключ `sess:rule:__global__:foo` — неоднозначный разбор. Санитизация ключей отсутствует.

---

### 69. `_flatten_to_string` — квадратичная проверка размера

**Файл:** [sanitizer.py](file:///Users/misha/PolicyShield/policyshield/shield/sanitizer.py#L210-L228)

Строка 214 вычисляет `sum(len(p) for p in parts[-10:])` на **каждом** рекурсивном вызове. Для dict с тысячами ключей это даёт O(n²) поведение. Кроме того, проверяются только последние 10 частей, поэтому payload из множества коротких строк + одной огромной строки **обходит** лимит.

---

### 70. PII `scan_dict` — нет ограничения на общее число matches

**Файл:** [pii.py](file:///Users/misha/PolicyShield/policyshield/shield/pii.py#L291-L310)

При dict'е с множеством строковых полей, содержащих PII, `scan_dict` генерирует unbounded список matches без cap. В сочетании с `redact_dict` (deepcopy + per-match замена) это может вызвать значительное потребление памяти и CPU.

---

### 88. MCP Server: `constraints` вызывает sync метод без `to_thread`

**Файл:** [mcp_server.py#L165-L167](file:///Users/misha/PolicyShield/policyshield/mcp_server.py#L165-L167)

В отличие от `kill`/`resume`/`reload`, `get_policy_summary()` вызывается **напрямую** без `asyncio.to_thread()`. Если метод выполняет I/O или длительные вычисления, он заблокирует event loop.

---

### 89. Env-var expansion не поддерживает nested `${}`

**Файл:** [config/loader.py#L72-L85](file:///Users/misha/PolicyShield/policyshield/config/loader.py#L72-L85)

Issue #57 документирует однопроходность expansion, но не специфически nested references. Конструкции вида `${VAR1_${VAR2}}` не раскрываются даже при рекурсивном обходе dict/list — раскрытие строки однопроходное.

---

### 90. Rate Limiter: `check()` + `record()` — TOCTOU split

**Файл:** [rate_limiter.py#L104-L203](file:///Users/misha/PolicyShield/policyshield/shield/rate_limiter.py#L104-L203)

API экспортирует **отдельные** `check()` и `record()` методы. `check_and_record()` существует для атомарной операции, но нет deprecation warning на split-методы. Вызывающий код может использовать `check()` без `record()`, создавая TOCTOU race condition.

---

### 91. Session Manager: eviction по `total_calls` вместо LRU

**Файл:** [session.py#L167-L182](file:///Users/misha/PolicyShield/policyshield/shield/session.py#L167-L182)

`_evict_oldest()` удаляет сессию с **наименьшим числом вызовов**, а не наименее недавно использованную (LRU). Новая сессия с 0 вызовов будет удалена раньше старой неактивной сессии с большим числом вызовов. Название метода (`_evict_oldest`) и комментарий не соответствуют реальному поведению.

> [!WARNING]
> **Влияние:** Новые сессии вытесняются раньше старых неактивных — нарушение ожидаемой семантики eviction.

---

### 92. Shell injection detector — false positives на backtick-текст

**Файл:** [detectors.py#L84-L96](file:///Users/misha/PolicyShield/policyshield/shield/detectors.py#L84-L96)

Regex `` `[^`]+` `` (backtick command substitution) срабатывает на **любой** строке в backticks — Markdown code blocks, SQL идентификаторы, template literals. AI-инструменты часто генерируют backtick-форматированный текст → массовые false positives.

> [!WARNING]
> **Влияние:** Легитимные tool-вызовы блокируются из-за backtick-форматирования в аргументах.

---

### 93. Sanitizer: `_flatten_to_string` пропускает числовые dict-ключи

**Файл:** [sanitizer.py#L216-L219](file:///Users/misha/PolicyShield/policyshield/shield/sanitizer.py#L216-L219)

```python
for k, v in value.items():
    if isinstance(k, str):  # ← int/float ключи пропускаются
        parts.append(k)
```

Dict-ключи, не являющиеся строками (int, float, bool), не участвуют в flatten. Blocked patterns и detectors не проверяют такие ключи.

---

### 94. Context evaluator: `strftime("%a")` зависит от locale

**Файл:** [context.py#L85](file:///Users/misha/PolicyShield/policyshield/shield/context.py#L85)

```python
today = self._now().strftime("%a")  # "Mon", "Tue" ... или "Пн", "Вт" ...
```

`strftime("%a")` возвращает локализованные имена дней в non-English locale. Правила с `day_of_week: "Mon-Fri"` **перестанут работать** на серверах с русской/немецкой/etc locale.

> [!WARNING]
> **Влияние:** Context-based правила с `day_of_week` ломаются в non-English locale.

---

### 95. Ring Buffer: `find_recent()` — O(n) scan без early-exit

**Файл:** [ring_buffer.py#L43-L77](file:///Users/misha/PolicyShield/policyshield/shield/ring_buffer.py#L43-L77)

`find_recent()` копирует весь буфер под lock и итерирует все события. Для буфера по умолчанию (100 элементов) это приемлемо, но при увеличении `max_size` каждый `check()` выполняет полный scan на каждое chain-правило. При N chain rules и M событий — O(N*M) на каждую проверку.

---

### 113. CrewAI wrapper: `post_check` результат игнорируется

**Файл:** [crewai/wrapper.py](file:///Users/misha/PolicyShield/policyshield/integrations/crewai/wrapper.py#L111-L125)

`_run` вызывает `post_check()` после выполнения tool, но **результат не проверяется** — output возвращается всегда:

```python
output = self.wrapped_tool._run(**kwargs)
self.engine.post_check(self.name, output)  # результат игнорируется!
return output  # PII в output проходит без redaction
```

> [!WARNING]
> **Влияние:** PII в output tool проходит без redaction в CrewAI pipeline.

---

### 114. LangChain wrapper: `post_check` полностью отсутствует

**Файл:** [langchain/wrapper.py](file:///Users/misha/PolicyShield/policyshield/integrations/langchain/wrapper.py#L52-L80)

В отличие от CrewAI wrapper, LangChain вообще **не вызывает** `post_check()`. Output rule и PII redaction не применяются к результатам tool.

> [!WARNING]
> **Влияние:** PII leakage в LangChain pipelines.

---

### 115. Honeypot checker: case-insensitivity bypass

**Файл:** [honeypots.py](file:///Users/misha/PolicyShield/policyshield/shield/honeypots.py#L18-L30)

Honeypot names хранятся как `lowercase`, но `check()` сравнивает tool_name **тоже через `.lower()`**. Проблема в том, что matcher может использовать case-sensitive сравнение для tool_name, создавая несоответствие:

```python
# honeypots.py: self._tools = {name.lower() for name in tools}
# check(): tool_name.lower() in self._tools
# matcher.py: tool_pattern = re.compile(f"^{tool_str}$")  # case-sensitive!
```

> [!WARNING]
> **Влияние:** Tool name `Secret_Tool` матчится honeypot'om, но не матчится rule с `tool: "secret_tool"`.

---

### 116. Config validation: 6 из 8 секций не валидируются

**Файл:** [loader.py](file:///Users/misha/PolicyShield/policyshield/config/loader.py#L93-L197)

JSON schema валидирует только `rules_path` и `mode`. Секции `pii`, `rate_limits`, `sanitizer`, `watch`, `approval`, `plugins` принимают произвольные ключи без ошибок — опечатки молча игнорируются.

> [!WARNING]
> **Влияние:** Опечатка в ключе конфига (`enabeld` вместо `enabled`) не детектируется.

---

### 117. Watcher: удаление YAML-файлов не обрабатывается

**Файл:** [watcher.py](file:///Users/misha/PolicyShield/policyshield/shield/watcher.py#L55-L73)

`_scan_mtimes()` возвращает mtime dict только существующих файлов. `_has_changes()` сравнивает **только** текущий mtime с предыдущим, но **не детектирует** исчезнувшие ключи. Удалённый rule-файл продолжает действовать.

> [!WARNING]
> **Влияние:** Удаление rule-файла не отражается в engine до рестарта.

---

### 118. Ring Buffer: `find_recent()` — нет backward traversal

**Файл:** [ring_buffer.py](file:///Users/misha/PolicyShield/policyshield/shield/ring_buffer.py#L43-L77)

`find_recent()` копирует весь буфер и сканирует с начала вместо reverse traversal с early exit. При N chain rules и M событий — O(N×M) на каждый `check()`. Для `max_size=10000` и 10 chain rules = 100K operations.

> [!WARNING]
> **Влияние:** Производительность деградирует линейно от размера буфера.

---

### 119. Sync/Async Clients: несовместимые retry параметры

**Файлы:** [client.py](file:///Users/misha/PolicyShield/policyshield/client.py) vs [async_client.py](file:///Users/misha/PolicyShield/policyshield/async_client.py)

| Параметр | `PolicyShieldClient` | `AsyncPolicyShieldClient` |
|---|---|---|
| max_retries | 3 | 2 |
| retry param name | `max_retries` | `retries` |
| Retry delay | 1.0s fixed | 0.5s fixed |

Разные дефолты между sync и async клиентами вносят путаницу и непредсказуемое поведение при миграции.

> [!WARNING]
> **Влияние:** При миграции sync→async клиент должен переименовать параметр и получает другие дефолты.

---

### 134. Config loader: env-var override только для `mode` и `fail_open`

**Файл:** [loader.py](file:///Users/misha/PolicyShield/policyshield/config/loader.py#L131-L138)

```python
env_mode = os.environ.get(f"{env_prefix}MODE")
if env_mode:
    cfg.mode = ShieldMode(env_mode.upper())

env_fp = os.environ.get(f"{env_prefix}FAIL_OPEN")
if env_fp is not None:
    cfg.fail_open = env_fp.lower() in ("1", "true", "yes")
```

`env_prefix` принимается, подразумевая поддержку env-var overrides для **всех** полей, но реализованы только `MODE` и `FAIL_OPEN`. `POLICYSHIELD_PII_ENABLED`, `POLICYSHIELD_TRACE_ENABLED` и т.д. — **не работают**.

> [!WARNING]
> **Влияние:** Невозможно переопределить большинство настроек через env-var без YAML-файла.

---

### 135. Async/Sync client: несовместимое именование параметров retry

**Файлы:** [client.py](file:///Users/misha/PolicyShield/policyshield/client.py#L38) vs [async_client.py](file:///Users/misha/PolicyShield/policyshield/async_client.py#L28)

| Параметр | Sync | Async |
|---|---|---|
| Retry count param | `max_retries=3` | `retries=2` |

Issue #119 описывает разные дефолты, но **не упоминает** что параметры **по-разному названы** (`max_retries` vs `retries`). Миграция sync→async требует переименования kwarg.

> [!NOTE]
> **Уточнение к Issue #119:** Дополнительная проблема — несовместимые имена параметров, не только значения.

---

### 136. MCP Proxy: `subprocess` импортирован, но upstream процесс никогда не запускается

**Файл:** [mcp_proxy.py](file:///Users/misha/PolicyShield/policyshield/mcp_proxy.py#L18)

```python
import subprocess  # imported but never used
```

`MCPProxy.__init__` принимает `upstream_command: list[str]`, но нигде не запускает `subprocess.Popen`. `_upstream_proc` установлен в `None` и никогда не присваивается.

> [!NOTE]
> **Уточнение к Issues #8/#75:** Дополнительная проблема — dead import `subprocess` и unused field `_upstream_proc`.

---

### 137. `render_config()` пропускает `watch_interval` (дополнение к #122)

**Файл:** [loader.py](file:///Users/misha/PolicyShield/policyshield/config/loader.py#L321-L356)

Issue #122 описывает пропуск `rate_limits`. Дополнительно пропущен `watch_interval` — round-trip `load_config()` → `render_config()` теряет и rate limits, и интервал watch.

---

### 138. `LLMGuardConfig.api_key` — plain string в памяти

**Файл:** [llm_guard.py](file:///Users/misha/PolicyShield/policyshield/shield/llm_guard.py#L45)

```python
@dataclass
class LLMGuardConfig:
    api_key: str | None = None  # plain text в памяти
```

API ключ OpenAI хранится как обычная строка в dataclass. При heap dump, core dump, или ошибке с traceback ключ может утечь. Нет zeroization при cleanup.

> [!WARNING]
> **Влияние:** Утечка API key через memory dump, debug logs, или exception traceback.

---

### 139. Trace Recorder `compute_args_hash` — нестабильный хэш

**Файл:** [trace/recorder.py](file:///Users/misha/PolicyShield/policyshield/trace/recorder.py#L19-L29)

```python
serialized = json.dumps(args, sort_keys=True, default=str)
return hashlib.sha256(serialized.encode()).hexdigest()
```

`default=str` конвертирует non-serializable объекты (datetime, UUID, custom classes) через `str()`. Это **не стабильно** — один и тот же datetime может дать разные `str()` результаты. В privacy mode одинаковые args могут получить разные хэши.

---

### 149. `ContextEvaluator._check_time` — лексикографическое сравнение time strings без валидации формата

**Файл:** [context.py](file:///Users/misha/PolicyShield/policyshield/shield/context.py#L57-L77)

`_check_time` сравнивает time strings лексикографически (строка 72: `start_s <= now_s <= end_s`). `strftime("%H:%M")` гарантирует zero-padding, но **user input** не валидируется. Если пользователь задаст `"9:00-17:00"` вместо `"09:00-17:00"`:

```python
parts = spec.split("-", 1)
start_s, end_s = parts[0].strip(), parts[1].strip()
now_s = self._now().strftime("%H:%M")
# "9:00" <= "08:59" → True (неправильно, т.к. "9" > "0" лексикографически)
return start_s <= now_s <= end_s
```

> [!WARNING]
> **Влияние:** Time-based правила с неправильным форматом (без ведущего нуля) дают некорректные результаты без какого-либо предупреждения.

---

### 150. `RateLimiter.from_yaml_dict` — отсутствие валидации, `KeyError` на malformed YAML

**Файл:** [rate_limiter.py](file:///Users/misha/PolicyShield/policyshield/shield/rate_limiter.py#L77-L102)

`from_yaml_dict()` делает `int(item["max_calls"])` (строка 96) без try/except. Если YAML rate_limit entry не содержит `max_calls` — `KeyError` crash при старте engine. Нет валидации:
- `window_seconds > 0`
- `max_calls > 0`
- Наличие обязательных ключей

```python
for item in per_tool:
    cfg = RateLimitConfig(
        max_calls=int(item["max_calls"]),      # KeyError!
        window_seconds=int(item["window_seconds"]),  # KeyError!
    )
```

> [!WARNING]
> **Влияние:** Непонятный crash при старте engine с некорректным YAML. Нет user-friendly сообщения об ошибке.

---

### 151. TraceRecorder `_generate_file_path` — infinite loop при permission denied

**Файл:** [trace/recorder.py](file:///Users/misha/PolicyShield/policyshield/trace/recorder.py#L96-L108)

`_generate_file_path()` в цикле `while True` проверяет `if not candidate.exists()`. Если директория read-only (файлы не создаются, но `exists()` возвращает релевантное значение), потенциально может создать проблему при совпадении имён:

```python
counter = 1
while True:
    candidate = self._output_dir / f"trace_{timestamp}_{counter}.jsonl"
    if not candidate.exists():
        return candidate  # Но если все имена заняты?
    counter += 1          # Нет upper bound!
```

> [!WARNING]
> **Влияние:** При очень большом количестве trace-файлов с одним timestamp'om — бесконечный цикл при старте TraceRecorder. Нужен upper bound на counter.

---

### 152. InMemoryBackend `get_status()` timeout race с `respond()`

**Файл:** [approval/memory.py](file:///Users/misha/PolicyShield/policyshield/approval/memory.py#L82-L117)

При timeout detection в `get_status()` (строки 98-116): создаётся `ApprovalResponse`, **удаляется request** (стр. 107), устанавливается event. Если `respond()` вызывается одновременно, он может **перезаписать** timeout response, нарушая first-response-wins гарантию:

```python
# get_status() — thread A:
self._responses[request_id] = ApprovalResponse(...)  # timeout response
self._requests.pop(request_id, None)                  # удаляем request
event.set()                                           # пробуждаем waiter

# respond() — thread B (между pop и set):
if request_id in self._responses:  # True — first-response guard!
    return  # OK, защита работает...
# НО: если respond() выполнится ДО записи timeout response:
if request_id not in self._requests:  # True (pop уже был)
    return  # ответ отброшен!
```

> [!WARNING]
> **Влияние:** Легитимный ответ approve/deny может быть тихо отброшен, а timeout auto-response применится вместо реального решения человека.

---

### 158. `sanitize_args` — shallow, secrets в nested args утекают

**Файл:** [approval/sanitizer.py](file:///Users/misha/PolicyShield/policyshield/approval/sanitizer.py#L18-L30)

`sanitize_args()` итерирует **только top-level** `args.items()` и применяет regex к `str(v)`. Для nested dict/list `str(v)` даёт Python repr (`{'key': 'sk-proj-...'}`) — regex `\bsk-(?:proj-|ant-)?[A-Za-z0-9]{32,}\b` **может не сматчить** из-за окружающих символов:

```python
def sanitize_args(args: dict) -> dict:
    for k, v in args.items():       # ❗ только top-level
        v_str = str(v)              # {'key': 'sk-proj-xxx'} → repr string
        for pattern, replacement in _SECRET_PATTERNS:
            v_str = pattern.sub(replacement, v_str)
```

> [!WARNING]
> **Влияние:** Secrets в nested args (например, `{"config": {"api_key": "sk-proj-..."}}`) могут утекать в Telegram/Slack approval channels.

---

### 159. Alert backends — blocking `urllib` в async контексте

**Файл:** [alerts/backends.py](file:///Users/misha/PolicyShield/policyshield/alerts/backends.py#L47-L111)

`WebhookBackend.send()`, `SlackBackend.send()`, `TelegramBackend.send()` используют **блокирующий** `urllib.request.urlopen()`. Если `AlertDispatcher.dispatch()` вызывается из async контекста (engine check callback), event loop блокируется:

```python
def send(self, alert: Alert) -> bool:
    with urllib.request.urlopen(req, timeout=10) as resp:  # ❗ blocking!
        return 200 <= resp.status < 300
```

> [!WARNING]
> **Влияние:** Блокировка event loop на 10с при отправке alert. 3 backends × N alerts = N×30с блокировки.

---
