# PolicyShield — Аудит кода: Баги и Проблемы

> Результат тщательного анализа 30+ файлов исходного кода репозитория.  
> Находки ранжированы по критичности: 🔴 Баг, 🟠 Серьёзная проблема, 🟡 Качество кода, ⚪ Мелочи.

---

## 🔴 Баги

### 1. `_parse_rule` мутирует `when` dict через `pop("chain")` — падение на frozen-модели

[parser.py:L103-104](file:///Users/misha/PolicyShield/policyshield/core/parser.py#L103-L104)

```python
if isinstance(when, dict) and "chain" in when:
    chain = when.pop("chain")  # ← МУТАЦИЯ!
```

`when` создаётся как `raw.get("when", {})`, и затем передаётся в `RuleConfig(when=when)`, который имеет `frozen=True` (ConfigDict). Хотя `.pop()` вызывается **до** создания `RuleConfig`, проблема в том, что `when` — это **ссылка на оригинальный `raw` dict**, загруженный из YAML. Это значит:

- При повторном использовании `raw` dict (например, в `_resolve_extends`), ключ `chain` уже будет удалён.
- В функции `_load_rules_from_dir` каждый YAML файл парсится **трижды** (см. баг #2), и мутация `raw` может вызвать неожиданное поведение между проходами.

---

### 2. `_load_rules_from_dir` парсит каждый YAML файл 3 раза

[parser.py:L159-213](file:///Users/misha/PolicyShield/policyshield/core/parser.py#L159-L213)

```python
for f in yaml_files:
    data = parse_rule_file(f)    # проход 1: правила
    ...
for f in yaml_files:
    data = parse_rule_file(f)    # проход 2: taint_chain
    ...
for f in yaml_files:
    data = parse_rule_file(f)    # проход 3: honeypots
```

Каждый файл читается и парсится YAML 3 раза вместо одного. Помимо неэффективности, это создаёт гонку с мутацией `when.pop` из бага #1: если YAML-объект кэшируется PyYAML, мутация первого прохода повлияет на второй.

---

### 3. Async engine не запускает plugin detectors

[async_engine.py:L89-220](file:///Users/misha/PolicyShield/policyshield/shield/async_engine.py#L89-L220) vs [base_engine.py:L225-240](file:///Users/misha/PolicyShield/policyshield/shield/base_engine.py#L225-L240)

Sync путь `_do_check_sync` содержит:
```python
from policyshield.plugins import get_detectors as _get_detectors
for pname, detector_fn in _get_detectors().items():
    ...  # BLOCK if detected
```

**Async путь `_do_check` в `AsyncShieldEngine` полностью пропускает этот блок.** Это значит, что любые зарегистрированные plugin detectors **не работают** при использовании async API — серьёзная дыра в безопасности.

---

### 4. Async `_handle_approval` не сохраняет timestamp для TTL-очистки

[async_engine.py:L272-279](file:///Users/misha/PolicyShield/policyshield/shield/async_engine.py#L272-L279)

```python
with self._lock:
    self._approval_meta[req.request_id] = { ... }
    # НЕТ: self._approval_meta_ts[req.request_id] = monotonic()
    # НЕТ: self._cleanup_approval_meta()
```

В sync пути ([base_engine.py:L428-436](file:///Users/misha/PolicyShield/policyshield/shield/base_engine.py#L428-L436)) сохраняется timestamp и вызывается cleanup. В async — нет. Это приводит к **утечке памяти**: `_approval_meta` бесконечно растёт, а cleanup по TTL никогда не срабатывает для async записей.

---

### 5. Backpressure middleware использует `_semaphore.locked()` неправильно

[server/app.py:L210](file:///Users/misha/PolicyShield/policyshield/server/app.py#L210)

```python
if _semaphore.locked():
    return JSONResponse(status_code=503, ...)
async with _semaphore:
    return await call_next(request)
```

`asyncio.Semaphore.locked()` возвращает `True` только когда значение семафора равно **0**. Между проверкой `locked()` и `async with _semaphore` есть **race condition**: другой запрос мог занять последнее место. Кроме того, при `max_concurrent=100`, `locked()` вернёт `True` только при **ровно 100** активных запросах — на 99 он всё ещё пустит, хотя по замыслу должен был блокировать.

---

### 6. `wait_for_response` в `InMemoryBackend` удаляет response — второй poll вернёт `None`

[approval/memory.py:L106-108](file:///Users/misha/PolicyShield/policyshield/approval/memory.py#L106-L108)

```python
self._events.pop(request_id, None)
return self._responses.pop(request_id, None)
```

Метод `wait_for_response` удаляет response из `_responses` после первого потребления. Но `get_approval_status` в `BaseShieldEngine` может вызвать `wait_for_response` многократно (через polling). Первый call получит ответ, **все последующие получат `None`** и вернут `"pending"` — даже если approval уже обработан.

Хотя `BaseShieldEngine.get_approval_status` кэширует результат в `_resolved_approvals`, в случае concurrent вызовов два потока могут одновременно дойти до `wait_for_response`, и один из них потеряет ответ.

---

## 🟠 Серьёзные проблемы

### 7. Decorator `shield()` не обрабатывает `APPROVE` verdict

[decorators.py:L51-59](file:///Users/misha/PolicyShield/policyshield/decorators.py#L51-L59)

```python
if result.verdict == Verdict.BLOCK:
    ...
if result.modified_args:
    kwargs.update(result.modified_args)
return await func(*args, **kwargs)  # ← вызывается даже при APPROVE!
```

Если движок возвращает `APPROVE` (требуется человеческое одобрение), декоратор **всё равно вызывает функцию**, не дожидаясь одобрения. `APPROVE` фактически обрабатывается как `ALLOW`.

---

### 8. `AsyncPolicyShieldClient` не имеет retry/backoff

[async_client.py](file:///Users/misha/PolicyShield/policyshield/async_client.py) vs [client.py:L40-57](file:///Users/misha/PolicyShield/policyshield/client.py#L40-L57)

Sync `PolicyShieldClient` имеет `_request()` с retry loop и exponential backoff. `AsyncPolicyShieldClient` делает bare `await self._client.post()` — **никакой обработки ошибок, timeouts, или retries**. При кратковременном сбое сети async клиент упадёт с необработанным исключением.

---

### 9. Thread safety: `SessionManager` двойная блокировка

[session.py:L71-84](file:///Users/misha/PolicyShield/policyshield/shield/session.py#L71-L84)

```python
def increment(self, session_id, tool_name):
    session = self.get_or_create(session_id)  # ← берёт self._lock
    with self._lock:                          # ← берёт self._lock СНОВА
        session.increment(tool_name)
```

`get_or_create()` уже захватывает `self._lock`. Если lock — `threading.Lock()` (**не** `RLock`), это **deadlock**. Проверка: да, `self._lock = threading.Lock()` (L27). Это **гарантированный deadlock** при каждом вызове `increment()`.

> **UPDATE**: Проверил ещё раз — `threading.Lock()` в Python не является реентрантным. Однако `get_or_create()` использует `with self._lock`, которое **освобождает** lock при выходе из `with`-блока. Так что `increment()` захватит lock второй раз **после** освобождения из `get_or_create()`. Deadlock'а нет, но **есть race condition**: между `get_or_create()` и `with self._lock:` session мог быть evicted другим потоком.

---

### 10. `_build_ruleset` не загружает `output_rules` из YAML

[parser.py:L261-303](file:///Users/misha/PolicyShield/policyshield/core/parser.py#L261-L303)

Модель `RuleSet` имеет поле `output_rules: list[OutputRule] = []`. Парсер `_build_ruleset()` **никогда не читает** `data.get("output_rules")` из YAML. `_load_rules_from_dir` тоже. Это означает, что **output rules из YAML-конфигурации всегда пустые**, и `_post_check_sync` никогда не блокирует output по паттернам.

---

### 11. Shadow evaluation не передаётся в async engine

`_do_check` в [async_engine.py](file:///Users/misha/PolicyShield/policyshield/shield/async_engine.py) не содержит shadow evaluation блока (lines 338-368 в `base_engine.py`). Shadow rules, установленные через `set_shadow_rules()`, **не работают** в async mode.

---

## 🟡 Качество кода / Потенциальные проблемы

### 12. PII: Phone pattern — очень высокий false positive rate

[pii.py:L81-89](file:///Users/misha/PolicyShield/policyshield/shield/pii.py#L81-L89)

```python
r"(?:\+\d{1,3}[-.\\s]?)?"
r"\(?\d{1,4}\)?"
r"[-.\\s]?\d{1,4}"
r"[-.\\s]?\d{1,4}"
r"(?:[-.\\s]?\d{1,4})?"
```

Этот паттерн матчит почти любую последовательность из 6+ цифр с разделителями — включая даты (`12-05-2024`), версии (`3.10.12`), IP-адреса, номера заказов. Нет валидации длины итогового номера, нет проверки формата.

---

### 13. Passport pattern слишком широкий

[pii.py:L121](file:///Users/misha/PolicyShield/policyshield/shield/pii.py#L121)

```python
r"\b[A-Z]{1,2}\d{7,9}\b"
```

Матчит любую строку из 1-2 заглавных букв и 7-9 цифр: `V123456789`, `AB1234567`. Это затронет: коды продуктов, серийные номера, коды лотов, и т.д.

---

### 14. `RU_PASSPORT` pattern матчит слишком много

[pii.py:L142](file:///Users/misha/PolicyShield/policyshield/shield/pii.py#L142)

```python
r"\b\d{2}\s?\d{2}\s?\d{6}\b"
```

Матчит любые 10 цифр (возможно с пробелами). Затронет: телефоны, ID, серийные номера, и практически любое 10-значное число.

---

### 15. `EventRingBuffer` не thread-safe, но используется из разных потоков

[ring_buffer.py](file:///Users/misha/PolicyShield/policyshield/shield/ring_buffer.py) — комментарий: "Thread safety is handled by the caller (SessionManager)".

Но `_apply_post_check()` ([base_engine.py:L540-541](file:///Users/misha/PolicyShield/policyshield/shield/base_engine.py#L540-L541)) вызывает `buf.add()` **без блокировки**:

```python
buf = self._session_mgr.get_event_buffer(session_id)
buf.add(tool_name, result.verdict.value)
```

А в `_do_check_sync` (L273) `buf` тоже читается без lock. В async engine `asyncio.to_thread` создаёт отдельный поток — concurrent `buf.add()` и `buf.find_recent()` на `deque` без lock — **потенциальная гонка данных**.

---

### 16. `reload_rules` и `_hot_reload_callback` дублируют одну и ту же логику

[base_engine.py:L651-712](file:///Users/misha/PolicyShield/policyshield/shield/base_engine.py#L651-L712)

Оба метода содержат идентичный код обновления `_rule_set`, `_matcher`, `_honeypot_checker`. Любое изменение нужно дублировать в двух местах — прямой путь к рассинхронизации. Стоит вынести в `_swap_rules(new_ruleset)`.

---

### 17. `_load_rules_from_dir` не парсит `sanitizer` config

`_build_ruleset` и `_load_rules_from_dir` никогда не вызывают `parse_sanitizer_config()`. Хотя sanitizer передаётся в engine отдельно, пользователь может ожидать, что `sanitizer:` секция в YAML автоматически активирует санитайзер.

---

### 18. Content-Type middleware — ложные срабатывания для multipart

[server/app.py:L174-175](file:///Users/misha/PolicyShield/policyshield/server/app.py#L174-L175)

```python
if ct and "application/json" not in ct and request.url.path.startswith("/api/"):
```

Это **заблокирует** `multipart/form-data` и `application/x-www-form-urlencoded` на **всех** `/api/` эндпоинтах, даже если в будущем добавятся эндпоинты с file upload. Также блокирует `text/plain` тела для webhook callback'ов.

---

## ⚪ Мелочи

### 19. `all` extras не включает `server` и `ai`

[pyproject.toml:L69-71](file:///Users/misha/PolicyShield/pyproject.toml#L69-L71)

```toml
all = ["policyshield[langchain,crewai,otel,dashboard,prometheus,docs,dev]"]
```

Отсутствуют `server` и `ai`. `pip install policyshield[all]` не установит FastAPI/uvicorn/httpx для сервера и openai/anthropic для AI features.

---

### 20. Linter `check_invalid_regex` проверяет только `args_match`, но matcher также использует `args`

[linter.py:L68](file:///Users/misha/PolicyShield/policyshield/lint/linter.py#L68) — проверяется `rule.when.get("args_match", {})`.

Но `CompiledRule.from_rule()` использует `when.get("args") or when.get("args_match")`. Если пользователь использует `args:` вместо `args_match:`, невалидный regex пройдёт через linter без предупреждения.

---

### 21. CI build зависит от `plugin-e2e-smoke`, но тесты ненадёжны

[ci.yml:L69](file:///Users/misha/PolicyShield/.github/workflows/ci.yml#L69)

```yaml
needs: [lint, typecheck, test, benchmark, plugin-test, plugin-e2e-smoke, sdk-sync]
```

Сборка блокируется на e2e-smoke тестах плагина, которые зависят от внешних npm пакетов. Flaky npm registry или breaking change в vitest заблокирует **весь** CI pipeline.

---

## Сводная таблица

| # | Серьёзность | Компонент | Описание |
|---|---|---|---|
| 1 | 🔴 Баг | parser | `when.pop("chain")` мутирует исходный raw dict |
| 2 | 🔴 Баг | parser | YAML файлы парсятся 3 раза при загрузке директории |
| 3 | 🔴 Баг | async_engine | Plugin detectors не вызываются в async path |
| 4 | 🔴 Баг | async_engine | `_approval_meta_ts` не обновляется → утечка памяти |
| 5 | 🔴 Баг | server | Backpressure semaphore race condition |
| 6 | 🔴 Баг | approval | `wait_for_response` удаляет response, ломая concurrent poll |
| 7 | 🟠 Проблема | decorators | `APPROVE` verdict не blocking — функция вызывается |
| 8 | 🟠 Проблема | async_client | Нет retry/backoff |
| 9 | 🟠 Проблема | session | Race condition между `get_or_create` и `increment` |
| 10 | 🟠 Проблема | parser | `output_rules` не парсятся из YAML |
| 11 | 🟠 Проблема | async_engine | Shadow evaluation отсутствует |
| 12 | 🟡 Quality | pii | Phone pattern — массовые false positives |
| 13 | 🟡 Quality | pii | Passport pattern слишком широкий |
| 14 | 🟡 Quality | pii | RU_PASSPORT матчит любые 10 цифр |
| 15 | 🟡 Quality | ring_buffer | Не thread-safe, используется без lock |
| 16 | 🟡 Quality | base_engine | `reload_rules` / `_hot_reload_callback` дублирование |
| 17 | 🟡 Quality | parser | `sanitizer` config не парсится |
| 18 | 🟡 Quality | server | Content-Type middleware блокирует не-JSON |
| 19 | ⚪ Мелочь | pyproject | `[all]` extras неполные |
| 20 | ⚪ Мелочь | linter | Не проверяет `args` паттерны (только `args_match`) |
| 21 | ⚪ Мелочь | CI | Build зависит от flaky e2e-smoke |
