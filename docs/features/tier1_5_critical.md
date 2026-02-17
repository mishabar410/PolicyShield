# 🔥 Tier 1.5 — DX & Быстрое внедрение

v1.0-blockers и critical features для production readiness.

> **Примечание:** Bounded Session Storage (LRU/TTL) — **уже реализовано** в `session.py`
> (`SessionManager` с `ttl_seconds`, `max_sessions`, `_evict_expired`, `_evict_oldest`).
> Перенесено в ROADMAP как completed.

### ~~Bounded Session Storage (LRU/TTL)~~ ✅ DONE

> Реализовано в `session.py`. `SessionManager` имеет `ttl_seconds=3600`, `max_sessions=1000`,
> `_evict_expired()`, `_evict_oldest()`. LRU + TTL. Закрыто.

### Graceful Shutdown & Signal Handling 🔴 `v1.0-blocker`

При `SIGTERM`/`SIGINT` сервер должен: flush трейсов, завершить pending approvals, дождаться in-flight requests. Без этого — потеря данных при каждом деплое в Docker/K8s. **Сейчас SIGTERM = мгновенная смерть.**

**Важно:** текущий `lifespan()` в `app.py` останавливает только file watcher, но **не останавливает Telegram poller** (`TelegramApprovalBackend.stop()` нигде не вызывается). Daemon thread умирает без cleanup → pending approvals теряются.

- **Усилия**: Маленькие (~40 строк, lifespan hooks + backend.stop())
- **Ценность**: 🔥🔥🔥 — обязательно для контейнерного деплоя

### Structured Logging (JSON) 🔴

Сейчас `logger.warning()` пишет plaintext. Для Datadog/ELK/CloudWatch нужен JSON formatter. `structlog` или stdlib `logging.config`.

```json
{"level":"warning","event":"pii_detected","tool":"send_email","pii_types":["EMAIL"],"ts":"2026-02-18T00:30:00Z"}
```

- **Усилия**: Маленькие (~30 строк конфигурации)
- **Ценность**: 🔥🔥 — production observability

### Python SDK-клиент для HTTP API 🔴

Сейчас пользователь пишет raw HTTP запросы. Должно быть:

```python
from policyshield.client import PolicyShieldClient

ps = PolicyShieldClient("http://localhost:8100")
result = ps.check("write_file", {"path": "/tmp/x"})
if result.verdict == "APPROVE":
    ps.wait_for_approval(result.approval_id, timeout=300)
```

- **Усилия**: Средние (~200 строк, обёртка над httpx)
- **Ценность**: 🔥🔥🔥 — убирает 80% трения при интеграции

### Готовые пресеты по ролям 🔴

`policyshield init --preset coding-agent`, `--preset data-analyst`, `--preset customer-support`. 90% пользователей хотят «включил и забыл», а не писать YAML.

- **Усилия**: Маленькие (YAML шаблоны)
- **Ценность**: 🔥🔥🔥 — zero-config для конкретного use case

### `policyshield quickstart` — интерактивный мастер 🔴

Спрашивает «какие инструменты использует ваш агент?», генерирует правила, запускает сервер, выводит код для интеграции. Одна команда от нуля до работающей защиты.

- **Усилия**: Средние (wizard CLI + template engine)
- **Ценность**: 🔥🔥🔥 — самый короткий путь к value

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

### Dry-run CLI (`policyshield check`) 🔴

Проверить один вызов без поднятия сервера:

```bash
policyshield check --tool exec --args '{"cmd":"rm -rf /"}' --rules rules.yaml
```

- **Усилия**: Маленькие (~30 строк)
- **Ценность**: 🔥🔥 — отладка правил без запуска сервера

### Config Validation на старте 🔴 `v1.0-blocker`

`policyshield doctor` проверяет здоровье, но сервер **не падает** при невалидном конфиге на старте (`TELEGRAM_TOKEN` задан но невалидный, порт занят, несуществующий путь к правилам). Должен быть fail-fast.

- **Усилия**: Маленькие (~50 строк, startup checks)
- **Ценность**: 🔥🔥🔥 — экономит часы отладки, невалидный конфиг должен быть fatal

### Retry/Backoff для Telegram и Webhook 🔴

Telegram API может быть недоступен. Без retry с экспоненциальным backoff — **потеря approval-уведомлений без ошибки.**

```python
# Сейчас: один запрос, при ошибке — silent fail
# Нужно: 3 повтора с backoff 1s → 2s → 4s
```

- **Усилия**: Маленькие (~30 строк, tenacity/простой цикл)
- **Ценность**: 🔥🔥🔥 — без этого approval flow ненадёжен

### Idempotency / Request Deduplication 🔴

Если агент retry'ит запрос к `/api/v1/check` — дублируются trace записи, rate limit счётчики растут, approval создаётся дважды. Нужен `idempotency_key` в запросе.

```python
result = ps.check("write_file", {"path": "/tmp/x"}, idempotency_key="req-abc-123")
# повторный вызов с тем же ключом = тот же результат, без side effects
```

- **Усилия**: Средние (~100 строк, LRU cache результатов по ключу)
- **Ценность**: 🔥🔥🔥 — без этого retry-логика ломает rate limits и approvals

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

### Secret/Credential Detection 🔴

Есть PII-детектор (email, SSN, IBAN…), но нет детектора **секретов**. Агент случайно передаёт API key, JWT, AWS access key, private key в аргументах — и они утекают.

```yaml
sanitizer:
  secret_detection:
    enabled: true
    patterns: [aws_key, jwt, private_key, api_key, github_token]
    action: BLOCK
```

- **Усилия**: Маленькие (~80 строк, regex-паттерны по аналогии с PII)
- **Ценность**: 🔥🔥🔥 — отдельная категория утечек, PII её не покрывает

### MCP (Model Context Protocol) интеграция 🔴

MCP — де-факто стандарт для tool calling. PolicyShield как MCP proxy/middleware перехватывает tool calls на уровне протокола. Killer feature: любой MCP-агент получает защиту автоматически.

```bash
# Вместо прямого подключения к MCP серверу:
# agent → mcp_server
# С PolicyShield:
# agent → policyshield_mcp_proxy → mcp_server
policyshield mcp-proxy --upstream stdio://my-mcp-server --rules rules.yaml
```

- **Усилия**: Средние (~400 строк, MCP protocol wrapper)
- **Ценность**: 🔥🔥🔥 — охват всей MCP экосистемы одной интеграцией

### Fail-Open / Fail-Closed Strategy 🔴 `v1.0-blocker`

Если сам PolicyShield упал (OOM, uncaught exception в engine, timeout regex) — что происходит с tool call? **Сейчас — неопределённое поведение.** Для production это критический вопрос.

```yaml
server:
  on_error: block     # fail-closed (безопасно, но тулы встанут)
  # on_error: allow   # fail-open (тулы работают, но без защиты)
```

Должен быть:
- конфигурируемый `on_error` с дефолтом `block` (безопасный)
- try/except обертка вокруг `engine.check()` в HTTP handler
- метрика `policyshield_engine_errors_total` для мониторинга

- **Усилия**: Маленькие (~30 строк, try/except + config option)
- **Ценность**: 🔥🔥🔥 — без этого поведение при сбое не определено

### Engine Check Timeout 🔴 `v1.0-blocker`

Если `engine.check()` зависает (катастрофический backtracking в regex, бесконечный loop) — агент ждёт вечно. Нет таймаута.

```yaml
server:
  check_timeout: 5s   # максимальное время на один check
```

- **Усилия**: Маленькие (~20 строк, `asyncio.wait_for` в handler)
- **Ценность**: 🔥🔥🔥 — fail-fast при зависании, без этого один regex кладёт весь сервер

### Startup Self-Test / Smoke Check 🔴

При старте сервер загружает правила и запускается. Но не проверяет их **работоспособность**. Невалидный regex (`[unterminated`) может пройти `validate` но упасть при первом реальном запросе.

```bash
# При старте сервера автоматически:
# 1. Скомпилировать все regex паттерни
# 2. Прогнать каждое правило на синтетическом input
# 3. Проверить все detectors
# При ошибке → не стартовать, показать что сломано
```

- **Усилия**: Маленькие (~50 строк, dry-run при startup)
- **Ценность**: 🔥🔥🔥 — ловит broken rules **до** production, не после

### Backpressure / Max Concurrent Checks 🔴 `v1.0-blocker`

Нет лимита на количество одновременных запросов. 10000 concurrent check-ов → OOM или дедлок. PolicyShield должен защищать себя.

```yaml
server:
  max_concurrent_checks: 100
  on_overload: 503       # HTTP 503 Service Unavailable
```

- **Усилия**: Маленькие (~30 строк, `asyncio.Semaphore` middleware)
- **Ценность**: 🔥🔥🔥 — self-protection, иначе DDoS кладёт и shield и агентов. **Повышен до blocker.**

### Atomic Hot-Reload 🔴

Текущий `reload_rules()` не атомарный: если новые правила невалидны, старые уже сброшены → **окно без защиты**. Должен быть "load new → validate → swap".

```python
# Сейчас:
def reload_rules(self):
    self.rules = parse(self.rules_path)  # если упадёт → rules = None

# Нужно:
def reload_rules(self):
    new_rules = parse(self.rules_path)  # если упадёт → старые остаются
    validate(new_rules)                  # проверить до свапа
    self.rules = new_rules               # атомарный swap
```

- **Усилия**: Маленькие (~20 строк, переставить строчки)
- **Ценность**: 🔥🔥🔥 — без этого hot-reload может убить защиту

### Deep Health Checks (/livez + /readyz) 🔴

`/api/v1/health` возвращает `ok` если процесс жив. Не проверяет: доступен ли Telegram бот? Работает ли trace writer? Скомпилированы ли regex?

Частично пересекается с "K8s Liveness & Readiness", но суть шире:

```
GET /livez  → 200 (процесс жив)
GET /readyz → 200 (правила загружены, detectors ok, approval backend доступен)
             → 503 (telegram down, rules broken, etc.)
```

- **Усилия**: Маленькие (~40 строк)
- **Ценность**: 🔥🔥🔥 — без deep check проблемы обнаруживаются только при первом запросе

### K8s Liveness & Readiness Probes 🟡

Один `/api/v1/health` недостаточно. K8s нужен `/livez` (процесс жив) и `/readyz` (правила загружены, бэкенды доступны).

- **Усилия**: Маленькие (~20 строк)
- **Ценность**: 🔥🔥 — стандарт для K8s деплоя

### Decorator/middleware API 🟡

Inline интеграция без отдельного сервера:

```python
from policyshield import shield

@shield(engine)
def my_tool(args):
    ...
```

- **Усилия**: Маленькие (~50 строк)
- **Ценность**: 🔥🔥 — для тех кто не хочет отдельный сервер

### JS/TS SDK 🟡

Python SDK — начало, но большинство агентов на Node.js. Без JS клиента теряем огромную аудиторию.

```typescript
import { PolicyShield } from '@policyshield/client';
const ps = new PolicyShield('http://localhost:8100');
const result = await ps.check('write_file', { path: '/tmp/x' });
```

- **Усилия**: Средние (~300 строк TypeScript)
- **Ценность**: 🔥🔥 — открывает Node.js аудиторию

### Slack/Webhook уведомления о нарушениях 🟡

Telegram есть, но Slack в корпоративном мире важнее. Webhook для кастомных интеграций.

```yaml
alerts:
  on_block: slack
  slack_webhook: ${SLACK_WEBHOOK_URL}
```

- **Усилия**: Маленькие (адаптер поверх alert engine)
- **Ценность**: 🔥🔥 — enterprise adoption

### Рабочие примеры интеграций 🟡

Не документация, а `git clone && python run.py`:

```
examples/
  langchain_agent/     # полный агент с PolicyShield
  crewai_workflow/     # CrewAI pipeline
  autogen_agent/       # AutoGen multi-agent
  fastapi_service/     # микросервис с check/approve
  docker_compose/      # сервер + агент + monitoring
```

- **Усилия**: Средние (5-6 рабочих примеров)
- **Ценность**: 🔥🔥 — proof of concept за 2 минуты

### Конфиг через env variables (12-factor) 🟡

Сейчас конфиг из YAML + отдельные `POLICYSHIELD_TELEGRAM_*` env vars. Нет полного `POLICYSHIELD_*` маппинга. Для Docker/K8s это стандарт.

```bash
POLICYSHIELD_PORT=8100
POLICYSHIELD_MODE=enforce
POLICYSHIELD_DEFAULT_VERDICT=block
POLICYSHIELD_RULES_PATH=/app/rules.yaml
```

- **Усилия**: Маленькие (~40 строк)
- **Ценность**: 🔥🔥 — 12-factor app, стандарт для контейнеров

### OpenAPI Schema & API Contract 🟡

FastAPI генерирует OpenAPI автоматически, но нет публикуемого стабильного API-контракта. Без него SDK-авторы и интеграторы не знают на что полагаться.

```bash
# Генерация и публикация спецификации
policyshield openapi --output openapi.json
```

- **Усилия**: Маленькие (FastAPI + endpoint)
- **Ценность**: 🔥🔥 — основа для SDK любого языка

### `policyshield test --coverage` 🟢

Показывает какие инструменты агента покрыты правилами:

```
$ policyshield test --coverage --tools exec,read_file,write_file,send_email
Coverage: 3/4 tools (75%)
  ✅ exec → block-exec
  ✅ read_file → allow-read-file
  ✅ send_email → redact-pii
  ❌ write_file → no matching rule (default: BLOCK)
```

- **Усилия**: Маленькие
- **Ценность**: 🔥 — уверенность что ничего не пропущено

### Web UI дашборд 🟢

Посмотреть что заблочено, одобрить/отклонить, статистика PII — прямо в браузере.

- **Усилия**: Большие (SPA + WebSocket)
- **Ценность**: 🔥 — визуализация для менеджеров

### HTTP Error Handler (Global Exception Handler) 🔴 `v1.0-blocker`

`check()` handler в `app.py` вызывает `engine.check()` **без try/except**. Fail-Open/Fail-Closed реализован в engine (`base_engine.py`), но если исключение пробрасывается выше — FastAPI возвращает голый `500 Internal Server Error` без машинно-читаемого JSON. Клиент не может определить вердикт → агент зависает.

```python
# Сейчас:
@app.post("/api/v1/check")
async def check(req):
    result = await engine.check(...)  # если упадёт → 500 без verdict

# Нужно: глобальный exception handler
@app.exception_handler(Exception)
async def shield_error_handler(request, exc):
    if config.on_error == "allow":
        return JSONResponse({"verdict": "ALLOW", "error": str(exc)})
    return JSONResponse({"verdict": "BLOCK", "error": str(exc)}, status_code=500)
```

- **Усилия**: Маленькие (~20 строк, FastAPI exception_handler)
- **Ценность**: 🔥🔥🔥 — без этого клиент получает непарсируемый 500 вместо verdict

### Request / Correlation ID 🔴 `v1.0-blocker`

Нет `request_id` ни в запросе, ни в ответе `/check`. При отладке невозможно корреляциять HTTP запрос с trace записью, логом, и approval'ом. Для production observability — блокер.

```json
// Запрос
{"tool_name": "exec", "args": {...}, "request_id": "req-abc-123"}
// Ответ
{"verdict": "BLOCK", "request_id": "req-abc-123", "trace_id": "tr-xyz"}
```

Связано с Idempotency (request dedup), но Request ID — более базовая вещь: даже без дедупликации нужна корреляция.

- **Усилия**: Маленькие (~30 строк, добавить поле в модели + генерация UUID)
- **Ценность**: 🔥🔥🔥 — без этого debugging в production = гадание на кофейной гуще

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

### Admin Token Separation (Read vs Write Auth) 🔴

`/api/v1/reload`, `/api/v1/kill`, `/api/v1/respond-approval` используют тот же `POLICYSHIELD_API_TOKEN` что и `/api/v1/check`. Любой клиент с токеном может перезагрузить правила, активировать kill switch, одобрять approvals. Для production нужно минимум два уровня:

```bash
# Read-only (для агентов): check, post-check, constraints, health
POLICYSHIELD_API_TOKEN=agent-token-xxx

# Admin (для ops): reload, kill, resume, respond-approval
POLICYSHIELD_ADMIN_TOKEN=admin-token-yyy
```

- **Усилия**: Маленькие (~30 строк, второй Depends для admin endpoints)
- **Ценность**: 🔥🔥🔥 — принцип наименьших привилегий, иначе компрометация агента = полный контроль

### Payload Size Limit 🔴 `v1.0-blocker`

`app.py` не ограничивает размер входящего JSON. Один запрос с 100MB payload в `/api/v1/check` → OOM сервера. **Отдельная проблема** от Backpressure (concurrent requests) — тут один запрос убивает процесс.

```yaml
server:
  max_request_size: 1MB    # reject payloads > 1MB с HTTP 413
```

- **Усилия**: Маленькие (~10 строк, FastAPI middleware или Starlette `ContentSizeLimitMiddleware`)
- **Ценность**: 🔥🔥🔥 — без этого один запрос от агента может положить весь сервер

### Sensitive Data в Error Responses 🔴

При необработанном исключении FastAPI возвращает дефолтный `500` с Python stack traces, которые могут содержать:
- пути к файлам на сервере (`/app/policyshield/shield/pii.py:42`)
- содержимое `args` (PII, секреты, API ключи)
- имена внутренних модулей и версии

**Не покрывается** HTTP Error Handler (который про verdict при ошибке). Это про **утечку внутренней информации** через error responses.

```python
# Сейчас при исключении:
# {"detail": "File /app/policyshield/shield/matcher.py, line 87..."}
#
# Нужно: generic error без деталей в production
# {"error": "internal_error", "message": "Check failed"}
```

- **Усилия**: Маленькие (~20 строк, глобальный exception handler + `debug` flag в конфиге)
- **Ценность**: 🔥🔥🔥 — утечка stack traces = утечка внутренней архитектуры, information disclosure vulnerability

### Approval Polling Timeout (HTTP Handler) 🔴 `v1.0-blocker`

`engine.check()` покрыт Engine Check Timeout, но **отдельный вектор**: если клиент вызывает `check-approval` и approval backend зависает — нет timeout'а на уровне HTTP handler'а. `asyncio.wait_for` нигде не используется в server handlers.

В `telegram.py` дефолтный `wait_for_response(timeout=300s)`, в `base_engine.py:357` — `timeout=0.0` при polling. Но если Telegram API не отвечает на `getUpdates` — poll thread зависает, ответы не приходят, клиент ждёт бесконечно.

```yaml
server:
  approval_poll_timeout: 30s   # максимальное время ожидания на /check-approval
```

- **Усилия**: Маленькие (~15 строк, `asyncio.wait_for` в handler + httpx timeout в telegram)
- **Ценность**: 🔥🔥🔥 — зависание одного approval блокирует HTTP worker, каскадный отказ

### CORS Policy 🔴 `v1.0-blocker`

В `app.py` **нет CORS middleware**. Без явной CORS policy: 1) любой frontend/SDK из браузера получит `403 CORS error`; 2) при неправильной конфигурации — вектор CSRF-атаки. Для Web UI дашборда (в roadmap) и любых browser-based интеграций — обязательно.

```yaml
server:
  cors:
    allowed_origins: ["http://localhost:3000"]  # или ["*"] для dev
    allowed_methods: ["POST", "GET"]
```

- **Усилия**: Маленькие (~5 строк, `CORSMiddleware` из Starlette)
- **Ценность**: 🔥🔥🔥 — security hardening + обязательно для Web UI и browser SDK

### Input Validation (tool_name + args depth) 🔴 `v1.0-blocker`

`CheckRequest.tool_name` принимает **любую строку** без ограничений: пустую, 10MB, с null-bytes. `args: dict = {}` не ограничивает глубину вложенности (nested dict bomb → CPU/memory exhaustion). Payload Size Limit (уже в списке) закрывает размер тела, но **не закрывает** crafted input внутри валидного JSON.

```python
class CheckRequest(BaseModel):
    tool_name: str = Field(..., min_length=1, max_length=256, pattern=r"^[\w.\-]+$")
    args: dict = {}  # + custom validator для max_depth и max_value_length
```

- **Усилия**: Маленькие (~30 строк, Pydantic validators)
- **Ценность**: 🔥🔥🔥 — без этого malicious agent может крашнуть сервер crafted input'ом

### Trace Flush on Shutdown 🔴 `v1.0-blocker`

`TraceRecorder` буферизирует записи (`batch_size=100`), flush при заполнении или явном вызове. При shutdown (`lifespan()`) вызывается только `stop_watching()` — **`tracer.flush()` нигде не вызывается**. До 99 аудит-записей теряются при каждом деплое.

Связано с Graceful Shutdown, но **отдельная проблема**: даже с graceful shutdown, если `lifespan()` не вызывает `tracer.flush()` — данные пропадут.

```python
# lifespan() в app.py — СЕЙЧАС:
yield
engine.stop_watching()
# НЕТ: engine._tracer.flush()

# НУЖНО:
yield
engine.stop_watching()
if engine._tracer:
    engine._tracer.flush()  # ← 1 строка, спасает аудит-данные
```

- **Усилия**: 1 строка
- **Ценность**: 🔥🔥🔥 — потеря аудит-данных при каждом деплое, нарушает compliance

### Admin Rate Limit / Auth Brute-Force Protection 🔴

Нет rate limit на admin endpoints (`/kill`, `/reload`, `/respond-approval`) и нет защиты от brute-force подбора `POLICYSHIELD_API_TOKEN`. Неограниченное количество auth попыток в секунду. Скомпрометированный агент с токеном может спамить `/reload` 1000 раз/сек.

Отдельно от «Rate Limit на HTTP API» (Tier 2) — тут фокус на **admin-операциях и auth**, а не на `/check`.

```yaml
server:
  admin_rate_limit: 10/min    # макс 10 admin-запросов в минуту
  auth_fail_limit: 5/min      # макс 5 неудачных auth попыток → 429
  auth_fail_lockout: 300s     # lockout после превышения
```

- **Усилия**: Маленькие (~30 строк, counter + middleware)
- **Ценность**: 🔥🔥🔥 — без этого brute-force токена неограничен, admin abuse не контролируется

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

### Startup Python Version Validation 🔴 `v1.0-blocker`

README указывает `Python 3.10+`, но **нет runtime проверки**. На Python 3.8/3.9 пользователь получает непонятный `SyntaxError` на `X | Y` type unions или `match/case`. Должен быть **понятный fatal error на старте**, а не Python traceback.

```python
# __init__.py или cli entry point
import sys
if sys.version_info < (3, 10):
    sys.exit("PolicyShield requires Python 3.10+. Current: {}.{}".format(*sys.version_info[:2]))
```

- **Усилия**: 3 строки
- **Ценность**: 🔥🔥🔥 — без этого пользователь видит непонятный трейсбек и думает что проект сломан

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

### Trace File Permissions 🔴 `v1.0-blocker`

`TraceRecorder` создаёт JSONL файлы с дефолтными permissions ОС (обычно `644`/`rw-r--r--`). Трейсы содержат `args` (включая PII, если `privacy_mode` off). Любой пользователь на сервере может прочитать audit log. Для compliance (SOC 2, GDPR) audit trail должен быть `600`/`rw-------`.

```python
# При создании файла трейсов:
fd = os.open(trace_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
# или после создания:
os.chmod(trace_path, 0o600)  # owner-only read/write
```

- **Усилия**: 1 строка
- **Ценность**: 🔥🔥🔥 — PII в читаемых файлах = data leak по определению

### Logging Sensitive Data (Log Sanitization) 🔴

`base_engine.py` при ошибке матчера: `logger.error("Matcher error: %s", e)` — исключение может содержать аргументы инструмента (PII, секреты). Шире: **нет политики что логировать**. `logger.info`, `logger.warning` в разных модулях могут случайно слить чувствительные данные в серверные логи.

**Не покрывается** "Sensitive Data в Error Responses" (та про HTTP ответы). Это про **серверные логи** — другой канал утечки. Если включить JSON logging (из roadmap) и отправлять в ELK/Datadog — args утекут в лог-систему.

```python
# Сейчас: exception может содержать args с PII/секретами
logger.error("Matcher error: %s", e)
# e.args может включать: {"ssn": "123-45-6789", "api_key": "sk-xxx..."}

# Нужно: log filter/sanitizer
class SensitiveDataFilter(logging.Filter):
    def filter(self, record):
        record.msg = sanitize_log_message(record.msg)
        return True
```

- **Усилия**: Маленькие (~30 строк, logging.Filter + sanitize функция)
- **Ценность**: 🔥🔥🔥 — без этого PII/секреты утекают через логи в лог-агрегаторы

### HTTP Request Lifecycle Timeout 🔴

Отдельно описаны "Engine Check Timeout" и "Approval Polling Timeout", но **нет общего HTTP request timeout** на уровне сервера. Uvicorn по дефолту не имеет request timeout — один медленный запрос с chunked transfer-encoding может держать worker бесконечно.

**Не покрывается** Payload Size Limit (размер тела) и Engine Check Timeout (время `engine.check()`) — тут про полный цикл HTTP request lifecycle: получение тела + обработка + отправка ответа.

```yaml
server:
  request_timeout: 30s   # общий таймаут всего HTTP запроса
```

```python
# Middleware:
@app.middleware("http")
async def timeout_middleware(request, call_next):
    return await asyncio.wait_for(call_next(request), timeout=30)
```

- **Усилия**: Маленькие (~10 строк, middleware + config option)
- **Ценность**: 🔥🔥🔥 — без этого один медленный запрос блокирует worker навсегда

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

### Content-Type Validation (HTTP Layer) 🔴

`app.py` принимает запросы без проверки `Content-Type` header. Отправка `text/plain`, `multipart/form-data`, или вообще без `Content-Type` вместо `application/json` → непредсказуемое поведение Pydantic парсера. Должен быть `415 Unsupported Media Type`.

```python
# Сейчас: любой Content-Type проходит
POST /api/v1/check
Content-Type: text/plain    # ← парсится, может крашнуть
Content-Type: (отсутствует)  # ← тоже проходит

# Нужно: middleware валидирует Content-Type для POST/PUT
@app.middleware("http")
async def content_type_check(request, call_next):
    if request.method in ("POST", "PUT"):
        ct = request.headers.get("content-type", "")
        if "application/json" not in ct:
            return JSONResponse(status_code=415, content={"error": "Unsupported Media Type"})
    return await call_next(request)
```

- **Усилия**: Маленькие (~10 строк, middleware)
- **Ценность**: 🔥🔥🔥 — hardening HTTP layer, предсказуемое поведение на невалидный input
