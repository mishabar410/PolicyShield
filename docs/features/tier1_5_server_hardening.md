# 🔥 Tier 1.5 — Server Hardening (HTTP Layer)

Защита самого HTTP-сервера от некорректного/вредоносного input.

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

### Payload Size Limit 🔴 `v1.0-blocker`

`app.py` не ограничивает размер входящего JSON. Один запрос с 100MB payload в `/api/v1/check` → OOM сервера. **Отдельная проблема** от Backpressure (concurrent requests) — тут один запрос убивает процесс.

```yaml
server:
  max_request_size: 1MB    # reject payloads > 1MB с HTTP 413
```

- **Усилия**: Маленькие (~10 строк, FastAPI middleware или Starlette `ContentSizeLimitMiddleware`)
- **Ценность**: 🔥🔥🔥 — без этого один запрос от агента может положить весь сервер

### Input Validation (tool_name + args depth) 🔴 `v1.0-blocker`

`CheckRequest.tool_name` принимает **любую строку** без ограничений: пустую, 10MB, с null-bytes. `args: dict = {}` не ограничивает глубину вложенности (nested dict bomb → CPU/memory exhaustion). Payload Size Limit (уже в списке) закрывает размер тела, но **не закрывает** crafted input внутри валидного JSON.

```python
class CheckRequest(BaseModel):
    tool_name: str = Field(..., min_length=1, max_length=256, pattern=r"^[\w.\-]+$")
    args: dict = {}  # + custom validator для max_depth и max_value_length
```

- **Усилия**: Маленькие (~30 строк, Pydantic validators)
- **Ценность**: 🔥🔥🔥 — без этого malicious agent может крашнуть сервер crafted input'ом

### Backpressure / Max Concurrent Checks 🔴 `v1.0-blocker`

Нет лимита на количество одновременных запросов. 10000 concurrent check-ов → OOM или дедлок. PolicyShield должен защищать себя.

```yaml
server:
  max_concurrent_checks: 100
  on_overload: 503       # HTTP 503 Service Unavailable
```

- **Усилия**: Маленькие (~30 строк, `asyncio.Semaphore` middleware)
- **Ценность**: 🔥🔥🔥 — self-protection, иначе DDoS кладёт и shield и агентов. **Повышен до blocker.**

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
