# Prompt 305 — DX & Adoption

## Цель

Снизить порог входа до zero-friction: Python SDK, presets, quickstart, dry-run CLI, MCP integration, idempotency, retry/backoff, health checks, K8s probes, decorator API, JS/TS SDK, Slack/webhook alerts, example integrations, env config, OpenAPI schema, test coverage, web UI.

## Контекст

- PolicyShield HTTP server работает на FastAPI (`policyshield/server/app.py`)
- Python SDK не существует — пользователь вручную делает `httpx.post("/api/v1/check")`
- Нет CLI dry-run — пользователь не может протестировать правила без запуска сервера
- Интеграция с MCP (Model Context Protocol) отсутствует
- Нет retry/backoff → один сетевой сбой = потеря ACI security
- Health endpoint есть, но нет readiness/liveness probe format для K8s
- Нет примеров интеграции с популярными фреймворками (LangChain, CrewAI, OpenAI)
- Нет OpenAPI schema export → SDK auto-gen невозможен
- Нет env-based config → 12-factor app невозможен

> ⚠️ Это самая большая группа (17 фич). Рекомендуется разбить на под-фазы.

## Под-фазы

### Под-фаза A: Core DX (промпты 305a–305d)

#### 305a. Python SDK

```python
# policyshield/sdk/client.py
"""Lightweight sync+async Python client for PolicyShield HTTP API."""

import httpx
from dataclasses import dataclass

@dataclass
class CheckResult:
    verdict: str
    message: str = ""
    rule_id: str | None = None
    modified_args: dict | None = None
    approval_id: str | None = None
    request_id: str = ""

class PolicyShieldClient:
    """Sync client for PolicyShield API."""

    def __init__(
        self,
        base_url: str = "http://localhost:8000",
        token: str | None = None,
        timeout: float = 10.0,
    ):
        headers = {}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        self._client = httpx.Client(
            base_url=base_url,
            headers=headers,
            timeout=timeout,
        )

    def check(
        self,
        tool_name: str,
        args: dict | None = None,
        session_id: str = "default",
        sender: str | None = None,
    ) -> CheckResult:
        resp = self._client.post("/api/v1/check", json={
            "tool_name": tool_name,
            "args": args or {},
            "session_id": session_id,
            "sender": sender,
        })
        resp.raise_for_status()
        return CheckResult(**resp.json())

    def health(self) -> dict:
        resp = self._client.get("/api/v1/health")
        resp.raise_for_status()
        return resp.json()

    def kill(self, reason: str = "") -> dict:
        resp = self._client.post("/api/v1/kill", json={"reason": reason})
        resp.raise_for_status()
        return resp.json()

    def resume(self) -> dict:
        resp = self._client.post("/api/v1/resume")
        resp.raise_for_status()
        return resp.json()

    def close(self):
        self._client.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


class AsyncPolicyShieldClient:
    """Async client for PolicyShield API."""

    def __init__(
        self,
        base_url: str = "http://localhost:8000",
        token: str | None = None,
        timeout: float = 10.0,
    ):
        headers = {}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        self._client = httpx.AsyncClient(
            base_url=base_url,
            headers=headers,
            timeout=timeout,
        )

    async def check(self, tool_name: str, args: dict | None = None, **kwargs) -> CheckResult:
        resp = await self._client.post("/api/v1/check", json={
            "tool_name": tool_name,
            "args": args or {},
            **kwargs,
        })
        resp.raise_for_status()
        return CheckResult(**resp.json())

    async def health(self) -> dict:
        resp = await self._client.get("/api/v1/health")
        resp.raise_for_status()
        return resp.json()

    async def close(self):
        await self._client.aclose()

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        await self.close()
```

**Коммит:** `feat(sdk): add sync + async Python SDK client`

---

#### 305b. Retry/Backoff

```python
# policyshield/sdk/retry.py
"""Retry logic with exponential backoff for SDK clients."""

import time
import random
import logging
from functools import wraps
from typing import TypeVar, Callable

import httpx

logger = logging.getLogger(__name__)
T = TypeVar("T")

class RetryConfig:
    def __init__(
        self,
        max_retries: int = 3,
        base_delay: float = 0.5,
        max_delay: float = 30.0,
        jitter: bool = True,
        retryable_statuses: tuple[int, ...] = (502, 503, 504),
    ):
        self.max_retries = max_retries
        self.base_delay = base_delay
        self.max_delay = max_delay
        self.jitter = jitter
        self.retryable_statuses = retryable_statuses

def with_retry(config: RetryConfig | None = None):
    """Decorator that adds retry logic to SDK methods."""
    cfg = config or RetryConfig()

    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        @wraps(func)
        def wrapper(*args, **kwargs) -> T:
            last_exc = None
            for attempt in range(cfg.max_retries + 1):
                try:
                    return func(*args, **kwargs)
                except httpx.HTTPStatusError as e:
                    if e.response.status_code not in cfg.retryable_statuses:
                        raise
                    last_exc = e
                except (httpx.ConnectError, httpx.TimeoutException) as e:
                    last_exc = e

                if attempt < cfg.max_retries:
                    delay = min(cfg.base_delay * (2 ** attempt), cfg.max_delay)
                    if cfg.jitter:
                        delay *= (0.5 + random.random())
                    logger.warning("Retry %d/%d after %.1fs: %s", attempt + 1, cfg.max_retries, delay, last_exc)
                    time.sleep(delay)

            raise last_exc  # type: ignore
        return wrapper
    return decorator
```

**Коммит:** `feat(sdk): add retry/backoff with exponential jitter`

---

#### 305c. Dry-Run CLI

```python
# cli/main.py — добавить:
@cli.command("dry-run")
@click.option("--rules", "-r", required=True, type=click.Path(exists=True), help="Path to rules YAML")
@click.option("--tool", "-t", required=True, help="Tool name to check")
@click.option("--args", "-a", default="{}", help="JSON args")
@click.option("--session", default="default", help="Session ID")
def dry_run(rules: str, tool: str, args: str, session: str):
    """Test a check against rules without running the server."""
    import json
    from policyshield.shield.sync_engine import ShieldEngine

    parsed_args = json.loads(args)
    engine = ShieldEngine(rules=rules)

    result = engine.check(tool, parsed_args, session_id=session)

    click.echo(f"Tool:     {tool}")
    click.echo(f"Verdict:  {result.verdict.value}")
    click.echo(f"Message:  {result.message}")
    if result.rule_id:
        click.echo(f"Rule:     {result.rule_id}")
    if result.modified_args:
        click.echo(f"Modified: {json.dumps(result.modified_args, indent=2)}")
```

**Коммит:** `feat(cli): add dry-run command for offline rule testing`

---

#### 305d. Decorator API

```python
# policyshield/sdk/decorators.py
"""Decorator API for wrapping functions with PolicyShield checks."""

from functools import wraps
from typing import TypeVar, Callable

T = TypeVar("T")

def shield_check(
    client,
    tool_name: str | None = None,
    session_id: str = "default",
    on_block: str = "raise",  # "raise" | "return_none" | "log"
):
    """Decorator that runs a PolicyShield check before function execution.

    Usage:
        @shield_check(client, tool_name="send_email")
        def send_email(to: str, body: str):
            ...
    """
    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        _tool = tool_name or func.__name__

        @wraps(func)
        def wrapper(*args, **kwargs) -> T:
            result = client.check(_tool, kwargs or {}, session_id=session_id)
            if result.verdict == "BLOCK":
                if on_block == "raise":
                    raise PermissionError(f"PolicyShield blocked {_tool}: {result.message}")
                elif on_block == "return_none":
                    return None  # type: ignore
                # else: log and continue
            if result.modified_args:
                kwargs.update(result.modified_args)
            return func(*args, **kwargs)
        return wrapper
    return decorator
```

**Коммит:** `feat(sdk): add @shield_check decorator API`

---

### Под-фаза B: Integration & Operations (промпты 305e–305i)

#### 305e. Presets Enhancement

```python
# Уже есть --preset secure. Добавить presets:
# --preset strict  → default BLOCK, все детекторы, PII scan, rate limit
# --preset minimal → default ALLOW, no detectors, no PII
# --preset api     → default ALLOW, rate limit, CORS, input validation

# config/presets.py — расширить:
PRESETS = {
    "secure": {...},  # existing
    "strict": {
        "default_verdict": "BLOCK",
        "builtin_detectors": ["path_traversal", "shell_injection", "sql_injection", "ssrf", "url_schemes", "secret_detection"],
        "pii": {"enabled": True, "action": "REDACT"},
        "rate_limit": {"max_calls": 50, "window": 60},
        "fail_mode": "closed",
    },
    "minimal": {
        "default_verdict": "ALLOW",
        "builtin_detectors": [],
        "pii": {"enabled": False},
    },
    "api": {
        "default_verdict": "ALLOW",
        "rate_limit": {"max_calls": 100, "window": 60},
    },
}
```

**Коммит:** `feat(config): add strict, minimal, api presets`

---

#### 305f. MCP Integration

```python
# policyshield/integrations/mcp.py
"""Model Context Protocol (MCP) integration for PolicyShield.

Acts as an MCP middleware that intercepts tool calls and runs them through PolicyShield.
"""

from typing import Any

class PolicyShieldMCPMiddleware:
    """MCP middleware that checks tool calls against PolicyShield."""

    def __init__(self, client, fail_open: bool = True):
        self._client = client
        self._fail_open = fail_open

    async def intercept_tool_call(
        self, tool_name: str, args: dict[str, Any], session_id: str = "default"
    ) -> dict[str, Any]:
        """Check tool call and return modified args or raise on BLOCK."""
        try:
            result = await self._client.check(tool_name, args, session_id=session_id)
        except Exception:
            if self._fail_open:
                return args
            raise

        if result.verdict == "BLOCK":
            raise PermissionError(f"PolicyShield: {result.message}")
        if result.modified_args:
            return result.modified_args
        return args
```

**Коммит:** `feat(integrations): add MCP middleware for tool call interception`

---

#### 305g. K8s Health Probes

```python
# server/app.py — расширить health endpoint:
@app.get("/healthz")  # K8s liveness probe
async def liveness():
    return {"status": "ok"}

@app.get("/readyz")  # K8s readiness probe
async def readiness():
    if engine.is_killed:
        return JSONResponse(status_code=503, content={"status": "killed"})
    if engine.rule_count == 0:
        return JSONResponse(status_code=503, content={"status": "no_rules"})
    return {"status": "ready", "rules": engine.rule_count, "mode": engine.mode.value}

@app.get("/api/v1/deep-health")  # Deep health check
async def deep_health():
    checks = {}
    # Check rules
    checks["rules"] = {"status": "ok", "count": engine.rule_count}
    # Check tracer
    if engine._tracer:
        try:
            checks["tracer"] = {"status": "ok", "path": str(engine._tracer.file_path)}
        except Exception as e:
            checks["tracer"] = {"status": "error", "error": str(e)}
    # Check approval backend
    if engine._approval_backend:
        checks["approval"] = {"status": "ok"}
    overall = "ok" if all(c["status"] == "ok" for c in checks.values()) else "degraded"
    return {"status": overall, "checks": checks}
```

**Коммит:** `feat(server): add K8s liveness/readiness probes and deep health check`

---

#### 305h. Env-Based Config

```python
# config/env.py
"""Environment variable configuration support."""

import os

ENV_PREFIX = "POLICYSHIELD_"

# Mapping: env var (without prefix) → config key
ENV_MAP = {
    "MODE": ("mode", str),
    "DEFAULT_VERDICT": ("default_verdict", str),
    "FAIL_MODE": ("fail_mode", str),
    "LOG_LEVEL": ("log_level", str),
    "LOG_FORMAT": ("log_format", str),  # "json" | "text"
    "RULES_PATH": ("rules_path", str),
    "TRACE_DIR": ("trace_dir", str),
    "API_TOKEN": ("api_token", str),
    "ADMIN_TOKEN": ("admin_token", str),
    "MAX_REQUEST_SIZE": ("max_request_size", int),
    "MAX_CONCURRENT_CHECKS": ("max_concurrent_checks", int),
    "REQUEST_TIMEOUT": ("request_timeout", float),
    "CORS_ORIGINS": ("cors_origins", str),
}

def load_env_config() -> dict:
    """Load config from environment variables."""
    config = {}
    for env_key, (config_key, type_fn) in ENV_MAP.items():
        full_key = f"{ENV_PREFIX}{env_key}"
        value = os.environ.get(full_key)
        if value is not None:
            config[config_key] = type_fn(value)
    return config
```

**Коммит:** `feat(config): add env-based configuration (12-factor compatible)`

---

#### 305i. Idempotency Support

```python
# server/idempotency.py
"""Idempotency key middleware for PolicyShield API."""

from collections import OrderedDict
import threading

class IdempotencyStore:
    """LRU cache for idempotent request results."""

    def __init__(self, max_size: int = 10000):
        self._max_size = max_size
        self._store: OrderedDict[str, dict] = OrderedDict()
        self._lock = threading.Lock()

    def get(self, key: str) -> dict | None:
        with self._lock:
            if key in self._store:
                self._store.move_to_end(key)
                return self._store[key]
        return None

    def set(self, key: str, value: dict):
        with self._lock:
            self._store[key] = value
            self._store.move_to_end(key)
            while len(self._store) > self._max_size:
                self._store.popitem(last=False)

# app.py — использовать:
# If request has Idempotency-Key header, check cache first
# If hit → return cached result
# If miss → process, cache, return
```

**Коммит:** `feat(server): add idempotency key support`

---

### Под-фаза C: Ecosystem (промпты 305j–305l)

#### 305j. Quickstart & Example Integrations

Создать директорию `examples/` с готовыми минимальными примерами:

```
examples/
├── langchain/
│   ├── README.md
│   └── langchain_shield.py
├── openai_functions/
│   ├── README.md
│   └── openai_shield.py
├── crewai/
│   ├── README.md
│   └── crewai_shield.py
└── fastapi_middleware/
    ├── README.md
    └── middleware_example.py
```

**Коммит:** `docs(examples): add integration examples (LangChain, OpenAI, CrewAI, FastAPI)`

---

#### 305k. OpenAPI Schema + JS/TS SDK Stubs

```python
# server/app.py — OpenAPI уже генерируется FastAPI.
# Добавить route для export:
@app.get("/api/v1/openapi.json")
async def openapi_schema():
    return app.openapi()

# JS/TS SDK — стаб в sdk/typescript/:
# sdk/typescript/
# ├── package.json
# ├── src/
# │   ├── index.ts
# │   └── client.ts
# └── README.md
```

**Коммит:** `feat(sdk): add OpenAPI schema endpoint and JS/TS SDK stub`

---

#### 305l. Slack/Webhook Alerts

```python
# alerts/webhook.py
"""Generic webhook alert sender."""

import httpx
import logging
from dataclasses import dataclass

logger = logging.getLogger(__name__)

@dataclass
class WebhookConfig:
    url: str
    headers: dict | None = None
    events: list[str] | None = None  # ["kill_switch", "approval_timeout", "rate_limit_exceeded"]

class WebhookAlertSender:
    def __init__(self, config: WebhookConfig):
        self._config = config

    def send(self, event: str, payload: dict) -> bool:
        if self._config.events and event not in self._config.events:
            return False
        try:
            resp = httpx.post(
                self._config.url,
                json={"event": event, **payload},
                headers=self._config.headers or {},
                timeout=5.0,
            )
            return resp.is_success
        except Exception as e:
            logger.warning("Webhook alert failed: %s", e)
            return False

# alerts/slack.py
class SlackAlertSender(WebhookAlertSender):
    """Slack-specific alert formatting."""

    def send(self, event: str, payload: dict) -> bool:
        slack_payload = {
            "text": f"🛡️ PolicyShield Alert: *{event}*",
            "blocks": [{
                "type": "section",
                "text": {"type": "mrkdwn", "text": self._format_payload(event, payload)},
            }],
        }
        try:
            resp = httpx.post(self._config.url, json=slack_payload, timeout=5.0)
            return resp.is_success
        except Exception as e:
            logger.warning("Slack alert failed: %s", e)
            return False
```

**Коммит:** `feat(alerts): add webhook and Slack alert senders`

---

### Под-фаза D: Quality (промпт 305m)

#### 305m. Test Coverage & Web UI

- Довести test coverage до ≥ 80%
- Web UI — **отложить** до Tier 4 (отдельный milestone)

```bash
# coverage:
pytest --cov=policyshield --cov-report=html tests/
# открыть htmlcov/index.html
```

**Коммит:** `test: increase coverage to 80%+`

---

## Тесты (`tests/test_dx.py`)

```python
"""Tests for DX & adoption features."""
import pytest

class TestPythonSDK:
    def test_check_result_dataclass(self):
        from policyshield.sdk.client import CheckResult
        r = CheckResult(verdict="ALLOW", message="ok")
        assert r.verdict == "ALLOW"

    def test_client_context_manager(self):
        from policyshield.sdk.client import PolicyShieldClient
        # Would need a running server — mark as integration test
        pass

class TestRetry:
    def test_retry_on_503(self):
        from policyshield.sdk.retry import RetryConfig, with_retry
        import httpx

        call_count = 0
        @with_retry(RetryConfig(max_retries=2, base_delay=0.01))
        def fail_twice():
            nonlocal call_count
            call_count += 1
            if call_count <= 2:
                resp = httpx.Response(503)
                raise httpx.HTTPStatusError("503", request=httpx.Request("POST", "http://x"), response=resp)
            return "ok"
        assert fail_twice() == "ok"
        assert call_count == 3

class TestDryRun:
    def test_dry_run_exists(self):
        from click.testing import CliRunner
        from policyshield.cli.main import cli
        runner = CliRunner()
        result = runner.invoke(cli, ["dry-run", "--help"])
        assert result.exit_code == 0

class TestDecorator:
    def test_shield_check_blocks(self):
        from policyshield.sdk.decorators import shield_check
        # Mock client that always blocks
        pass

class TestIdempotency:
    def test_store_lru(self):
        from policyshield.server.idempotency import IdempotencyStore
        store = IdempotencyStore(max_size=2)
        store.set("a", {"v": 1})
        store.set("b", {"v": 2})
        store.set("c", {"v": 3})  # "a" should be evicted
        assert store.get("a") is None
        assert store.get("c") == {"v": 3}
```

## Самопроверка

```bash
pytest tests/test_dx.py -v
pytest tests/ -q
ruff check policyshield/
```

## Суммарный порядок коммитов

1. `feat(sdk): add sync + async Python SDK client`
2. `feat(sdk): add retry/backoff with exponential jitter`
3. `feat(cli): add dry-run command for offline rule testing`
4. `feat(sdk): add @shield_check decorator API`
5. `feat(config): add strict, minimal, api presets`
6. `feat(integrations): add MCP middleware for tool call interception`
7. `feat(server): add K8s liveness/readiness probes and deep health check`
8. `feat(config): add env-based configuration (12-factor compatible)`
9. `feat(server): add idempotency key support`
10. `docs(examples): add integration examples (LangChain, OpenAI, CrewAI, FastAPI)`
11. `feat(sdk): add OpenAPI schema endpoint and JS/TS SDK stub`
12. `feat(alerts): add webhook and Slack alert senders`
13. `test: increase coverage to 80%+`
