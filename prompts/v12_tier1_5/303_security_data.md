# Prompt 303 — Security & Data Protection

## Цель

Закрыть утечки чувствительных данных через все каналы: HTTP responses, серверные логи, trace-файлы, auth-система.

## Контекст

- `policyshield/shield/detectors.py` — есть 5 attack-детекторов, но **нет** детектора секретов (API keys, JWT, AWS keys)
- `policyshield/server/app.py` — один `POLICYSHIELD_API_TOKEN` для всех endpoints (agent + admin)
- FastAPI при необработанном исключении возвращает Python stack traces с путями, args, internal info
- `logger.error("Matcher error: %s", e)` — exception может содержать PII/секреты
- `TraceRecorder` создаёт файлы с дефолтными permissions (`644`) — PII доступна всем
- Нет rate limit на admin endpoints + нет защиты от brute-force auth

## Что сделать

### 1. Secret/Credential Detection (`shield/detectors.py`)

```python
SECRET_DETECTION = Detector(
    name="secret_detection",
    description="API keys, tokens, and credentials",
    severity=DetectorSeverity.CRITICAL,
    patterns=_compile([
        r"(?:AKIA|ASIA)[0-9A-Z]{16}",                     # AWS Access Key
        r"aws_secret_access_key\s*=\s*\S{40}",            # AWS Secret Key
        r"(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}",    # GitHub Token
        r"sk-[A-Za-z0-9]{20,}",                            # OpenAI API Key
        r"xox[bpors]-[A-Za-z0-9\-]+",                     # Slack Token
        r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",     # JWT
        r"-----BEGIN\s+(RSA|DSA|EC|OPENSSH)?\s*PRIVATE KEY-----",  # Private Key
        r"(?:api[_-]?key|apikey|api[_-]?token)\s*[:=]\s*\S{10,}",  # Generic api_key=...
        r"(?:password|passwd|pwd)\s*[:=]\s*\S{6,}",        # password=...
        r"(?:secret|token)\s*[:=]\s*\S{10,}",             # secret=.../token=...
    ]),
)

# Добавить в ALL_DETECTORS:
ALL_DETECTORS: dict[str, Detector] = {
    d.name: d for d in [
        PATH_TRAVERSAL, SHELL_INJECTION, SQL_INJECTION, SSRF, URL_SCHEMES,
        SECRET_DETECTION,  # NEW
    ]
}
```

### 2. Admin Token Separation (`app.py`)

```python
def _get_admin_token() -> str | None:
    return os.environ.get("POLICYSHIELD_ADMIN_TOKEN")

async def verify_admin_token(request: Request):
    """Verify admin-level token for destructive operations."""
    admin_token = _get_admin_token()
    if not admin_token:
        # Fallback to regular token if admin token not configured
        return await verify_token(request)

    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing admin token")

    provided = auth.removeprefix("Bearer ").strip()
    if not hmac.compare_digest(provided.encode(), admin_token.encode()):
        raise HTTPException(status_code=403, detail="Invalid admin token")

# Применить к admin endpoints:
# /api/v1/reload — Depends(verify_admin_token)
# /api/v1/kill   — Depends(verify_admin_token)
# /api/v1/resume — Depends(verify_admin_token)
# /api/v1/respond-approval — Depends(verify_admin_token)
```

### 3. Sensitive Data в Error Responses

```python
# app.py — global exception handler (из Prompt 301) расширить:
DEBUG_MODE = os.environ.get("POLICYSHIELD_DEBUG", "false").lower() == "true"

@app.exception_handler(Exception)
async def shield_error_handler(request: Request, exc: Exception):
    verdict = "ALLOW" if getattr(engine, '_fail_open', False) else "BLOCK"
    content = {
        "verdict": verdict,
        "error": "internal_error",
        "message": "Check failed",
    }
    if DEBUG_MODE:
        content["debug"] = {
            "exception": type(exc).__name__,
            "detail": str(exc)[:500],
        }
    return JSONResponse(status_code=500, content=content)

# Также: убрать default FastAPI exception handler для ValidationError
@app.exception_handler(RequestValidationError)
async def validation_error_handler(request: Request, exc: RequestValidationError):
    return JSONResponse(
        status_code=422,
        content={"error": "validation_error", "message": "Invalid request format"},
    )
```

### 4. Log Sanitization (`shield/log_filter.py`)

```python
"""Logging filter to prevent PII/secrets from leaking into server logs."""

import logging
import re

# Patterns to redact in log messages
_SENSITIVE_PATTERNS = [
    (re.compile(r"(?:AKIA|ASIA)[0-9A-Z]{16}"), "[REDACTED_AWS_KEY]"),
    (re.compile(r"sk-[A-Za-z0-9]{20,}"), "[REDACTED_API_KEY]"),
    (re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"), "[REDACTED_JWT]"),
    (re.compile(r"(?:password|passwd|pwd)\s*[:=]\s*\S{6,}", re.I), "[REDACTED_PASSWORD]"),
    (re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), "[REDACTED_SSN]"),
]

class SensitiveDataFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str):
            for pattern, replacement in _SENSITIVE_PATTERNS:
                record.msg = pattern.sub(replacement, record.msg)
        if record.args and isinstance(record.args, tuple):
            sanitized = []
            for arg in record.args:
                s = str(arg)
                for pattern, replacement in _SENSITIVE_PATTERNS:
                    s = pattern.sub(replacement, s)
                sanitized.append(s)
            record.args = tuple(sanitized)
        return True

def install_log_filter():
    """Install sensitive data filter on root policyshield logger."""
    logger = logging.getLogger("policyshield")
    logger.addFilter(SensitiveDataFilter())
```

### 5. Trace File Permissions (`trace/recorder.py`)

```python
import os

# В _flush_unlocked() — заменить open() на os.open() с permissions:
def _flush_unlocked(self) -> None:
    if not self._buffer:
        return
    try:
        # Use os.open with restrictive permissions (owner-only)
        fd = os.open(
            str(self._file_path),
            os.O_WRONLY | os.O_CREAT | os.O_APPEND,
            0o600,
        )
        with os.fdopen(fd, "a", encoding="utf-8") as f:
            for entry in self._buffer:
                f.write(json.dumps(entry, default=str) + "\n")
    except OSError as exc:
        logger.error("Failed to write trace file %s: %s", self._file_path, exc)
    self._buffer.clear()
```

### 6. Admin Rate Limit / Brute-Force Protection

```python
# server/rate_limit.py
from collections import defaultdict
from time import monotonic

class AuthRateLimiter:
    """Track failed auth attempts and enforce lockout."""

    def __init__(self, max_failures: int = 5, window: float = 60.0, lockout: float = 300.0):
        self._max_failures = max_failures
        self._window = window
        self._lockout = lockout
        self._failures: dict[str, list[float]] = defaultdict(list)
        self._lockouts: dict[str, float] = {}

    def check(self, client_ip: str) -> bool:
        """Return True if request is allowed, False if rate-limited."""
        now = monotonic()
        if client_ip in self._lockouts:
            if now - self._lockouts[client_ip] < self._lockout:
                return False
            del self._lockouts[client_ip]

        # Clean old failures
        self._failures[client_ip] = [t for t in self._failures[client_ip] if now - t < self._window]
        return len(self._failures[client_ip]) < self._max_failures

    def record_failure(self, client_ip: str):
        now = monotonic()
        self._failures[client_ip].append(now)
        if len(self._failures[client_ip]) >= self._max_failures:
            self._lockouts[client_ip] = now
```

## Тесты (`tests/test_security.py`)

```python
"""Tests for security & data protection features."""
import pytest
from policyshield.shield.detectors import SECRET_DETECTION, ALL_DETECTORS
from policyshield.shield.log_filter import SensitiveDataFilter

class TestSecretDetection:
    def test_aws_key(self):
        assert SECRET_DETECTION.scan("AKIAIOSFODNN7EXAMPLE") is not None
    def test_github_token(self):
        assert SECRET_DETECTION.scan("ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij") is not None
    def test_openai_key(self):
        assert SECRET_DETECTION.scan("sk-proj-abcdefghijklmnopqrstuvwxyz") is not None
    def test_jwt(self):
        assert SECRET_DETECTION.scan("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0") is not None
    def test_private_key(self):
        assert SECRET_DETECTION.scan("-----BEGIN RSA PRIVATE KEY-----") is not None
    def test_safe_text(self):
        assert SECRET_DETECTION.scan("hello world, this is normal text") is None
    def test_in_registry(self):
        assert "secret_detection" in ALL_DETECTORS

class TestLogFilter:
    def test_redacts_aws_key(self):
        import logging
        f = SensitiveDataFilter()
        record = logging.LogRecord("test", logging.INFO, "", 0, "Key: AKIAIOSFODNN7EXAMPLE", (), None)
        f.filter(record)
        assert "AKIA" not in record.msg
        assert "REDACTED" in record.msg

class TestTraceFilePermissions:
    def test_trace_file_is_600(self, tmp_path):
        from policyshield.trace.recorder import TraceRecorder
        from policyshield.core.models import Verdict
        recorder = TraceRecorder(output_dir=tmp_path)
        recorder.record("s1", "test", Verdict.ALLOW)
        recorder.flush()
        import stat
        mode = stat.S_IMODE(recorder.file_path.stat().st_mode)
        assert mode == 0o600

class TestAdminTokenSeparation:
    def test_regular_token_cannot_kill(self, client_with_tokens):
        # agent token should get 403 on /kill
        pass
    def test_admin_token_can_kill(self, client_with_tokens):
        # admin token should get 200 on /kill
        pass

class TestAuthRateLimit:
    def test_lockout_after_failures(self):
        from policyshield.server.rate_limit import AuthRateLimiter
        limiter = AuthRateLimiter(max_failures=3, window=60, lockout=10)
        for _ in range(3):
            limiter.record_failure("1.2.3.4")
        assert limiter.check("1.2.3.4") is False
```

## Самопроверка

```bash
pytest tests/test_security.py -v
pytest tests/test_detectors.py -v  # existing tests still pass
pytest tests/ -q
ruff check policyshield/
```

## Порядок коммитов

1. `feat(security): add secret/credential detection patterns`
2. `feat(server): separate admin token from API token`
3. `feat(server): sanitize error responses in production mode`
4. `feat(logging): add SensitiveDataFilter for log sanitization`
5. `fix(trace): set restrictive file permissions (0o600) on trace files`
6. `feat(server): add admin rate limit and auth brute-force protection`
