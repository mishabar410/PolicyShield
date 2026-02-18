# Prompt 201 — Detector Registry

## Цель

Создать каталог встроенных security-детекторов в `policyshield/shield/detectors.py`. Каждый детектор — набор скомпилированных regex-паттернов, обнаруживающих атаки в аргументах tool calls.

## Контекст

- Сейчас `InputSanitizer` принимает `blocked_patterns: list[str]` — пользователь **сам** должен знать regex
- 99% пользователей не знают, какие regex нужны для path traversal или shell injection
- Нужен каталог готовых детекторов, которые включаются одной строкой в конфиге
- Детекторы должны работать **без YAML-правил** — это pre-rule sanitization
- Каждый детектор: имя + список regex + описание + severity

## Что сделать

### 1. Создать `policyshield/shield/detectors.py`

```python
"""Built-in security detectors for InputSanitizer.

Each detector is a named collection of compiled regex patterns that catch
common attack vectors in tool call arguments. Detectors run before rule
matching and work without any YAML rules configured.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum


class DetectorSeverity(Enum):
    """Severity level for a detector match."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass(frozen=True)
class DetectorMatch:
    """Result of a detector finding a match."""
    detector_name: str
    pattern: str
    matched_text: str
    severity: DetectorSeverity
    description: str


@dataclass(frozen=True)
class Detector:
    """A named security detector with compiled patterns."""
    name: str
    description: str
    severity: DetectorSeverity
    patterns: list[re.Pattern] = field(default_factory=list)

    def scan(self, text: str) -> DetectorMatch | None:
        """Scan text for this detector's patterns.

        Returns first match found, or None.
        """
        for pat in self.patterns:
            m = pat.search(text)
            if m:
                return DetectorMatch(
                    detector_name=self.name,
                    pattern=pat.pattern,
                    matched_text=m.group()[:100],  # Truncate for safety
                    severity=self.severity,
                    description=self.description,
                )
        return None


def _compile(patterns: list[str]) -> list[re.Pattern]:
    """Compile a list of regex strings with IGNORECASE."""
    return [re.compile(p, re.IGNORECASE) for p in patterns]


# ─── Built-in detectors ─────────────────────────────────────────────

PATH_TRAVERSAL = Detector(
    name="path_traversal",
    description="Directory traversal attack (../)",
    severity=DetectorSeverity.HIGH,
    patterns=_compile([
        r"\.\./",                           # ../
        r"\.\. /",                          # .. / (space variant)
        r"%2e%2e[%2f/\\]",                  # URL-encoded ../
        r"\.\.\\",                          # ..\  (Windows)
        r"/etc/(passwd|shadow|hosts)",      # Direct /etc access
        r"~/.ssh/",                         # SSH keys
        r"/proc/self/",                     # Proc filesystem
    ]),
)

SHELL_INJECTION = Detector(
    name="shell_injection",
    description="Shell command injection",
    severity=DetectorSeverity.CRITICAL,
    patterns=_compile([
        r";\s*(rm|cat|curl|wget|nc|bash|sh|python|perl|ruby)\b",  # ;cmd
        r"\|\s*(bash|sh|curl|wget|nc|python)\b",                   # |cmd
        r"`[^`]+`",                                                 # `backtick cmd`
        r"\$\([^)]+\)",                                             # $(cmd)
        r"\b(rm\s+-rf|mkfs|dd\s+if=)\b",                          # Destructive
        r">\s*/dev/sd[a-z]",                                        # Write to disk
        r"\b(chmod\s+777|chmod\s+-R\s+777)\b",                    # Insecure perms
    ]),
)

SQL_INJECTION = Detector(
    name="sql_injection",
    description="SQL injection attack",
    severity=DetectorSeverity.CRITICAL,
    patterns=_compile([
        r"'\s*(OR|AND)\s+['\d].*=",           # ' OR '1'='1
        r";\s*(DROP|DELETE|UPDATE|INSERT)\b",  # ;DROP TABLE
        r"UNION\s+(ALL\s+)?SELECT\b",          # UNION SELECT
        r"--\s*$",                              # SQL comment at end
        r"/\*.*\*/",                            # Block comment injection
        r"\bSLEEP\s*\(\d+\)",                  # SLEEP(5)
        r"\bBENCHMARK\s*\(",                   # BENCHMARK()
        r"\bWAITFOR\s+DELAY\b",               # MSSQL delay
    ]),
)

SSRF = Detector(
    name="ssrf",
    description="Server-Side Request Forgery",
    severity=DetectorSeverity.CRITICAL,
    patterns=_compile([
        r"https?://169\.254\.169\.254",          # AWS metadata
        r"https?://metadata\.google\.internal",   # GCP metadata
        r"https?://100\.100\.100\.200",           # Alibaba metadata
        r"https?://(localhost|127\.0\.0\.1|0\.0\.0\.0)",  # Loopback
        r"https?://\[::1?\]",                     # IPv6 loopback
        r"https?://10\.\d+\.\d+\.\d+",           # Private 10.x
        r"https?://172\.(1[6-9]|2\d|3[01])\.",   # Private 172.16-31.x
        r"https?://192\.168\.\d+\.\d+",          # Private 192.168.x
        r"file://",                               # File protocol
        r"gopher://",                             # Gopher protocol
    ]),
)

URL_SCHEMES = Detector(
    name="url_schemes",
    description="Dangerous URL schemes",
    severity=DetectorSeverity.HIGH,
    patterns=_compile([
        r"javascript:",             # XSS via javascript:
        r"data:text/html",          # Data URI HTML
        r"data:application/",       # Data URI application
        r"vbscript:",               # VBScript
        r"file:///",                # Local file access
    ]),
)


# ─── Registry ────────────────────────────────────────────────────────

ALL_DETECTORS: dict[str, Detector] = {
    d.name: d for d in [PATH_TRAVERSAL, SHELL_INJECTION, SQL_INJECTION, SSRF, URL_SCHEMES]
}


def get_detector(name: str) -> Detector:
    """Get a detector by name.

    Args:
        name: Detector name (path_traversal, shell_injection, etc.)

    Raises:
        KeyError: If detector not found.
    """
    if name not in ALL_DETECTORS:
        available = ", ".join(sorted(ALL_DETECTORS))
        raise KeyError(f"Unknown detector: {name!r}. Available: {available}")
    return ALL_DETECTORS[name]


def get_detectors(names: list[str]) -> list[Detector]:
    """Get multiple detectors by name.

    Args:
        names: List of detector names.

    Returns:
        List of Detector objects.
    """
    return [get_detector(n) for n in names]


def scan_all(text: str, detectors: list[Detector] | None = None) -> list[DetectorMatch]:
    """Scan text with multiple detectors.

    Args:
        text: Text to scan.
        detectors: List of detectors. If None, uses all detectors.

    Returns:
        List of matches found (may be empty).
    """
    if detectors is None:
        detectors = list(ALL_DETECTORS.values())

    matches = []
    for detector in detectors:
        match = detector.scan(text)
        if match:
            matches.append(match)
    return matches
```

### 2. Тесты

#### `tests/test_detectors.py`

```python
"""Tests for built-in security detectors."""

import pytest

from policyshield.shield.detectors import (
    ALL_DETECTORS,
    PATH_TRAVERSAL,
    SHELL_INJECTION,
    SQL_INJECTION,
    SSRF,
    URL_SCHEMES,
    DetectorSeverity,
    get_detector,
    get_detectors,
    scan_all,
)


class TestPathTraversal:
    def test_dotdot_slash(self):
        assert PATH_TRAVERSAL.scan("../../etc/passwd") is not None

    def test_url_encoded(self):
        assert PATH_TRAVERSAL.scan("%2e%2e%2fetc/passwd") is not None

    def test_windows_backslash(self):
        assert PATH_TRAVERSAL.scan("..\\windows\\system32") is not None

    def test_etc_passwd(self):
        assert PATH_TRAVERSAL.scan("/etc/passwd") is not None

    def test_safe_path(self):
        assert PATH_TRAVERSAL.scan("/home/user/file.txt") is None

    def test_dotdot_in_word(self):
        """'something..' should not match."""
        assert PATH_TRAVERSAL.scan("version..1") is None


class TestShellInjection:
    def test_semicolon_rm(self):
        assert SHELL_INJECTION.scan("; rm -rf /") is not None

    def test_pipe_bash(self):
        assert SHELL_INJECTION.scan("| bash -c 'evil'") is not None

    def test_backtick(self):
        assert SHELL_INJECTION.scan("hello `whoami` world") is not None

    def test_dollar_paren(self):
        assert SHELL_INJECTION.scan("$(curl evil.com)") is not None

    def test_rm_rf(self):
        assert SHELL_INJECTION.scan("rm -rf /tmp") is not None

    def test_safe_command(self):
        assert SHELL_INJECTION.scan("echo hello") is None


class TestSqlInjection:
    def test_or_1_eq_1(self):
        assert SQL_INJECTION.scan("' OR '1'='1") is not None

    def test_union_select(self):
        assert SQL_INJECTION.scan("UNION SELECT * FROM users") is not None

    def test_drop_table(self):
        assert SQL_INJECTION.scan("; DROP TABLE users") is not None

    def test_sleep(self):
        assert SQL_INJECTION.scan("SLEEP(5)") is not None

    def test_safe_query(self):
        assert SQL_INJECTION.scan("SELECT name FROM users WHERE id = 1") is None


class TestSSRF:
    def test_aws_metadata(self):
        assert SSRF.scan("http://169.254.169.254/latest/meta-data/") is not None

    def test_gcp_metadata(self):
        assert SSRF.scan("http://metadata.google.internal/computeMetadata/v1/") is not None

    def test_localhost(self):
        assert SSRF.scan("http://localhost:8080/admin") is not None

    def test_file_protocol(self):
        assert SSRF.scan("file:///etc/passwd") is not None

    def test_private_ip(self):
        assert SSRF.scan("http://192.168.1.1/admin") is not None

    def test_safe_url(self):
        assert SSRF.scan("https://api.github.com/repos") is None


class TestUrlSchemes:
    def test_javascript(self):
        assert URL_SCHEMES.scan("javascript:alert(1)") is not None

    def test_data_html(self):
        assert URL_SCHEMES.scan("data:text/html,<script>alert(1)</script>") is not None

    def test_safe_https(self):
        assert URL_SCHEMES.scan("https://example.com") is None


class TestRegistry:
    def test_all_detectors_count(self):
        assert len(ALL_DETECTORS) == 5

    def test_get_detector(self):
        d = get_detector("path_traversal")
        assert d.name == "path_traversal"

    def test_get_detector_unknown(self):
        with pytest.raises(KeyError, match="Unknown detector"):
            get_detector("nonexistent")

    def test_get_detectors(self):
        ds = get_detectors(["path_traversal", "ssrf"])
        assert len(ds) == 2

    def test_scan_all_finds_multiple(self):
        # This text has both path traversal and shell injection
        text = "../../etc/passwd; rm -rf /"
        matches = scan_all(text)
        names = {m.detector_name for m in matches}
        assert "path_traversal" in names
        assert "shell_injection" in names

    def test_scan_all_clean(self):
        matches = scan_all("echo hello world")
        assert matches == []

    def test_detector_severity(self):
        assert SHELL_INJECTION.severity == DetectorSeverity.CRITICAL
        assert PATH_TRAVERSAL.severity == DetectorSeverity.HIGH
```

## Самопроверка

```bash
pytest tests/test_detectors.py -v
pytest tests/ -q  # все тесты проходят
```

## Коммит

```
feat(security): add built-in security detector registry

- Add 5 detectors: path_traversal, shell_injection, sql_injection, ssrf, url_schemes
- Each detector: named, categorized by severity, with compiled regex patterns
- Registry API: get_detector(), get_detectors(), scan_all()
- DetectorMatch dataclass with matched text, pattern, and description
```
