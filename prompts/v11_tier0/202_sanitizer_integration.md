# Prompt 202 — Sanitizer Integration

## Цель

Интегрировать детекторы из `detectors.py` в `InputSanitizer` — они должны работать **автоматически** при включении в конфиге, без YAML-правил.

## Контекст

- `InputSanitizer` сейчас проверяет только `blocked_patterns` (пользовательские regex)
- Нужно добавить `builtin_detectors: list[str]` в `SanitizerConfig`
- При инициализации sanitizer загружает детекторы из реестра
- Проверка встроенных детекторов идёт **перед** пользовательскими `blocked_patterns`
- Если детектор сработал — `rejected=True` с описанием (какой детектор, какой паттерн)

## Что сделать

### 1. Обновить `SanitizerConfig` в `policyshield/shield/sanitizer.py`

Добавить поле:

```python
@dataclass
class SanitizerConfig:
    """Configuration for :class:`InputSanitizer`."""

    max_string_length: int = 10_000
    max_args_depth: int = 10
    max_total_keys: int = 100
    strip_whitespace: bool = True
    strip_null_bytes: bool = True
    normalize_unicode: bool = True
    strip_control_chars: bool = True
    blocked_patterns: list[str] | None = None
    builtin_detectors: list[str] | None = None  # ← НОВОЕ
```

### 2. Обновить `InputSanitizer.__init__`

```python
def __init__(self, config: SanitizerConfig | None = None) -> None:
    self._config = config or SanitizerConfig()
    self._compiled_patterns: list[re.Pattern] | None = None
    if self._config.blocked_patterns:
        self._compiled_patterns = [re.compile(p, re.IGNORECASE) for p in self._config.blocked_patterns]

    # Load built-in detectors
    self._detectors: list[Detector] | None = None
    if self._config.builtin_detectors:
        from policyshield.shield.detectors import get_detectors
        self._detectors = get_detectors(self._config.builtin_detectors)
```

### 3. Обновить `InputSanitizer.sanitize`

Добавить проверку детекторов **перед** blocked_patterns:

```python
def sanitize(self, args: dict) -> SanitizeResult:
    """Sanitize *args* according to the current config."""
    warnings: list[str] = []
    was_modified = False

    raw_str = _flatten_to_string(args)

    # Built-in detectors (before user patterns)
    if self._detectors:
        from policyshield.shield.detectors import scan_all
        matches = scan_all(raw_str, self._detectors)
        if matches:
            first = matches[0]
            return SanitizeResult(
                sanitized_args=args,
                warnings=[],
                was_modified=False,
                rejected=True,
                rejection_reason=(
                    f"Built-in detector [{first.detector_name}]: "
                    f"{first.description} (matched: {first.matched_text!r})"
                ),
            )

    # Check blocked patterns (existing logic, unchanged)
    if self._compiled_patterns:
        for pat in self._compiled_patterns:
            if pat.search(raw_str):
                return SanitizeResult(
                    sanitized_args=args,
                    warnings=[],
                    was_modified=False,
                    rejected=True,
                    rejection_reason=f"Blocked pattern matched: {pat.pattern!r}",
                )

    # Deep-copy and sanitize (existing logic, unchanged)
    ...
```

### 4. Тесты

#### `tests/test_sanitizer_detectors.py`

```python
"""Tests for built-in detector integration in InputSanitizer."""

from policyshield.shield.sanitizer import InputSanitizer, SanitizerConfig


class TestBuiltinDetectors:
    def test_path_traversal_blocked(self):
        san = InputSanitizer(SanitizerConfig(builtin_detectors=["path_traversal"]))
        result = san.sanitize({"path": "../../etc/passwd"})
        assert result.rejected
        assert "path_traversal" in result.rejection_reason

    def test_shell_injection_blocked(self):
        san = InputSanitizer(SanitizerConfig(builtin_detectors=["shell_injection"]))
        result = san.sanitize({"command": "; rm -rf /"})
        assert result.rejected
        assert "shell_injection" in result.rejection_reason

    def test_sql_injection_blocked(self):
        san = InputSanitizer(SanitizerConfig(builtin_detectors=["sql_injection"]))
        result = san.sanitize({"query": "' OR '1'='1"})
        assert result.rejected

    def test_ssrf_blocked(self):
        san = InputSanitizer(SanitizerConfig(builtin_detectors=["ssrf"]))
        result = san.sanitize({"url": "http://169.254.169.254/latest/meta-data/"})
        assert result.rejected
        assert "ssrf" in result.rejection_reason

    def test_safe_args_pass(self):
        san = InputSanitizer(SanitizerConfig(
            builtin_detectors=["path_traversal", "shell_injection", "sql_injection", "ssrf"]
        ))
        result = san.sanitize({"text": "Hello world", "count": "42"})
        assert not result.rejected

    def test_multiple_detectors(self):
        san = InputSanitizer(SanitizerConfig(
            builtin_detectors=["path_traversal", "shell_injection"]
        ))
        result = san.sanitize({"path": "../../etc/passwd"})
        assert result.rejected

    def test_no_detectors_no_block(self):
        """Without builtin_detectors, traversal is not caught."""
        san = InputSanitizer(SanitizerConfig())
        result = san.sanitize({"path": "../../etc/passwd"})
        assert not result.rejected

    def test_detectors_before_blocked_patterns(self):
        """Built-in detectors run before user-defined patterns."""
        san = InputSanitizer(SanitizerConfig(
            builtin_detectors=["path_traversal"],
            blocked_patterns=[r"custom_pattern"],
        ))
        result = san.sanitize({"path": "../../etc/passwd"})
        assert result.rejected
        assert "path_traversal" in result.rejection_reason  # Not "custom_pattern"

    def test_nested_args_detected(self):
        """Detectors scan flattened nested structures."""
        san = InputSanitizer(SanitizerConfig(builtin_detectors=["ssrf"]))
        result = san.sanitize({"config": {"url": "http://169.254.169.254/"}})
        assert result.rejected

    def test_url_schemes(self):
        san = InputSanitizer(SanitizerConfig(builtin_detectors=["url_schemes"]))
        result = san.sanitize({"link": "javascript:alert(1)"})
        assert result.rejected
```

## Самопроверка

```bash
pytest tests/test_sanitizer_detectors.py -v
pytest tests/test_sanitizer.py -v   # Existing tests still pass
pytest tests/ -q
```

## Коммит

```
feat(security): integrate built-in detectors into InputSanitizer

- Add builtin_detectors field to SanitizerConfig
- Detectors run before user-defined blocked_patterns
- Rejection reason includes detector name and matched text
- Zero config overhead when detectors not enabled
```
