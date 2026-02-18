# Prompt 203 — Detector YAML Config & E2E Tests

## Цель

Добавить поддержку `builtin_detectors` в конфиг-файл `policyshield.yaml` и парсер. Написать E2E тест, проверяющий, что engine блокирует атаки через встроенные детекторы.

## Контекст

- После промптов 201–202 детекторы работают программно через `SanitizerConfig`
- Пользователи конфигурируют PolicyShield через `policyshield.yaml`
- Нужно, чтобы `builtin_detectors` работали через YAML:
  ```yaml
  sanitizer:
    builtin_detectors:
      - path_traversal
      - shell_injection
      - sql_injection
      - ssrf
      - url_schemes
  ```
- Парсер конфига: `policyshield/core/config.py` (если нет — создать)
- E2E тест: engine + sanitizer + детекторы работают вместе

## Что сделать

### 1. Обновить парсинг конфига

В YAML-парсере (или при создании engine) добавить чтение `sanitizer.builtin_detectors`:

```python
# В месте, где создаётся engine из YAML-конфига:
sanitizer_config = config.get("sanitizer", {})
if sanitizer_config:
    from policyshield.shield.sanitizer import InputSanitizer, SanitizerConfig
    san = InputSanitizer(SanitizerConfig(
        builtin_detectors=sanitizer_config.get("builtin_detectors"),
        blocked_patterns=sanitizer_config.get("blocked_patterns"),
    ))
```

### 2. E2E тест

#### `tests/test_e2e_detectors.py`

```python
"""E2E tests: built-in detectors block attacks through the full engine pipeline."""

import pytest
from policyshield.shield.engine import ShieldEngine
from policyshield.shield.sanitizer import InputSanitizer, SanitizerConfig
from policyshield.core.parser import RuleSet


def _engine_with_detectors(detectors: list[str]) -> ShieldEngine:
    """Create engine with built-in detectors and no rules."""
    ruleset = RuleSet(rules=[], default_verdict="allow")
    sanitizer = InputSanitizer(SanitizerConfig(builtin_detectors=detectors))
    return ShieldEngine(rules=ruleset, sanitizer=sanitizer)


class TestDetectorE2E:
    def test_path_traversal_blocks(self):
        engine = _engine_with_detectors(["path_traversal"])
        result = engine.check("read_file", {"path": "../../etc/passwd"})
        assert result.verdict.value == "block"
        assert "path_traversal" in result.message

    def test_shell_injection_blocks(self):
        engine = _engine_with_detectors(["shell_injection"])
        result = engine.check("exec", {"command": "; rm -rf /"})
        assert result.verdict.value == "block"

    def test_ssrf_blocks(self):
        engine = _engine_with_detectors(["ssrf"])
        result = engine.check("http_fetch", {"url": "http://169.254.169.254/meta"})
        assert result.verdict.value == "block"

    def test_sql_injection_blocks(self):
        engine = _engine_with_detectors(["sql_injection"])
        result = engine.check("query_db", {"sql": "' OR '1'='1"})
        assert result.verdict.value == "block"

    def test_safe_call_allowed(self):
        engine = _engine_with_detectors(
            ["path_traversal", "shell_injection", "sql_injection", "ssrf", "url_schemes"]
        )
        result = engine.check("read_file", {"path": "/home/user/notes.txt"})
        assert result.verdict.value == "allow"

    def test_no_detectors_allows_traversal(self):
        """Without detectors, traversal is not caught by sanitizer."""
        ruleset = RuleSet(rules=[], default_verdict="allow")
        engine = ShieldEngine(rules=ruleset)
        result = engine.check("read_file", {"path": "../../etc/passwd"})
        assert result.verdict.value == "allow"

    def test_detectors_plus_rules(self):
        """Detectors block before rules even run."""
        engine = _engine_with_detectors(["shell_injection"])
        # Even though we have no rule for exec, detector catches it
        result = engine.check("exec", {"command": "`whoami`"})
        assert result.verdict.value == "block"
        assert "__sanitizer__" in (result.rule_id or "")

    def test_all_five_detectors(self):
        """All 5 detectors can be enabled simultaneously."""
        engine = _engine_with_detectors(
            ["path_traversal", "shell_injection", "sql_injection", "ssrf", "url_schemes"]
        )
        attacks = [
            ("read_file", {"path": "../../etc/passwd"}),
            ("exec", {"command": "; cat /etc/passwd"}),
            ("query", {"sql": "' OR '1'='1"}),
            ("fetch", {"url": "http://169.254.169.254/"}),
            ("render", {"link": "javascript:alert(1)"}),
        ]
        for tool, args in attacks:
            result = engine.check(tool, args)
            assert result.verdict.value == "block", f"Expected block for {tool} with {args}"
```

## Самопроверка

```bash
pytest tests/test_e2e_detectors.py -v
pytest tests/ -q
```

## Коммит

```
feat(security): add YAML config for builtin_detectors + E2E tests

- Support sanitizer.builtin_detectors in policyshield.yaml
- E2E tests: all 5 detectors block through full engine pipeline
- Verify detectors work without YAML rules (pre-rule sanitization)
- Verify safe calls pass through when all detectors enabled
```
