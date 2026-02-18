# Prompt 212 — Honeypot Tools

## Цель

Добавить механизм honeypot-тулов — фейковые tools, которые не должны вызываться. Если LLM их вызывает — это сигнал prompt injection или anomalous behavior.

## Контекст

- Honeypot — инструмент, который **не существует** в реальном workflow
- Если LLM вызывает honeypot tool → вероятная prompt injection или hallucination
- Конфигурируется в YAML:
  ```yaml
  honeypots:
    - name: internal_admin_panel
      alert: "Honeypot triggered: agent tried to access admin panel"
    - name: export_all_data
      alert: "Honeypot triggered: agent tried to export all data"
    - name: disable_security
      alert: "Honeypot triggered: agent tried to disable security"
  ```
- При match: BLOCK + алерт с повышенным severity + запись в trace
- Honeypot check идёт **после** kill switch, **перед** sanitizer (максимально ранняя детекция)
- Honeypot match не зависит от режима (ENFORCE/AUDIT) — всегда block

## Что сделать

### 1. Создать `policyshield/shield/honeypots.py`

```python
"""Honeypot tools — decoy tools that signal prompt injection or anomalous behavior.

Honeypots are fake tool names that should never be called in normal operation.
If an LLM agent tries to call a honeypot, it signals prompt injection,
jailbreaking, or abnormal behavior.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any


logger = logging.getLogger("policyshield.honeypot")


@dataclass(frozen=True)
class HoneypotConfig:
    """A configured honeypot tool."""
    name: str
    alert: str = ""
    severity: str = "critical"

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> HoneypotConfig:
        return cls(
            name=data["name"],
            alert=data.get("alert", f"Honeypot triggered: {data['name']}"),
            severity=data.get("severity", "critical"),
        )


@dataclass(frozen=True)
class HoneypotMatch:
    """Result when a honeypot is triggered."""
    honeypot: HoneypotConfig
    tool_name: str

    @property
    def message(self) -> str:
        return self.honeypot.alert or f"Honeypot triggered: {self.tool_name}"


class HoneypotChecker:
    """Checks tool calls against configured honeypots."""

    def __init__(self, honeypots: list[HoneypotConfig]) -> None:
        self._lookup: dict[str, HoneypotConfig] = {h.name: h for h in honeypots}

    @classmethod
    def from_config(cls, config_list: list[dict[str, Any]]) -> HoneypotChecker:
        """Create from YAML config list."""
        return cls([HoneypotConfig.from_dict(d) for d in config_list])

    def check(self, tool_name: str) -> HoneypotMatch | None:
        """Check if a tool name matches a honeypot.

        Args:
            tool_name: The tool being called.

        Returns:
            HoneypotMatch if triggered, None otherwise.
        """
        if tool_name in self._lookup:
            match = HoneypotMatch(
                honeypot=self._lookup[tool_name],
                tool_name=tool_name,
            )
            logger.critical(
                "🍯 HONEYPOT TRIGGERED: tool=%s alert=%s",
                tool_name,
                match.message,
            )
            return match
        return None

    @property
    def names(self) -> set[str]:
        """Set of configured honeypot tool names."""
        return set(self._lookup.keys())

    def __len__(self) -> int:
        return len(self._lookup)
```

### 2. Интегрировать в `BaseShieldEngine`

В `__init__`:

```python
# Honeypot checker (load from ruleset or config)
honeypot_config = getattr(self._rule_set, "honeypots", None)
if honeypot_config:
    from policyshield.shield.honeypots import HoneypotChecker
    self._honeypot_checker = HoneypotChecker.from_config(honeypot_config)
else:
    self._honeypot_checker = None
```

В `_do_check_sync`, **после** kill switch, **перед** sanitizer:

```python
def _do_check_sync(self, tool_name, args, session_id, sender):
    # Kill switch (existing)
    if self._killed.is_set():
        ...

    # Honeypot check — always block, regardless of mode
    if self._honeypot_checker is not None:
        honeypot_match = self._honeypot_checker.check(tool_name)
        if honeypot_match:
            return ShieldResult(
                verdict=Verdict.BLOCK,
                rule_id="__honeypot__",
                message=honeypot_match.message,
            )

    # Sanitize args (existing)
    ...
```

### 3. Обновить парсер YAML — поддержка `honeypots` в RuleSet

В `policyshield/core/parser.py`, при загрузке yaml-файла:

```python
# В load_rules или RuleSet:
# Добавить поле honeypots: list[dict] | None = None
# При парсинге: ruleset.honeypots = data.get("honeypots", None)
```

### 4. Тесты

#### `tests/test_honeypots.py`

```python
"""Tests for honeypot tools."""

import pytest

from policyshield.shield.honeypots import (
    HoneypotChecker,
    HoneypotConfig,
    HoneypotMatch,
)


class TestHoneypotConfig:
    def test_from_dict(self):
        cfg = HoneypotConfig.from_dict({"name": "admin_panel", "alert": "Alert!"})
        assert cfg.name == "admin_panel"
        assert cfg.alert == "Alert!"

    def test_default_alert(self):
        cfg = HoneypotConfig.from_dict({"name": "admin_panel"})
        assert "admin_panel" in cfg.alert

    def test_default_severity(self):
        cfg = HoneypotConfig.from_dict({"name": "x"})
        assert cfg.severity == "critical"


class TestHoneypotChecker:
    def test_match(self):
        checker = HoneypotChecker([HoneypotConfig(name="secret_tool", alert="CAUGHT")])
        match = checker.check("secret_tool")
        assert match is not None
        assert match.tool_name == "secret_tool"
        assert "CAUGHT" in match.message

    def test_no_match(self):
        checker = HoneypotChecker([HoneypotConfig(name="secret_tool")])
        assert checker.check("read_file") is None

    def test_multiple_honeypots(self):
        checker = HoneypotChecker([
            HoneypotConfig(name="admin_panel"),
            HoneypotConfig(name="export_all"),
            HoneypotConfig(name="disable_security"),
        ])
        assert checker.check("admin_panel") is not None
        assert checker.check("export_all") is not None
        assert checker.check("normal_tool") is None
        assert len(checker) == 3

    def test_from_config(self):
        checker = HoneypotChecker.from_config([
            {"name": "a", "alert": "Alert A"},
            {"name": "b"},
        ])
        assert len(checker) == 2
        assert checker.check("a") is not None

    def test_names(self):
        checker = HoneypotChecker([
            HoneypotConfig(name="a"),
            HoneypotConfig(name="b"),
        ])
        assert checker.names == {"a", "b"}


class TestHoneypotE2E:
    """Test honeypots through the engine pipeline."""

    def test_engine_blocks_honeypot(self):
        from policyshield.core.parser import RuleSet
        from policyshield.shield.engine import ShieldEngine

        ruleset = RuleSet(rules=[], default_verdict="allow")
        # Manually set honeypots (simulating YAML config load)
        ruleset.honeypots = [
            {"name": "internal_admin", "alert": "Admin access attempted!"},
        ]
        engine = ShieldEngine(rules=ruleset)
        result = engine.check("internal_admin", {})
        assert result.verdict.value == "block"
        assert "__honeypot__" in (result.rule_id or "")

    def test_engine_allows_normal_tool(self):
        from policyshield.core.parser import RuleSet
        from policyshield.shield.engine import ShieldEngine

        ruleset = RuleSet(rules=[], default_verdict="allow")
        ruleset.honeypots = [
            {"name": "internal_admin"},
        ]
        engine = ShieldEngine(rules=ruleset)
        result = engine.check("read_file", {"path": "test.txt"})
        assert result.verdict.value == "allow"

    def test_honeypot_overrides_audit_mode(self):
        from policyshield.core.models import ShieldMode
        from policyshield.core.parser import RuleSet
        from policyshield.shield.engine import ShieldEngine

        ruleset = RuleSet(rules=[], default_verdict="allow")
        ruleset.honeypots = [{"name": "bad_tool"}]
        engine = ShieldEngine(rules=ruleset, mode=ShieldMode.AUDIT)
        result = engine.check("bad_tool", {})
        assert result.verdict.value == "block"  # Always block, even in audit
```

### 5. Пример YAML-конфигурации

```yaml
# rules.yaml
shield_name: my-secure-policy
version: 1
default_verdict: block

honeypots:
  - name: internal_admin_panel
    alert: "🍯 Agent tried to access admin panel — possible injection"
  - name: export_all_data
    alert: "🍯 Agent tried to export all data — possible injection"
  - name: disable_security
    alert: "🍯 Agent tried to disable security — highly suspicious"
  - name: sudo_execute
    alert: "🍯 Agent tried to execute sudo — possible privilege escalation"

rules:
  - id: allow-reads
    when: { tool: read_file }
    then: allow
  ...
```

## Самопроверка

```bash
pytest tests/test_honeypots.py -v
pytest tests/ -q
```

## Коммит

```
feat(security): add honeypot tools for prompt injection detection

- HoneypotChecker: O(1) lookup of tool names against configured decoys
- Integrated into engine pipeline: after kill_switch, before sanitizer
- Always blocks (regardless of ENFORCE/AUDIT mode)
- YAML config: honeypots list with name + alert + severity
- Logs critical alert on match via Python logging
```
