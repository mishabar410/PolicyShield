# Prompt 206 — Secure Preset

## Цель

Добавить пресет `--preset secure` в `policyshield init` — security-by-default конфигурация с `default_verdict: block`, whitelist разрешённых действий, и всеми встроенными детекторами.

## Контекст

- Сейчас 4 пресета: minimal, security, compliance, openclaw
- Ни один не использует `default_verdict: block` — все разрешают по умолчанию
- `secure` = философия «всё запрещено, если не разрешено явно»
- Включает **все** builtin detectors
- Whitelist: read_file, list_dir, search, help, status — только безопасные операции
- Всё остальное: BLOCK или APPROVE
- Это «поставил и защищён» пресет

## Что сделать

### 1. Добавить `_SECURE_RULES` в `policyshield/cli/init_scaffold.py`

```python
_SECURE_RULES: list[dict[str, Any]] = [
    # === Whitelist: safe read-only operations ===
    {
        "id": "allow-read-file",
        "description": "Allow reading files",
        "when": {"tool": "read_file"},
        "then": "allow",
    },
    {
        "id": "allow-list-dir",
        "description": "Allow listing directories",
        "when": {"tool": ["list_dir", "list_files", "ls"]},
        "then": "allow",
    },
    {
        "id": "allow-search",
        "description": "Allow search operations",
        "when": {"tool": ["search", "grep", "find", "search_files"]},
        "then": "allow",
    },
    {
        "id": "allow-info",
        "description": "Allow info/status/help tools",
        "when": {"tool": ["help", "status", "version", "info", "health"]},
        "then": "allow",
    },
    # === Require approval for write operations ===
    {
        "id": "approve-write",
        "description": "Require approval for all write operations",
        "when": {"tool": ["write_file", "write", "edit", "edit_file", "patch"]},
        "then": "approve",
        "severity": "medium",
        "message": "File write requires approval",
    },
    {
        "id": "approve-create",
        "description": "Require approval for creating files",
        "when": {"tool": ["create_file", "create", "touch", "mkdir"]},
        "then": "approve",
        "severity": "medium",
        "message": "File creation requires approval",
    },
    # === Hard block: destructive / network / exec ===
    {
        "id": "block-exec",
        "description": "Block all command execution",
        "when": {"tool": ["exec", "shell", "run_command", "system", "spawn"]},
        "then": "block",
        "severity": "critical",
        "message": "Command execution is blocked in secure mode",
    },
    {
        "id": "block-delete",
        "description": "Block all delete operations",
        "when": {"tool": ["delete_file", "delete", "remove", "rm", "unlink"]},
        "then": "block",
        "severity": "critical",
        "message": "Deletion is blocked in secure mode",
    },
    {
        "id": "block-network",
        "description": "Block all network operations",
        "when": {"tool": ["web_fetch", "http_request", "curl", "wget", "http_post", "api_call"]},
        "then": "block",
        "severity": "high",
        "message": "Network access is blocked in secure mode",
    },
    {
        "id": "redact-pii-all",
        "description": "Redact PII from any outgoing tool",
        "when": {"tool": ["send_message", "message", "reply", "send_email"]},
        "then": "redact",
        "severity": "high",
        "message": "PII redacted from outgoing message",
    },
]
```

### 2. Обновить `_get_preset_rules`

```python
def _get_preset_rules(preset: str) -> list[dict[str, Any]]:
    presets = {
        "minimal": _MINIMAL_RULES,
        "security": _SECURITY_RULES,
        "compliance": _COMPLIANCE_RULES,
        "openclaw": _OPENCLAW_RULES,
        "secure": _SECURE_RULES,  # ← НОВОЕ
    }
    ...
```

### 3. Обновить `scaffold()` — secure preset creates special config

В `scaffold()` добавить:

```python
# Build config
config_data: dict[str, Any] = {
    "mode": "ENFORCE",
    "fail_open": True if preset != "secure" else False,  # Secure: fail-closed
    "trace": {
        "enabled": trace_enabled,
        "output_dir": "./traces",
    },
}

# Secure preset: add builtin detectors and default_verdict: block
if preset == "secure":
    rules_data["default_verdict"] = "block"
    config_data["sanitizer"] = {
        "builtin_detectors": [
            "path_traversal",
            "shell_injection",
            "sql_injection",
            "ssrf",
            "url_schemes",
        ],
    }
    config_data["fail_open"] = False
```

### 4. Обновить `_ask_preset` — добавить вариант 5

```python
def _ask_preset(default: str) -> str:
    try:
        print("Choose a preset:")
        print("  1) minimal    — 3 rules (block, redact, allow)")
        print("  2) security   — 8 rules (shell, file, network, PII)")
        print("  3) compliance — 10 rules (GDPR, approval flows, audit)")
        print("  4) openclaw   — 11 rules (exec, PII, secrets, rate limits)")
        print("  5) secure     — 10 rules (default BLOCK + whitelist + all detectors)")
        choice = input(f"Preset [{default}]: ").strip()
        mapping = {"1": "minimal", "2": "security", "3": "compliance", "4": "openclaw", "5": "secure"}
        if choice in mapping:
            return mapping[choice]
        if choice in mapping.values():
            return choice
        return default
    except (EOFError, KeyboardInterrupt):
        print()
        return default
```

### 5. Тесты

#### `tests/test_secure_preset.py`

```python
"""Tests for --preset secure."""

import tempfile
from pathlib import Path

import yaml

from policyshield.cli.init_scaffold import scaffold, _get_preset_rules


class TestSecurePreset:
    def test_rules_count(self):
        rules = _get_preset_rules("secure")
        assert len(rules) == 10

    def test_has_whitelist(self):
        rules = _get_preset_rules("secure")
        allow_rules = [r for r in rules if r["then"] == "allow"]
        assert len(allow_rules) >= 4  # read, list, search, info

    def test_has_blocks(self):
        rules = _get_preset_rules("secure")
        block_rules = [r for r in rules if r["then"] == "block"]
        assert len(block_rules) >= 3  # exec, delete, network

    def test_scaffold_creates_files(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            created = scaffold(tmpdir, preset="secure", interactive=False)
            assert "policies/rules.yaml" in created
            assert "policyshield.yaml" in created

    def test_scaffold_default_verdict_block(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            scaffold(tmpdir, preset="secure", interactive=False)
            rules_file = Path(tmpdir) / "policies" / "rules.yaml"
            data = yaml.safe_load(rules_file.read_text())
            assert data["default_verdict"] == "block"

    def test_scaffold_builtin_detectors(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            scaffold(tmpdir, preset="secure", interactive=False)
            config_file = Path(tmpdir) / "policyshield.yaml"
            config = yaml.safe_load(config_file.read_text())
            detectors = config.get("sanitizer", {}).get("builtin_detectors", [])
            assert "path_traversal" in detectors
            assert "shell_injection" in detectors
            assert len(detectors) == 5

    def test_scaffold_fail_closed(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            scaffold(tmpdir, preset="secure", interactive=False)
            config_file = Path(tmpdir) / "policyshield.yaml"
            config = yaml.safe_load(config_file.read_text())
            assert config["fail_open"] is False

    def test_preset_not_break_others(self):
        """Adding secure preset doesn't break existing presets."""
        for preset in ("minimal", "security", "compliance", "openclaw"):
            rules = _get_preset_rules(preset)
            assert len(rules) > 0
```

## Самопроверка

```bash
pytest tests/test_secure_preset.py -v
pytest tests/test_scaffold.py -v   # Existing scaffold tests still pass
pytest tests/ -q
```

## Коммит

```
feat(dx): add --preset secure for security-by-default setup

- New preset: default_verdict=block, whitelist reads, block exec/delete/net
- Enables all 5 builtin detectors automatically
- Sets fail_open=false (fail-closed for maximum security)
- 10 rules: 4 allow, 2 approve, 3 block, 1 redact
```
