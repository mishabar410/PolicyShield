"""PolicyShield init scaffold — generates starter project files."""

from __future__ import annotations

from pathlib import Path
from typing import Any


# ---------- preset rule templates ----------

_MINIMAL_RULES: list[dict[str, Any]] = [
    {
        "id": "block-dangerous-commands",
        "description": "Block destructive shell commands",
        "when": {"tool": "exec", "args_match": {"command": {"regex": r"rm\s+-rf|mkfs|dd\s+if="}}},
        "then": "block",
        "severity": "critical",
        "message": "Destructive shell commands are not allowed.",
    },
    {
        "id": "redact-pii",
        "description": "Redact PII from outgoing messages",
        "when": {"tool": ["send_message", "web_fetch"]},
        "then": "redact",
        "severity": "medium",
        "message": "PII will be redacted before sending.",
    },
    {
        "id": "allow-reads",
        "description": "Allow file reads",
        "when": {"tool": "read_file"},
        "then": "allow",
    },
]

_SECURITY_RULES: list[dict[str, Any]] = [
    {
        "id": "block-shell-injection",
        "description": "Block destructive shell commands",
        "when": {"tool": "exec", "args_match": {"command": {"regex": r"rm\s+-rf|mkfs|dd\s+if=|format\s+c:|fdisk"}}},
        "then": "block",
        "severity": "critical",
        "message": "Destructive shell commands are not allowed.",
    },
    {
        "id": "block-file-delete",
        "description": "Block all file deletion",
        "when": {"tool": "delete_file"},
        "then": "block",
        "severity": "high",
        "message": "File deletion is not allowed.",
    },
    {
        "id": "block-write-system",
        "description": "Block writes to system directories",
        "when": {"tool": "write_file", "args_match": {"path": {"regex": r"^/(etc|usr|var|bin|sbin)/"}}},
        "then": "block",
        "severity": "critical",
        "message": "Writing outside the workspace is not allowed.",
    },
    {
        "id": "redact-pii-external",
        "description": "Redact PII from external requests",
        "when": {"tool": ["web_fetch", "web_search", "send_message"]},
        "then": "redact",
        "severity": "high",
        "message": "PII redacted before sending externally.",
    },
    {
        "id": "approve-network-downloads",
        "description": "Require approval for network downloads",
        "when": {"tool": "exec", "args_match": {"command": {"regex": "curl|wget"}}},
        "then": "approve",
        "severity": "medium",
        "message": "Network downloads require explicit approval.",
    },
    {
        "id": "block-spawn-process",
        "description": "Block spawning new processes",
        "when": {"tool": "spawn"},
        "then": "block",
        "severity": "high",
        "message": "Spawning new processes is blocked.",
    },
    {
        "id": "rate-limit-web",
        "description": "Rate limit web requests",
        "when": {"tool": "web_fetch", "session": {"tool_count.web_fetch": {"gt": 10}}},
        "then": "block",
        "severity": "medium",
        "message": "Web request rate limit exceeded.",
    },
    {
        "id": "allow-reads",
        "description": "Allow file reads",
        "when": {"tool": "read_file"},
        "then": "allow",
    },
]

_COMPLIANCE_RULES: list[dict[str, Any]] = [
    {
        "id": "redact-pii-gdpr",
        "description": "GDPR: Redact PII from all external APIs",
        "when": {"tool": ["web_fetch", "http_post", "api_call", "send_message"]},
        "then": "redact",
        "severity": "high",
        "message": "PII must be redacted (GDPR compliance).",
    },
    {
        "id": "approve-delete-operations",
        "description": "Require approval for any delete operation",
        "when": {"tool": "delete_file"},
        "then": "approve",
        "severity": "high",
        "message": "Delete operations require explicit approval.",
    },
    {
        "id": "approve-send-external",
        "description": "Require approval for sending data externally",
        "when": {"tool": ["send_email", "send_message"]},
        "then": "approve",
        "severity": "medium",
        "message": "Sending data externally requires approval.",
    },
    {
        "id": "block-shell-injection",
        "description": "Block destructive shell commands",
        "when": {"tool": "exec", "args_match": {"command": {"regex": r"rm\s+-rf|mkfs|dd\s+if="}}},
        "then": "block",
        "severity": "critical",
        "message": "Destructive shell commands are not allowed.",
    },
    {
        "id": "block-write-system",
        "description": "Block writes to system directories",
        "when": {"tool": "write_file", "args_match": {"path": {"regex": r"^/(etc|usr|var|bin|sbin)/"}}},
        "then": "block",
        "severity": "critical",
        "message": "Writing outside the workspace is not allowed.",
    },
    {
        "id": "rate-limit-api",
        "description": "Rate limit API calls to 20/session",
        "when": {"tool": "api_call", "session": {"tool_count.api_call": {"gt": 20}}},
        "then": "block",
        "severity": "medium",
        "message": "API call rate limit exceeded.",
    },
    {
        "id": "rate-limit-web",
        "description": "Rate limit web requests to 10/session",
        "when": {"tool": "web_fetch", "session": {"tool_count.web_fetch": {"gt": 10}}},
        "then": "block",
        "severity": "medium",
        "message": "Web request rate limit exceeded.",
    },
    {
        "id": "audit-shell",
        "description": "Audit trail for all shell commands",
        "when": {"tool": "exec"},
        "then": "allow",
        "severity": "low",
        "message": "Shell command logged for audit.",
    },
    {
        "id": "approve-file-write",
        "description": "Require approval for file writes",
        "when": {"tool": "write_file"},
        "then": "approve",
        "severity": "medium",
        "message": "File writes require approval for compliance audit.",
    },
    {
        "id": "allow-reads",
        "description": "Allow file reads",
        "when": {"tool": "read_file"},
        "then": "allow",
    },
]

_OPENCLAW_RULES: list[dict[str, Any]] = [
    {
        "id": "block-destructive-exec",
        "description": "Block destructive shell commands",
        "when": {
            "tool": "exec",
            "args_match": {
                "command": {"regex": r"\b(rm\s+-rf|rm\s+-r\s+/|mkfs|dd\s+if=|chmod\s+777|chmod\s+-R\s+777)\b"}
            },
        },
        "then": "block",
        "severity": "critical",
        "message": "Destructive command blocked by PolicyShield",
    },
    {
        "id": "block-curl-pipe-sh",
        "description": "Block remote code execution via curl|sh",
        "when": {
            "tool": "exec",
            "args_match": {"command": {"regex": r"curl.*\|.*sh|wget.*\|.*sh|curl.*\|.*bash"}},
        },
        "then": "block",
        "severity": "critical",
        "message": "Remote code execution via curl|sh is blocked",
    },
    {
        "id": "block-secrets-exfil",
        "description": "Block potential secrets exfiltration",
        "when": {
            "tool": "exec",
            "args_match": {
                "command": {
                    "regex": r"\b(curl|wget|nc|ncat|scp|rsync)\b.*\b(AWS_SECRET|OPENAI_API_KEY|API_KEY|SECRET_KEY|password|token|private.key)\b"
                }
            },
        },
        "then": "block",
        "severity": "critical",
        "message": "Potential secrets exfiltration blocked",
    },
    {
        "id": "block-env-dump",
        "description": "Block environment variable dumps",
        "when": {
            "tool": "exec",
            "args_match": {"command": {"regex": r"\benv\b|\bprintenv\b|\bset\b.*export"}},
        },
        "then": "block",
        "severity": "high",
        "message": "Environment variable dump is restricted",
    },
    {
        "id": "redact-pii-in-messages",
        "description": "Redact PII in outgoing messages",
        "when": {"tool": "message"},
        "then": "redact",
        "severity": "high",
        "message": "PII detected and redacted in outgoing message",
    },
    {
        "id": "redact-pii-in-writes",
        "description": "Redact PII in file writes",
        "when": {"tool": "write"},
        "then": "redact",
        "severity": "medium",
        "message": "PII detected and redacted in file write",
    },
    {
        "id": "redact-pii-in-edits",
        "description": "Redact PII in file edits",
        "when": {"tool": "edit"},
        "then": "redact",
        "severity": "medium",
        "message": "PII detected and redacted in file edit",
    },
    {
        "id": "approve-dotenv-write",
        "description": "Require approval for writing sensitive files",
        "when": {
            "tool": "write",
            "args_match": {"file_path": {"regex": r"\.(env|pem|key|crt|p12|pfx)$"}},
        },
        "then": "approve",
        "severity": "high",
        "message": "Writing to sensitive file requires approval",
    },
    {
        "id": "approve-ssh-access",
        "description": "Require approval for SSH key modification",
        "when": {
            "tool": "write",
            "args_match": {"file_path": {"contains": ".ssh/"}},
        },
        "then": "approve",
        "severity": "critical",
        "message": "SSH key modification requires approval",
    },
    {
        "id": "rate-limit-exec",
        "description": "Rate limit exec calls",
        "when": {"tool": "exec", "session": {"tool_count.exec": {"gt": 60}}},
        "then": "block",
        "message": "exec rate limit exceeded (60/min)",
    },
    {
        "id": "rate-limit-web",
        "description": "Rate limit web_fetch calls",
        "when": {"tool": "web_fetch", "session": {"tool_count.web_fetch": {"gt": 30}}},
        "then": "block",
        "message": "web_fetch rate limit exceeded (30/min)",
    },
]


def _get_preset_rules(preset: str) -> list[dict[str, Any]]:
    """Return rules for the given preset name."""
    presets = {
        "minimal": _MINIMAL_RULES,
        "security": _SECURITY_RULES,
        "compliance": _COMPLIANCE_RULES,
        "openclaw": _OPENCLAW_RULES,
    }
    if preset not in presets:
        raise ValueError(f"Unknown preset: {preset}. Choose from: {', '.join(presets)}")
    return [dict(r) for r in presets[preset]]


def _generate_test_cases(rules: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Generate positive + negative test cases for each rule."""
    tests: list[dict[str, Any]] = []
    for rule in rules:
        rule_id = rule["id"]
        when = rule.get("when", {})
        then = rule.get("then", "allow")
        tool_name = when.get("tool", "unknown_tool")
        if isinstance(tool_name, list):
            tool_name = tool_name[0]

        # Build sample args for a positive match
        args_match = when.get("args_match", {})
        sample_args: dict[str, str] = {}
        for key, cond in args_match.items():
            if isinstance(cond, dict):
                if "regex" in cond:
                    # Build a simple string that matches
                    regex_val = cond["regex"]
                    if "rm" in regex_val:
                        sample_args[key] = "rm -rf /tmp"
                    elif "curl" in regex_val:
                        sample_args[key] = "curl https://example.com"
                    elif "^/" in regex_val:
                        sample_args[key] = "/etc/passwd"
                    elif "sudo" in regex_val:
                        sample_args[key] = "sudo rm -rf /"
                    else:
                        sample_args[key] = "test-value"
                elif "contains" in cond:
                    sample_args[key] = cond["contains"]
            else:
                sample_args[key] = str(cond)

        # Positive test: action should match the rule verdict
        expected_verdict = then.upper()
        positive_test: dict[str, Any] = {
            "name": f"{rule_id} — positive match",
            "tool": tool_name,
            "args": sample_args if sample_args else {"input": "test"},
            "expect": {"verdict": expected_verdict},
        }
        if expected_verdict != "ALLOW":
            positive_test["expect"]["rule_id"] = rule_id
        tests.append(positive_test)

        # Negative test: different tool → ALLOW
        negative_test: dict[str, Any] = {
            "name": f"{rule_id} — negative (different tool)",
            "tool": "safe_test_tool_xyz",
            "args": {"input": "safe value"},
            "expect": {"verdict": "ALLOW"},
        }
        tests.append(negative_test)

    return tests


def _to_yaml_str(data: dict[str, Any], indent: int = 0) -> str:
    """Convert a dict to YAML string using pyyaml."""
    import yaml

    return yaml.dump(data, default_flow_style=False, allow_unicode=True, sort_keys=False)


def scaffold(
    directory: str | Path,
    preset: str = "minimal",
    interactive: bool = True,
) -> list[str]:
    """Create a starter project scaffold.

    Args:
        directory: Target directory for the scaffold.
        preset: Rule preset (minimal, security, compliance).
        interactive: Whether to prompt user for choices.

    Returns:
        List of created file paths (relative to directory).
    """
    import yaml

    directory = Path(directory)

    # Interactive mode: ask questions
    if interactive:
        preset = _ask_preset(preset)
        trace_enabled = _ask_trace()
    else:
        trace_enabled = True

    # Get rules
    rules = _get_preset_rules(preset)

    # Build rules data
    rules_data: dict[str, Any] = {
        "shield_name": f"{preset}-policy",
        "version": 1,
        "rules": rules,
    }
    if preset == "openclaw":
        rules_data["default_verdict"] = "allow"

    # Build test data
    test_cases = _generate_test_cases(rules)
    test_data = {
        "test_suite": f"{preset}-rules",
        "rules_path": "../policies/rules.yaml",
        "tests": test_cases,
    }

    # Build config
    config_data: dict[str, Any] = {
        "mode": "ENFORCE",
        "fail_open": True,
        "trace": {
            "enabled": trace_enabled,
            "output_dir": "./traces",
        },
    }

    # Create files
    created: list[str] = []

    # Policies dir
    policies_dir = directory / "policies"
    tests_dir = directory / "tests"
    policies_dir.mkdir(parents=True, exist_ok=True)
    tests_dir.mkdir(parents=True, exist_ok=True)

    # rules.yaml
    rules_file = policies_dir / "rules.yaml"
    if rules_file.exists():
        print(f"  ⚠ Skipped {rules_file} (already exists)")
    else:
        rules_file.write_text(
            f"# PolicyShield rules — preset: {preset}\n"
            + yaml.dump(rules_data, default_flow_style=False, allow_unicode=True, sort_keys=False),
            encoding="utf-8",
        )
        created.append("policies/rules.yaml")

    # test_rules.yaml
    test_file = tests_dir / "test_rules.yaml"
    if test_file.exists():
        print(f"  ⚠ Skipped {test_file} (already exists)")
    else:
        test_file.write_text(
            "# Auto-generated test cases for rules\n"
            + yaml.dump(test_data, default_flow_style=False, allow_unicode=True, sort_keys=False),
            encoding="utf-8",
        )
        created.append("tests/test_rules.yaml")

    # policyshield.yaml
    config_file = directory / "policyshield.yaml"
    if config_file.exists():
        print(f"  ⚠ Skipped {config_file} (already exists)")
    else:
        config_file.write_text(
            "# PolicyShield configuration\n"
            + yaml.dump(config_data, default_flow_style=False, allow_unicode=True, sort_keys=False),
            encoding="utf-8",
        )
        created.append("policyshield.yaml")

    # Print summary
    rule_count = len(rules)
    test_count = len(test_cases)
    print()
    for path in created:
        if "rules.yaml" in path and "test" not in path:
            print(f"✓ Created {path} ({rule_count} rules)")
        elif "test_rules" in path:
            print(f"✓ Created {path} ({test_count} test cases)")
        else:
            print(f"✓ Created {path}")

    if created:
        print()
        print("Next steps:")
        print(f"  policyshield validate {directory}/policies/")
        print(f"  policyshield test {directory}/tests/")
        print(f"  policyshield lint {directory}/policies/rules.yaml")
    else:
        print("No files created (all already exist).")

    return created


def _ask_preset(default: str) -> str:
    """Interactively ask for a preset."""
    try:
        print("Choose a preset:")
        print("  1) minimal  — 3 rules (block, redact, allow)")
        print("  2) security — 8 rules (shell, file, network, PII)")
        print("  3) compliance — 10 rules (GDPR, approval flows, audit)")
        print("  4) openclaw — 11 rules (exec, PII, secrets, rate limits)")
        choice = input(f"Preset [{default}]: ").strip()
        mapping = {"1": "minimal", "2": "security", "3": "compliance", "4": "openclaw"}
        if choice in mapping:
            return mapping[choice]
        if choice in ("minimal", "security", "compliance", "openclaw"):
            return choice
        return default
    except (EOFError, KeyboardInterrupt):
        print()
        return default


def _ask_trace() -> bool:
    """Interactively ask about trace."""
    try:
        answer = input("Enable tracing? [Y/n]: ").strip().lower()
        if answer in ("n", "no"):
            return False
        return True
    except (EOFError, KeyboardInterrupt):
        print()
        return True
