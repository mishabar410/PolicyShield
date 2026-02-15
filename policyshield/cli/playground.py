"""PolicyShield interactive playground — try rules without starting a server."""

from __future__ import annotations

import json
import sys
from pathlib import Path

from policyshield.core.exceptions import PolicyShieldParseError
from policyshield.core.parser import load_rules
from policyshield.shield.engine import ShieldEngine


def _print_result(result: object) -> None:
    """Pretty-print a check result."""
    verdict = getattr(result, "verdict", None)
    if verdict is None:
        print(f"  Result: {result}")
        return

    icons = {
        "ALLOW": "✓",
        "BLOCK": "✗",
        "REDACT": "✂",
        "APPROVE": "⏳",
    }
    v = verdict.value if hasattr(verdict, "value") else str(verdict)
    icon = icons.get(v, "?")

    print(f"  {icon} Verdict: {v}")
    if hasattr(result, "rule_id") and result.rule_id:
        print(f"    Rule: {result.rule_id}")
    if hasattr(result, "message") and result.message:
        print(f"    Message: {result.message}")
    if hasattr(result, "pii_types") and result.pii_types:
        print(f"    PII detected: {', '.join(result.pii_types)}")
    if hasattr(result, "redacted_args") and result.redacted_args:
        print(f"    Redacted args: {json.dumps(result.redacted_args, ensure_ascii=False)}")


def cmd_playground(rules_path: str) -> int:
    """Run interactive playground REPL.

    Args:
        rules_path: Path to YAML rules file.

    Returns:
        Exit code (0 = success, 1 = error).
    """
    path = Path(rules_path)
    if not path.exists():
        print(f"✗ Rules file not found: {rules_path}", file=sys.stderr)
        return 1

    try:
        ruleset = load_rules(rules_path)
    except PolicyShieldParseError as e:
        print(f"✗ Error loading rules: {e}", file=sys.stderr)
        return 1

    engine = ShieldEngine(ruleset)

    print(f"🛡️  PolicyShield Playground")
    print(f"   Rules: {ruleset.shield_name} v{ruleset.version} ({engine.rule_count} rules)")
    print()
    print("   Enter tool calls to test against your rules.")
    print("   Format: tool_name [arg1=val1 arg2=val2 ...]")
    print("   Special commands: :rules  :help  :quit")
    print()

    while True:
        try:
            line = input("ps> ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nBye!")
            return 0

        if not line:
            continue

        # Special commands
        if line == ":quit" or line == ":q":
            print("Bye!")
            return 0

        if line == ":help" or line == ":h":
            print("  Usage: tool_name [key=value ...]")
            print("  Example: exec command=rm -rf /")
            print("  Example: send_email to=user@example.com body=Hello!")
            print()
            print("  :rules  — show loaded rules")
            print("  :help   — show this help")
            print("  :quit   — exit")
            continue

        if line == ":rules" or line == ":r":
            for rule in ruleset.rules:
                status = "✓" if rule.enabled else "○"
                print(f"  {status} {rule.id} → {rule.then.value} [{rule.severity.value}]")
            continue

        # Parse tool call
        parts = line.split(maxsplit=1)
        tool_name = parts[0]
        args: dict[str, str] = {}

        if len(parts) > 1:
            raw_args = parts[1]
            # Parse key=value pairs (supports values with spaces via simple splitting)
            for token in _parse_args(raw_args):
                if "=" in token:
                    k, v = token.split("=", 1)
                    args[k] = v
                else:
                    # Treat as positional — put in "command" key
                    args["command"] = token if "command" not in args else args["command"] + " " + token

        # Run check
        try:
            result = engine.check(tool_name, args)
            _print_result(result)
        except Exception as e:
            print(f"  ✗ Error: {e}", file=sys.stderr)

    return 0


def _parse_args(raw: str) -> list[str]:
    """Parse key=value args, respecting simple quoting."""
    tokens: list[str] = []
    current = ""
    in_quote = False
    quote_char = ""

    for ch in raw:
        if in_quote:
            if ch == quote_char:
                in_quote = False
            else:
                current += ch
        elif ch in ('"', "'"):
            in_quote = True
            quote_char = ch
        elif ch == " " and not in_quote:
            if current:
                tokens.append(current)
                current = ""
        else:
            current += ch

    if current:
        tokens.append(current)

    return tokens


def run_single_check(rules_path: str, tool: str, args_json: str | None = None) -> int:
    """Run a single check (non-interactive mode).

    Args:
        rules_path: Path to YAML rules file.
        tool: Tool name to check.
        args_json: JSON string of arguments.

    Returns:
        Exit code (0 = ALLOW, 1 = BLOCK/REDACT/APPROVE, 2 = error).
    """
    path = Path(rules_path)
    if not path.exists():
        print(f"✗ Rules file not found: {rules_path}", file=sys.stderr)
        return 2

    try:
        ruleset = load_rules(rules_path)
    except PolicyShieldParseError as e:
        print(f"✗ Error loading rules: {e}", file=sys.stderr)
        return 2

    engine = ShieldEngine(ruleset)

    args: dict = {}
    if args_json:
        try:
            args = json.loads(args_json)
        except json.JSONDecodeError as e:
            print(f"✗ Invalid JSON args: {e}", file=sys.stderr)
            return 2

    result = engine.check(tool, args)
    _print_result(result)

    verdict = result.verdict.value if hasattr(result.verdict, "value") else str(result.verdict)
    return 0 if verdict == "ALLOW" else 1
