# 513 — Dry-Run CLI

## Goal

Add direct CLI check: `policyshield check --tool <name> --args '<json>' --rules <path>`.

## Context

- Currently need playground REPL or running server for checks
- One-shot CLI check is useful for CI, scripts, debugging
- Should output verdict, rule_id, message in text/JSON format

## Code

### Modify: `policyshield/cli/main.py`

Add `check` subcommand:

```python
check_parser = subparsers.add_parser("check", help="One-shot tool call check")
check_parser.add_argument("--tool", required=True, help="Tool name")
check_parser.add_argument("--args", default="{}", help="JSON args string")
check_parser.add_argument("--rules", required=True, help="Rules YAML path")
check_parser.add_argument("--session-id", default="cli", help="Session ID")
check_parser.add_argument("--json", action="store_true", help="JSON output")
```

Handler:

```python
def _cmd_check(parsed) -> int:
    engine = ShieldEngine(rules=parsed.rules)
    args = json.loads(parsed.args)
    result = engine.check(parsed.tool, args, session_id=parsed.session_id)
    if parsed.json:
        print(json.dumps({"verdict": result.verdict.value, "message": result.message, "rule_id": result.rule_id}))
    else:
        icon = "✓" if result.verdict.value == "ALLOW" else "✗"
        print(f"{icon} {result.verdict.value}: {result.message}")
        if result.rule_id:
            print(f"  Rule: {result.rule_id}")
    return 0 if result.verdict.value == "ALLOW" else 2
```

Exit codes: 0=ALLOW, 2=BLOCK/APPROVE/REDACT (non-zero for CI gates).

## Tests

- Test `policyshield check --tool safe --rules ...` → exit 0
- Test `policyshield check --tool blocked --rules ...` → exit 2
- Test `--json` flag outputs valid JSON

## Self-check

```bash
policyshield check --tool read_file --args '{}' --rules examples/policyshield.yaml
policyshield check --tool exec_command --args '{"cmd":"rm -rf /"}' --rules examples/policyshield.yaml --json
```

## Commit

```
feat(cli): add one-shot 'policyshield check' command for CI and scripting
```
