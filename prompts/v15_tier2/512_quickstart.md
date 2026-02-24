# 512 — Quickstart Wizard

## Goal

Add `policyshield quickstart` command — interactive wizard that asks questions, generates rules, and starts the server.

## Context

- Lowest-friction onboarding path
- Asks: what tools? what framework? what approval channel?
- Generates config + rules → validates → optionally starts server

## Code

### New file: `policyshield/cli/quickstart.py`

```python
def cmd_quickstart() -> int:
    """Interactive quickstart wizard."""
    print("🚀 PolicyShield Quickstart\n")

    # Step 1: Framework
    framework = ask_choice("What framework?", ["OpenClaw", "LangChain", "CrewAI", "Custom"])

    # Step 2: Tools
    if framework == "OpenClaw":
        tools = discover_openclaw_tools()
    else:
        tools = ask_list("List your tool names (comma-separated):")

    # Step 3: Mode
    mode = ask_choice("Default behavior for unknown tools?", ["block", "allow", "approve"])

    # Step 4: Approval channel
    approval = ask_choice("Approval channel?", ["CLI (stdin)", "Telegram bot", "REST API", "None"])

    # Generate
    rules_yaml = generate_rules(tools, mode)
    config_yaml = generate_config(approval)

    # Write & validate
    ...

    # Optionally start
    if ask_yn("Start server now?"):
        return _cmd_server(...)
```

### CLI entry: add `quickstart` subcommand in `cli/main.py`

## Tests

- Test with mocked input → correct rules generated
- Test tool discovery for OpenClaw
- Test generated rules pass validation

## Self-check

```bash
ruff check policyshield/cli/quickstart.py
pytest tests/test_quickstart.py -v
```

## Commit

```
feat(cli): add interactive quickstart wizard
```
