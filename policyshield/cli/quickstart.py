"""Interactive quickstart wizard for PolicyShield."""

from __future__ import annotations

import json
import sys
from pathlib import Path


def cmd_quickstart() -> int:
    """Run the interactive quickstart wizard.

    Guides users through framework selection, tool discovery,
    verdict mode, and generates config + rules.
    """
    print("🚀 PolicyShield Quickstart\n")

    # Step 1: Framework
    framework = _ask_choice(
        "What agent framework are you using?",
        ["OpenClaw", "LangChain", "CrewAI", "Custom"],
    )

    # Step 2: Tools
    if framework == "OpenClaw":
        tools = _discover_openclaw_tools()
        if not tools:
            tools = _ask_list("Could not auto-discover. Enter tool names (comma-separated):")
    else:
        tools = _ask_list("Enter your tool names (comma-separated):")

    if not tools:
        print("✗ No tools specified. Aborting.", file=sys.stderr)
        return 1

    # Step 3: Default mode
    mode = _ask_choice(
        "Default behavior for unknown tools?",
        ["block (recommended)", "allow", "approve"],
    ).split()[0]

    # Step 4: Preset
    preset = _ask_choice(
        "Agent role?",
        ["coding-agent", "data-analyst", "customer-support", "custom"],
    )

    # Generate rules
    rules = _generate_rules(tools, mode, preset)
    rules_path = Path("policies/rules.yaml")
    rules_path.parent.mkdir(parents=True, exist_ok=True)
    rules_path.write_text(rules, encoding="utf-8")
    print(f"\n✓ Rules written to {rules_path}")

    # Generate config
    config_path = Path("policyshield.yaml")
    if not config_path.exists():
        config = f"rules: {rules_path}\nmode: enforce\n"
        config_path.write_text(config, encoding="utf-8")
        print(f"✓ Config written to {config_path}")

    # Summary
    print("\n📋 Summary:")
    print(f"  Framework: {framework}")
    print(f"  Tools: {', '.join(tools)}")
    print(f"  Default: {mode}")
    print(f"  Preset: {preset}")
    print("\n▶ Next steps:")
    print(f"  policyshield validate {rules_path}")
    print(f"  policyshield server --rules {rules_path}")

    return 0


def _ask_choice(prompt: str, options: list[str]) -> str:
    """Ask user to pick from a list."""
    print(f"  {prompt}")
    for i, opt in enumerate(options, 1):
        print(f"    {i}) {opt}")
    while True:
        try:
            raw = input("  > ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            sys.exit(1)
        if raw.isdigit() and 1 <= int(raw) <= len(options):
            return options[int(raw) - 1]
        # Allow typing the option name
        for opt in options:
            if raw.lower() in opt.lower():
                return opt
        print(f"  Please enter 1-{len(options)}")


def _ask_list(prompt: str) -> list[str]:
    """Ask for comma-separated values."""
    print(f"  {prompt}")
    try:
        raw = input("  > ").strip()
    except (EOFError, KeyboardInterrupt):
        print()
        sys.exit(1)
    return [t.strip() for t in raw.split(",") if t.strip()]


def _discover_openclaw_tools() -> list[str]:
    """Try to discover tools from a running OpenClaw instance."""
    try:
        import urllib.request

        resp = urllib.request.urlopen("http://localhost:3000/api/tools", timeout=3)
        data = json.loads(resp.read())
        tools = [t.get("name", t.get("function", {}).get("name", "")) for t in data if isinstance(t, dict)]
        tools = [t for t in tools if t]
        if tools:
            print(f"  ✓ Discovered {len(tools)} tools from OpenClaw: {', '.join(tools[:5])}...")
        return tools
    except Exception:
        return []


def _generate_rules(tools: list[str], default_mode: str, preset: str) -> str:
    """Generate rules YAML from tool list and settings."""
    # Try to use a preset
    if preset != "custom":
        preset_path = Path(__file__).parent.parent / "presets" / f"{preset}.yaml"
        if preset_path.exists():
            return preset_path.read_text()

    # Custom rules
    lines = [
        "shield_name: quickstart-shield",
        "version: '1'",
        f"default_verdict: {default_mode.upper()}",
        "rules:",
    ]
    for tool in tools:
        lines.append(f"  - id: check-{tool.replace('_', '-')}")
        lines.append(f"    tool_name: {tool}")
        lines.append("    then: ALLOW")
        lines.append(f'    message: "{tool} allowed by quickstart"')
    return "\n".join(lines) + "\n"
