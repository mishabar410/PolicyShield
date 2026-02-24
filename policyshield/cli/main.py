"""PolicyShield CLI — command-line interface for rule validation and trace inspection."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from policyshield import __version__
from policyshield.core.exceptions import PolicyShieldParseError
from policyshield.core.parser import load_rules


def app(args: list[str] | None = None) -> int:
    """Main CLI entry point.

    Args:
        args: Command-line arguments (defaults to sys.argv).

    Returns:
        Exit code (0 = success, 1 = error).
    """
    parser = argparse.ArgumentParser(
        prog="policyshield",
        description="PolicyShield — Declarative firewall for AI agent tool calls",
    )
    parser.add_argument("--version", action="version", version=f"policyshield {__version__}")

    subparsers = parser.add_subparsers(dest="command")

    # openclaw subcommands (setup / teardown / status)
    from policyshield.cli.openclaw import add_openclaw_subcommands

    add_openclaw_subcommands(subparsers)

    # validate command
    validate_parser = subparsers.add_parser("validate", help="Validate rule files")
    validate_parser.add_argument("path", help="Path to YAML rule file or directory")

    # lint command
    lint_parser = subparsers.add_parser("lint", help="Lint rule files for potential issues")
    lint_parser.add_argument("path", help="Path to YAML rule file or directory")

    # test command
    test_parser = subparsers.add_parser("test", help="Run YAML-based rule tests")
    test_parser.add_argument("path", help="Path to test file or directory")
    test_parser.add_argument("-v", "--verbose", action="store_true", help="Show details for each test")
    test_parser.add_argument("--json", dest="json_output", action="store_true", help="JSON output")

    # diff command
    diff_parser = subparsers.add_parser("diff", help="Compare two rule sets")
    diff_parser.add_argument("old_path", help="Path to old rule file")
    diff_parser.add_argument("new_path", help="Path to new rule file")
    diff_parser.add_argument("--json", dest="json_output", action="store_true", help="JSON output")
    diff_parser.add_argument("--exit-code", action="store_true", help="Exit 1 if differences found")

    # trace command
    trace_parser = subparsers.add_parser("trace", help="Inspect trace logs")
    trace_subparsers = trace_parser.add_subparsers(dest="trace_command")

    # trace show
    show_parser = trace_subparsers.add_parser("show", help="Show trace entries")
    show_parser.add_argument("file", help="Path to JSONL trace file")
    show_parser.add_argument("-n", "--limit", type=int, default=50, help="Max entries to show")
    show_parser.add_argument("--verdict", help="Filter by verdict")
    show_parser.add_argument("--tool", help="Filter by tool name")
    show_parser.add_argument("--session", help="Filter by session ID")

    violations_parser = trace_subparsers.add_parser("violations", help="Show only violations (non-ALLOW)")
    violations_parser.add_argument("file", help="Path to JSONL trace file")
    violations_parser.add_argument("-n", "--limit", type=int, default=50, help="Max entries to show")

    # trace stats
    stats_parser = trace_subparsers.add_parser("stats", help="Show aggregated trace statistics")
    stats_parser.add_argument("file", nargs="?", default=None, help="Path to JSONL trace file (legacy mode)")
    stats_parser.add_argument("--dir", default=None, help="Trace directory for aggregation")
    stats_parser.add_argument("--from", dest="time_from", help="Start time (ISO datetime)")
    stats_parser.add_argument("--to", dest="time_to", help="End time (ISO datetime)")
    stats_parser.add_argument("--tool", help="Filter by tool name")
    stats_parser.add_argument("--session", help="Filter by session ID")
    stats_parser.add_argument("--top", type=int, default=10, help="Top N tools (default: 10)")
    stats_parser.add_argument("--format", choices=["text", "json"], default="text", help="Output format")

    # trace search
    search_parser = trace_subparsers.add_parser("search", help="Search traces with filters")
    search_parser.add_argument("--dir", default="./traces", help="Trace directory (default: ./traces)")
    search_parser.add_argument("--tool", help="Filter by tool name")
    search_parser.add_argument("--verdict", help="Filter by verdict (ALLOW, BLOCK, REDACT, APPROVE)")
    search_parser.add_argument("--session", help="Filter by session ID")
    search_parser.add_argument("--text", help="Full-text search in args, message, tool")
    search_parser.add_argument("--rule", help="Filter by rule ID")
    search_parser.add_argument("--pii", help="Filter by PII type")
    search_parser.add_argument("--from", dest="time_from", help="Start time (ISO datetime)")
    search_parser.add_argument("--to", dest="time_to", help="End time (ISO datetime)")
    search_parser.add_argument("--limit", type=int, default=50, help="Max results (default: 50)")
    search_parser.add_argument("--format", choices=["table", "json"], default="table", help="Output format")

    # trace cost
    cost_parser = trace_subparsers.add_parser("cost", help="Estimate token/dollar cost of tool calls")
    cost_parser.add_argument("--dir", default="./traces", help="Trace directory (default: ./traces)")
    cost_parser.add_argument("--model", default="gpt-4o", help="Model for pricing (default: gpt-4o)")
    cost_parser.add_argument("--from", dest="time_from", help="Start time (ISO datetime)")
    cost_parser.add_argument("--to", dest="time_to", help="End time (ISO datetime)")
    cost_parser.add_argument("--format", choices=["table", "json"], default="table", help="Output format")

    # trace export
    export_parser = trace_subparsers.add_parser("export", help="Export trace to CSV or HTML")
    export_parser.add_argument("file", help="Path to JSONL trace file")
    export_parser.add_argument("--format", choices=["csv", "html"], default="csv", help="Export format")
    export_parser.add_argument("--output", help="Output file path")
    export_parser.add_argument("--title", default="PolicyShield Trace Report", help="HTML report title")

    # trace dashboard
    dash_parser = trace_subparsers.add_parser("dashboard", help="Launch live web dashboard")
    dash_parser.add_argument("--dir", default="./traces", help="Trace directory (default: ./traces)")
    dash_parser.add_argument("--host", default="127.0.0.1", help="Host to bind (default: 127.0.0.1)")
    dash_parser.add_argument("--port", type=int, default=8000, help="Port to bind (default: 8000)")
    dash_parser.add_argument("--prometheus", action="store_true", help="Enable /metrics endpoint")

    # init command
    init_parser = subparsers.add_parser("init", help="Scaffold a new PolicyShield project")
    init_parser.add_argument("directory", nargs="?", default=".", help="Target directory (default: current directory)")
    init_parser.add_argument(
        "--preset",
        default="minimal",
        choices=["minimal", "security", "compliance", "openclaw"],
        help="Rule preset (default: minimal)",
    )
    init_parser.add_argument("--no-interactive", action="store_true", help="Skip interactive prompts")

    # config command
    config_parser = subparsers.add_parser("config", help="Manage policyshield config")
    config_subparsers = config_parser.add_subparsers(dest="config_command")
    val_parser = config_subparsers.add_parser("validate", help="Validate config file")
    val_parser.add_argument("path", nargs="?", default="policyshield.yaml", help="Config file path")
    show_parser2 = config_subparsers.add_parser("show", help="Show resolved config")
    show_parser2.add_argument("path", nargs="?", default=None, help="Config file path")
    config_subparsers.add_parser("init", help="Create default policyshield.yaml")

    # playground command
    play_parser = subparsers.add_parser("playground", help="Interactive rule testing REPL")
    play_parser.add_argument("--rules", required=True, help="Path to YAML rules file")
    play_parser.add_argument("--tool", default=None, help="Single check: tool name (non-interactive)")
    play_parser.add_argument("--args", default=None, help="Single check: JSON args string")

    # server command
    server_parser = subparsers.add_parser("server", help="Start PolicyShield HTTP server")
    server_parser.add_argument("--rules", required=True, help="Path to YAML rules file or directory")
    server_parser.add_argument("--port", type=int, default=8100, help="Server port (default: 8100)")
    server_parser.add_argument("--host", default="0.0.0.0", help="Server host (default: 0.0.0.0)")
    server_parser.add_argument(
        "--mode",
        choices=["enforce", "audit", "disabled"],
        default="enforce",
    )
    server_parser.add_argument("--reload", action="store_true", help="Enable hot reload of rules")
    server_parser.add_argument("--workers", type=int, default=1, help="Number of uvicorn workers")
    server_parser.add_argument("--tls-cert", help="Path to TLS certificate (PEM)")
    server_parser.add_argument("--tls-key", help="Path to TLS private key (PEM)")

    # replay command
    sp_replay = subparsers.add_parser("replay", help="Replay traces against different rules")
    sp_replay.add_argument("traces", help="Path to JSONL trace file or directory")
    sp_replay.add_argument("--rules", required=True, help="Path to new rules YAML")
    sp_replay.add_argument("--session", default=None, help="Filter by session ID")
    sp_replay.add_argument("--tool", default=None, help="Filter by tool name")
    sp_replay.add_argument("--only-changed", action="store_true", help="Show only changed verdicts")
    sp_replay.add_argument("--format", choices=["table", "json"], default="table", help="Output format")

    # generate command
    sp_gen = subparsers.add_parser("generate", help="Generate rules from description")
    sp_gen.add_argument("description", nargs="?", help="Natural language description of rules")
    sp_gen.add_argument("--tools", nargs="+", help="List of tool names for context")
    sp_gen.add_argument("--output", "-o", default=None, help="Output YAML file (default: stdout)")
    sp_gen.add_argument(
        "--provider",
        choices=["openai", "anthropic"],
        default="openai",
        help="LLM provider",
    )
    sp_gen.add_argument("--model", default=None, help="Specific LLM model")
    sp_gen.add_argument(
        "--template",
        action="store_true",
        help="Use offline template mode (no LLM). Requires --tools",
    )
    sp_gen.add_argument(
        "--interactive",
        "-i",
        action="store_true",
        help="Interactive mode: ask follow-up questions",
    )

    # kill command
    kill_parser = subparsers.add_parser("kill", help="Activate kill switch on running server")
    kill_parser.add_argument("--port", type=int, default=8100, help="Server port (default: 8100)")
    kill_parser.add_argument("--reason", type=str, default="Kill switch activated via CLI")

    # resume command
    resume_parser = subparsers.add_parser("resume", help="Deactivate kill switch on running server")
    resume_parser.add_argument("--port", type=int, default=8100, help="Server port (default: 8100)")

    # doctor command
    doctor_parser = subparsers.add_parser("doctor", help="Check configuration health and security score")
    doctor_parser.add_argument("--config", type=str, default=None, help="Path to policyshield.yaml")
    doctor_parser.add_argument("--rules", type=str, default=None, help="Path to rules.yaml")
    doctor_parser.add_argument("--json", action="store_true", help="Output as JSON")

    # generate-rules command
    genrules_parser = subparsers.add_parser(
        "generate-rules",
        help="Auto-generate rules from tool list or OpenClaw",
    )
    genrules_parser.add_argument(
        "--from-openclaw",
        action="store_true",
        help="Fetch tools from running OpenClaw instance",
    )
    genrules_parser.add_argument(
        "--url",
        type=str,
        default="http://localhost:3000",
        help="OpenClaw URL (default: http://localhost:3000)",
    )
    genrules_parser.add_argument(
        "--tools",
        type=str,
        default=None,
        help="Comma-separated tool names (alternative to --from-openclaw)",
    )
    genrules_parser.add_argument(
        "--output",
        "-o",
        type=str,
        default="policies/rules.yaml",
        help="Output file path",
    )
    genrules_parser.add_argument(
        "--include-safe",
        action="store_true",
        help="Include explicit ALLOW rules for safe tools",
    )
    genrules_parser.add_argument(
        "--default-verdict",
        type=str,
        default="block",
        help="Default verdict for unmatched tools (default: block)",
    )
    genrules_parser.add_argument(
        "--force",
        action="store_true",
        help="Overwrite output file without asking",
    )

    # simulate command
    sim_parser = subparsers.add_parser("simulate", help="What-if rule simulation")
    sim_parser.add_argument("--rules", required=True, help="Base ruleset path")
    sim_parser.add_argument("--new-rule", required=True, help="New rule YAML to test")
    sim_parser.add_argument("--tool", required=True, help="Tool name to simulate")
    sim_parser.add_argument("--args", default="{}", help="JSON args string")
    sim_parser.add_argument("--session-id", default="simulate", help="Session ID")

    # openapi command
    openapi_parser = subparsers.add_parser("openapi", help="Export OpenAPI schema as JSON")
    openapi_parser.add_argument("--rules", required=True, help="Path to YAML rules file")
    openapi_parser.add_argument("--output", "-o", default=None, help="Output file (default: stdout)")
    openapi_parser.add_argument("--indent", type=int, default=2, help="JSON indent (default: 2)")

    # check (dry-run) command
    check_parser = subparsers.add_parser("check", help="One-shot tool call check (dry-run)")
    check_parser.add_argument("--tool", required=True, help="Tool name to check")
    check_parser.add_argument("--args", default="{}", help="JSON args string")
    check_parser.add_argument("--rules", required=True, help="Path to YAML rules file")
    check_parser.add_argument("--session-id", default="cli", help="Session ID")
    check_parser.add_argument("--json", dest="json_output", action="store_true", help="JSON output")

    parsed = parser.parse_args(args)

    if parsed.command == "validate":
        return _cmd_validate(parsed.path)
    elif parsed.command == "lint":
        return _cmd_lint(parsed.path)
    elif parsed.command == "test":
        return _cmd_test(parsed)
    elif parsed.command == "diff":
        return _cmd_diff(parsed)
    elif parsed.command == "trace":
        if parsed.trace_command == "show":
            return _cmd_trace_show(parsed)
        elif parsed.trace_command == "violations":
            return _cmd_trace_violations(parsed)
        elif parsed.trace_command == "stats":
            return _cmd_trace_stats(parsed)
        elif parsed.trace_command == "search":
            return _cmd_trace_search(parsed)
        elif parsed.trace_command == "export":
            return _cmd_trace_export(parsed)
        elif parsed.trace_command == "cost":
            return _cmd_trace_cost(parsed)
        elif parsed.trace_command == "dashboard":
            return _cmd_trace_dashboard(parsed)
        else:
            trace_parser.print_help()
            return 1
    elif parsed.command == "init":
        return _cmd_init(parsed)
    elif parsed.command == "config":
        if parsed.config_command == "validate":
            return _cmd_config_validate(parsed)
        elif parsed.config_command == "show":
            return _cmd_config_show(parsed)
        elif parsed.config_command == "init":
            return _cmd_config_init()
        else:
            config_parser.print_help()
            return 1
    elif parsed.command == "playground":
        from policyshield.cli.playground import cmd_playground, run_single_check

        if parsed.tool:
            return run_single_check(parsed.rules, parsed.tool, parsed.args)
        return cmd_playground(parsed.rules)
    elif parsed.command == "server":
        return _cmd_server(parsed)
    elif parsed.command == "replay":
        return _cmd_replay(parsed)
    elif parsed.command == "generate":
        return _cmd_generate(parsed)
    elif parsed.command == "kill":
        return _cmd_kill(parsed)
    elif parsed.command == "resume":
        return _cmd_resume(parsed)
    elif parsed.command == "doctor":
        return _cmd_doctor(parsed)
    elif parsed.command == "generate-rules":
        return _cmd_generate_rules(parsed)
    elif parsed.command == "simulate":
        return _cmd_simulate(parsed)
    elif parsed.command == "openapi":
        return _cmd_openapi(parsed)
    elif parsed.command == "check":
        return _cmd_check(parsed)
    elif parsed.command == "openclaw":
        from policyshield.cli.openclaw import cmd_openclaw

        return cmd_openclaw(parsed)
    else:
        parser.print_help()
        return 1


def _cmd_init(parsed: argparse.Namespace) -> int:
    """Scaffold a new PolicyShield project."""
    from policyshield.cli.init_scaffold import scaffold

    directory = parsed.directory
    preset = parsed.preset
    interactive = not parsed.no_interactive

    try:
        scaffold(
            directory=directory,
            preset=preset,
            interactive=interactive,
        )
        return 0
    except Exception as e:
        print(f"✗ Error: {e}", file=sys.stderr)
        return 1


def _cmd_server(parsed: argparse.Namespace) -> int:
    """Start the PolicyShield HTTP server."""
    try:
        import uvicorn
    except ImportError:
        print(
            "ERROR: uvicorn not installed. Run: pip install policyshield[server]",
            file=sys.stderr,
        )
        return 1

    import os

    from policyshield.core.models import ShieldMode
    from policyshield.server.app import create_app
    from policyshield.shield.async_engine import AsyncShieldEngine

    mode_map = {
        "enforce": ShieldMode.ENFORCE,
        "audit": ShieldMode.AUDIT,
        "disabled": ShieldMode.DISABLED,
    }
    mode = mode_map[parsed.mode]

    rules_path = Path(parsed.rules)
    if not rules_path.exists():
        print(f"ERROR: rules not found: {rules_path}", file=sys.stderr)
        return 1

    # Use Telegram backend if env vars are set, otherwise InMemory
    tg_token = os.environ.get("POLICYSHIELD_TELEGRAM_TOKEN")
    tg_chat = os.environ.get("POLICYSHIELD_TELEGRAM_CHAT_ID")
    approval_backend: Any
    if tg_token and tg_chat:
        from policyshield.approval.telegram import TelegramApprovalBackend

        approval_backend = TelegramApprovalBackend(bot_token=tg_token, chat_id=tg_chat)
        print(f"  Approval: Telegram (chat_id={tg_chat})")
    else:
        from policyshield.approval.memory import InMemoryBackend

        approval_backend = InMemoryBackend()
        print("  Approval: InMemory (use REST API to respond)")

    # Built-in security detectors — always enabled
    from policyshield.shield.sanitizer import InputSanitizer, SanitizerConfig

    sanitizer = InputSanitizer(
        SanitizerConfig(
            builtin_detectors=[
                "path_traversal",
                "shell_injection",
                "sql_injection",
                "ssrf",
                "url_schemes",
            ]
        )
    )

    # Audit trail — trace recorder
    from policyshield.trace.recorder import TraceRecorder

    trace_dir = os.environ.get("POLICYSHIELD_TRACE_DIR", "./traces")
    trace_recorder = TraceRecorder(trace_dir)

    engine = AsyncShieldEngine(
        rules=rules_path,
        mode=mode,
        approval_backend=approval_backend,
        sanitizer=sanitizer,
        trace_recorder=trace_recorder,
    )
    print("PolicyShield server starting...")
    print(f"  Rules: {rules_path} ({engine.rule_count} rules)")
    print(f"  Mode: {mode.value}")
    print(f"  Traces: {trace_dir}")
    print(f"  Listen: http://{parsed.host}:{parsed.port}")
    print(f"  Health: http://{parsed.host}:{parsed.port}/api/v1/health")

    if parsed.reload:
        print("  Hot reload: enabled")

    # TLS support — env var fallback
    tls_cert = getattr(parsed, "tls_cert", None) or os.environ.get("POLICYSHIELD_TLS_CERT")
    tls_key = getattr(parsed, "tls_key", None) or os.environ.get("POLICYSHIELD_TLS_KEY")

    uvicorn_kwargs: dict = {
        "host": parsed.host,
        "port": parsed.port,
        "workers": parsed.workers,
    }

    if tls_cert and tls_key:
        cert_path = Path(tls_cert)
        key_path = Path(tls_key)
        if not cert_path.exists():
            print(f"❌ TLS cert not found: {cert_path}", file=sys.stderr)
            return 1
        if not key_path.exists():
            print(f"❌ TLS key not found: {key_path}", file=sys.stderr)
            return 1
        uvicorn_kwargs["ssl_certfile"] = str(cert_path)
        uvicorn_kwargs["ssl_keyfile"] = str(key_path)
        print(f"  🔒 TLS enabled: cert={cert_path}")
    elif tls_cert or tls_key:
        print("❌ Both --tls-cert and --tls-key required", file=sys.stderr)
        return 1

    app = create_app(engine, enable_watcher=parsed.reload)
    uvicorn.run(app, **uvicorn_kwargs)
    return 0


def _cmd_validate(path: str) -> int:
    """Validate YAML rule files."""
    try:
        ruleset = load_rules(path)
        enabled = ruleset.enabled_rules()
        print(f"✓ Valid: {ruleset.shield_name} v{ruleset.version}")
        print(f"  Rules: {len(ruleset.rules)} total, {len(enabled)} enabled")

        for rule in ruleset.rules:
            status = "✓" if rule.enabled else "○"
            print(f"  {status} {rule.id} → {rule.then.value} [{rule.severity.value}]")

        return 0
    except PolicyShieldParseError as e:
        print(f"✗ Error: {e}", file=sys.stderr)
        return 1


def _cmd_lint(path: str) -> int:
    """Lint YAML rule files for potential issues."""
    from policyshield.lint import RuleLinter

    try:
        ruleset = load_rules(path)
    except PolicyShieldParseError as e:
        print(f"✗ Error loading rules: {e}", file=sys.stderr)
        return 1

    linter = RuleLinter()
    warnings = linter.lint(ruleset)

    if not warnings:
        print("✓ No issues found")
        return 0

    errors = 0
    warning_count = 0
    info_count = 0

    for w in warnings:
        if w.level == "ERROR":
            icon = "✗"
            errors += 1
        elif w.level == "WARNING":
            icon = "⚠"
            warning_count += 1
        else:
            icon = "ℹ"
            info_count += 1
        print(f"{icon} {w.level} [{w.rule_id}] {w.check}: {w.message}")

    parts = []
    if errors:
        parts.append(f"{errors} error{'s' if errors != 1 else ''}")
    if warning_count:
        parts.append(f"{warning_count} warning{'s' if warning_count != 1 else ''}")
    if info_count:
        parts.append(f"{info_count} info")
    print(f"\n{', '.join(parts)}")

    return 1 if errors > 0 else 0


def _cmd_test(parsed: argparse.Namespace) -> int:
    """Run YAML-based rule tests."""
    from policyshield.testing.runner import TestRunner

    runner = TestRunner()
    target = Path(parsed.path)
    verbose = parsed.verbose
    json_output = getattr(parsed, "json_output", False)

    try:
        if target.is_dir():
            suites = runner.run_directory(target)
        else:
            suites = [runner.run_file(target)]
    except (FileNotFoundError, ValueError) as e:
        print(f"✗ {e}", file=sys.stderr)
        return 1

    if json_output:
        out = []
        for s in suites:
            suite_data = {
                "suite": s.name,
                "total": s.total,
                "passed": s.passed,
                "failed": s.failed,
                "results": [
                    {
                        "name": r.test_case.name,
                        "passed": r.passed,
                        "actual_verdict": r.actual_verdict.value,
                        "failure_reason": r.failure_reason,
                    }
                    for r in s.results
                ],
            }
            out.append(suite_data)
        print(json.dumps(out, indent=2))
        has_failures = any(s.failed > 0 for s in suites)
        return 1 if has_failures else 0

    # Text output
    has_failures = False
    for suite in suites:
        print(f"\n🧪 Test Suite: {suite.name}")
        for r in suite.results:
            if r.passed:
                print(f"  ✓ {r.test_case.name}")
            else:
                has_failures = True
                print(f"  ✗ {r.test_case.name}")
                if verbose and r.failure_reason:
                    print(f"    {r.failure_reason}")
        print(f"\n{suite.passed}/{suite.total} passed, {suite.failed} failed")

    return 1 if has_failures else 0


def _cmd_diff(parsed: argparse.Namespace) -> int:
    """Compare two rule sets and show differences."""
    import json as _json

    from policyshield.core.parser import load_rules
    from policyshield.lint.differ import PolicyDiffer

    try:
        old_rules = load_rules(parsed.old_path)
        new_rules = load_rules(parsed.new_path)
    except Exception as e:
        print(f"✗ {e}", file=sys.stderr)
        return 1

    d = PolicyDiffer.diff(old_rules, new_rules)
    json_output = getattr(parsed, "json_output", False)
    exit_code_flag = getattr(parsed, "exit_code", False)

    if json_output:
        print(_json.dumps(PolicyDiffer.diff_to_dict(d), indent=2, default=str))
    else:
        print(f"📋 Policy Diff: {parsed.old_path} → {parsed.new_path}\n")
        print(PolicyDiffer.format_diff(d))

    if exit_code_flag and d.has_changes:
        return 1
    return 0


def _cmd_trace_show(parsed: argparse.Namespace) -> int:
    """Show trace entries with optional filtering."""
    return _display_trace(
        file_path=parsed.file,
        limit=parsed.limit,
        verdict_filter=parsed.verdict,
        tool_filter=parsed.tool,
        session_filter=parsed.session,
    )


def _cmd_trace_violations(parsed: argparse.Namespace) -> int:
    """Show only violations (non-ALLOW verdicts)."""
    return _display_trace(
        file_path=parsed.file,
        limit=parsed.limit,
        exclude_allow=True,
    )


def _cmd_trace_stats(parsed: argparse.Namespace) -> int:
    """Show aggregated trace statistics."""
    from datetime import datetime as _dt

    # New dir-based aggregation mode
    if parsed.dir:
        from policyshield.trace.aggregator import (
            TimeWindow,
            TraceAggregator,
            format_aggregation,
        )

        trace_dir = Path(parsed.dir)
        if not trace_dir.exists():
            print(f"\u2717 Trace directory not found: {parsed.dir}", file=sys.stderr)
            return 1

        tw = None
        if parsed.time_from or parsed.time_to:
            start = _dt.fromisoformat(parsed.time_from) if parsed.time_from else _dt.min
            end = _dt.fromisoformat(parsed.time_to) if parsed.time_to else _dt.max
            tw = TimeWindow(start=start, end=end)

        aggregator = TraceAggregator(trace_dir)
        result = aggregator.aggregate(
            time_window=tw,
            session_id=parsed.session,
            tool=parsed.tool,
        )

        if parsed.format == "json":
            print(json.dumps(result.to_dict(), indent=2, default=str))
        else:
            print(format_aggregation(result, top_n=parsed.top))

        return 0

    # Legacy file-based mode
    if not parsed.file:
        print("\u2717 Provide either --dir or a trace file path.", file=sys.stderr)
        return 1

    from policyshield.trace.analyzer import TraceAnalyzer, format_stats

    trace_path = Path(parsed.file)
    if not trace_path.exists():
        print(f"\u2717 Trace file not found: {parsed.file}", file=sys.stderr)
        return 1

    stats = TraceAnalyzer.from_file(trace_path)

    if parsed.format == "json":
        print(json.dumps(stats.to_dict(), indent=2))
    else:
        print(format_stats(stats))

    return 0


def _cmd_trace_search(parsed: argparse.Namespace) -> int:
    """Search traces with filters."""
    from datetime import datetime as _dt

    from policyshield.trace.search import SearchQuery, TraceSearchEngine

    trace_dir = Path(parsed.dir)
    if not trace_dir.exists():
        print(f"✗ Trace directory not found: {parsed.dir}", file=sys.stderr)
        return 1

    query = SearchQuery(
        tool=parsed.tool,
        verdict=parsed.verdict,
        session_id=parsed.session,
        text=parsed.text,
        rule_id=parsed.rule,
        pii_type=parsed.pii,
        time_from=_dt.fromisoformat(parsed.time_from) if parsed.time_from else None,
        time_to=_dt.fromisoformat(parsed.time_to) if parsed.time_to else None,
        limit=parsed.limit,
    )

    engine = TraceSearchEngine(trace_dir)
    result = engine.search(query)

    if parsed.format == "json":
        output = {
            "total": result.total,
            "records": result.records,
        }
        print(json.dumps(output, indent=2, default=str))
    else:
        if not result.records:
            print(f"No results found (total: {result.total})")
            return 0
        for rec in result.records:
            verdict = rec.get("verdict", "?")
            tool = rec.get("tool", "?")
            ts = rec.get("timestamp", "?")
            session = rec.get("session_id", "?")
            icon = "✓" if verdict == "ALLOW" else "✗"
            print(f"{icon} [{verdict}] {tool} | session={session} | {ts}")
        print(f"\n({len(result.records)} of {result.total} shown)")

    return 0


def _cmd_trace_cost(parsed: argparse.Namespace) -> int:
    """Estimate token/dollar cost of tool calls."""
    from datetime import datetime as _dt

    from policyshield.trace.cost import CostEstimator, format_cost_estimate

    trace_dir = Path(parsed.dir)
    if not trace_dir.exists():
        print(f"\u2717 Trace directory not found: {parsed.dir}", file=sys.stderr)
        return 1

    filters: dict = {}
    if parsed.time_from or parsed.time_to:
        from policyshield.trace.aggregator import TimeWindow

        start = _dt.fromisoformat(parsed.time_from) if parsed.time_from else _dt.min
        end = _dt.fromisoformat(parsed.time_to) if parsed.time_to else _dt.max
        filters["time_window"] = TimeWindow(start=start, end=end)

    estimator = CostEstimator(model=parsed.model)
    estimate = estimator.estimate_from_traces(trace_dir, **filters)

    if parsed.format == "json":
        print(json.dumps(estimate.to_dict(), indent=2, default=str))
    else:
        print(format_cost_estimate(estimate))

    return 0


def _cmd_trace_export(parsed: argparse.Namespace) -> int:
    """Export trace to CSV or HTML."""
    from datetime import datetime as _dt

    from policyshield.trace.exporter import TraceExporter

    trace_path = Path(parsed.file)
    if not trace_path.exists():
        print(f"✗ Trace file not found: {parsed.file}", file=sys.stderr)
        return 1

    fmt = parsed.format
    output = getattr(parsed, "output", None)
    if not output:
        stamp = _dt.now().strftime("%Y%m%d")
        output = f"trace_export_{stamp}.{fmt}"

    if fmt == "csv":
        count = TraceExporter.to_csv(trace_path, output)
    else:
        title = getattr(parsed, "title", "PolicyShield Trace Report")
        count = TraceExporter.to_html(trace_path, output, title=title)

    print(f"✓ Exported {count} records to {output}")
    return 0


def _cmd_trace_dashboard(parsed: argparse.Namespace) -> int:
    """Launch the live web dashboard."""
    from policyshield.dashboard import create_dashboard_app

    trace_dir_path = Path(parsed.dir)
    host = parsed.host
    port = parsed.port

    app = create_dashboard_app(trace_dir_path)

    if getattr(parsed, "prometheus", False):
        from policyshield.dashboard.prometheus import add_prometheus_endpoint

        add_prometheus_endpoint(app, trace_dir_path)

    print(f"🛡️  PolicyShield Dashboard → http://{host}:{port}")
    print(f"   Trace dir: {trace_dir_path}")
    if getattr(parsed, "prometheus", False):
        print(f"   Prometheus: http://{host}:{port}/metrics")

    try:
        import uvicorn

        uvicorn.run(app, host=host, port=port, log_level="info")
    except ImportError:
        print("⚠  uvicorn not found. Install with: pip install policyshield[dashboard]", file=sys.stderr)
        print("   Starting with built-in server...", file=sys.stderr)
        # Fallback: just print a message, can't serve without uvicorn
        return 1

    return 0


def _cmd_config_validate(parsed: argparse.Namespace) -> int:
    """Validate a policyshield config file."""
    from policyshield.config.loader import validate_config_file

    errors = validate_config_file(parsed.path)
    if errors:
        print(f"✗ Config errors in {parsed.path}:", file=sys.stderr)
        for e in errors:
            print(f"  - {e}", file=sys.stderr)
        return 1
    print(f"✓ Config valid: {parsed.path}")
    return 0


def _cmd_config_show(parsed: argparse.Namespace) -> int:
    """Show resolved config."""
    from policyshield.config.loader import load_config, render_config

    try:
        cfg = load_config(path=getattr(parsed, "path", None))
    except (FileNotFoundError, ValueError) as e:
        print(f"✗ {e}", file=sys.stderr)
        return 1
    print(render_config(cfg))
    return 0


def _cmd_config_init() -> int:
    """Create default policyshield.yaml."""
    from policyshield.config.loader import generate_default_config

    target = Path("policyshield.yaml")
    if target.exists():
        print(f"✗ {target} already exists", file=sys.stderr)
        return 1
    target.write_text(generate_default_config(), encoding="utf-8")
    print(f"✓ Created {target}")
    return 0


def _cmd_replay(parsed: argparse.Namespace) -> int:
    """Replay historical traces against new rules."""
    from policyshield.replay.loader import TraceLoader
    from policyshield.replay.engine import ReplayEngine, ChangeType

    # Load traces
    try:
        loader = TraceLoader.from_path(parsed.traces)
    except (FileNotFoundError, ValueError) as e:
        print(f"✗ {e}", file=sys.stderr)
        return 1

    entries = loader.load(session_id=parsed.session, tool=parsed.tool)

    if not entries:
        print("No trace entries found.")
        return 1

    # Replay
    engine = ReplayEngine.from_file(parsed.rules)
    results = engine.replay_all(entries)
    summary = engine.summary(results)

    if parsed.only_changed:
        results = [r for r in results if r.changed]

    if parsed.format == "json":
        output = {
            "summary": summary,
            "results": [
                {
                    "tool": r.entry.tool,
                    "session_id": r.entry.session_id,
                    "old_verdict": r.old_verdict,
                    "new_verdict": r.new_verdict,
                    "change": r.change_type.value,
                    "rule_id": r.new_rule_id,
                }
                for r in results
            ],
        }
        print(json.dumps(output, indent=2))
        return 0

    # Table format
    _CHANGE_SYMBOLS = {
        ChangeType.UNCHANGED: "  ",
        ChangeType.RELAXED: "↓ ",
        ChangeType.TIGHTENED: "↑ ",
        ChangeType.MODIFIED: "~ ",
    }
    _CHANGE_COLORS = {
        ChangeType.UNCHANGED: "",
        ChangeType.RELAXED: "\033[32m",  # green
        ChangeType.TIGHTENED: "\033[31m",  # red
        ChangeType.MODIFIED: "\033[33m",  # yellow
    }
    RESET = "\033[0m"

    print(f"\n{'Tool':<30} {'Old':<10} {'New':<10} {'Change':<12} {'Rule'}")
    print("─" * 80)

    for r in results:
        symbol = _CHANGE_SYMBOLS[r.change_type]
        color = _CHANGE_COLORS[r.change_type]
        rule = r.new_rule_id or "(default)"
        print(
            f"{color}{r.entry.tool:<30} {r.old_verdict:<10} {r.new_verdict:<10} {symbol}{r.change_type.value:<10} {rule}{RESET}"
        )

    print("─" * 80)
    print(
        f"\nTotal: {summary['total']}  |  "
        f"Unchanged: {summary['unchanged']}  |  "
        f"\033[31m↑ Tightened: {summary['tightened']}\033[0m  |  "
        f"\033[32m↓ Relaxed: {summary['relaxed']}\033[0m"
    )

    if summary["tightened"] > 0:
        print(f"\n⚠️  {summary['tightened']} tool call(s) would be MORE restricted with new rules.")

    return 0


def _cmd_simulate(parsed: argparse.Namespace) -> int:
    """Simulate a tool call with and without a new rule."""
    import json as _json

    from policyshield.core.models import RuleSet
    from policyshield.shield.engine import ShieldEngine

    try:
        args = _json.loads(parsed.args)
    except _json.JSONDecodeError as e:
        print(f"❌ Invalid JSON args: {e}", file=sys.stderr)
        return 1

    # Check with CURRENT rules
    try:
        current_rules = load_rules(parsed.rules)
    except PolicyShieldParseError as e:
        print(f"❌ Cannot load rules: {e}", file=sys.stderr)
        return 1

    engine_current = ShieldEngine(rules=current_rules)
    result_current = engine_current.check(tool_name=parsed.tool, args=args, session_id=parsed.session_id)

    # Check with NEW rule added
    try:
        new_rules = load_rules(parsed.new_rule)
    except PolicyShieldParseError as e:
        print(f"❌ Cannot load new rule: {e}", file=sys.stderr)
        return 1

    # Merge: base rules + new rule
    merged = RuleSet(
        rules=list(current_rules.rules) + list(new_rules.rules),
        shield_name=current_rules.shield_name,
        version=current_rules.version,
        default_verdict=current_rules.default_verdict,
        honeypots=current_rules.honeypots,
        taint_chain=current_rules.taint_chain,
    )
    engine_merged = ShieldEngine(rules=merged)
    result_merged = engine_merged.check(tool_name=parsed.tool, args=args, session_id=parsed.session_id)

    # Display
    print(f"Tool:    {parsed.tool}")
    print(f"Args:    {args}")
    print()
    print(f"📋 Current rules ({len(current_rules.rules)} rules):")
    print(f"   Verdict: {result_current.verdict.value} (rule: {result_current.rule_id or 'none'})")
    print()
    print(f"📋 With new rule  ({len(merged.rules)} rules):")
    print(f"   Verdict: {result_merged.verdict.value} (rule: {result_merged.rule_id or 'none'})")
    if result_merged.message:
        print(f"   Message: {result_merged.message}")

    # Diff highlight
    if result_current.verdict != result_merged.verdict:
        print()
        print(f"⚠️  CHANGE: {result_current.verdict.value} → {result_merged.verdict.value}")
    else:
        print()
        print("✅ No change in verdict")

    return 0


def _display_trace(
    file_path: str,
    limit: int = 50,
    verdict_filter: str | None = None,
    tool_filter: str | None = None,
    session_filter: str | None = None,
    exclude_allow: bool = False,
) -> int:
    """Display trace entries from a JSONL file."""
    trace_path = Path(file_path)
    if not trace_path.exists():
        print(f"✗ Trace file not found: {file_path}", file=sys.stderr)
        return 1

    try:
        entries = []
        with open(trace_path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                entry = json.loads(line)

                # Apply filters
                if verdict_filter and entry.get("verdict", "").upper() != verdict_filter.upper():
                    continue
                if tool_filter and entry.get("tool") != tool_filter:
                    continue
                if session_filter and entry.get("session_id") != session_filter:
                    continue
                if exclude_allow and entry.get("verdict", "").upper() == "ALLOW":
                    continue

                entries.append(entry)
                if len(entries) >= limit:
                    break

        if not entries:
            print("No matching trace entries found.")
            return 0

        # Display entries
        for entry in entries:
            verdict = entry.get("verdict", "?")
            tool = entry.get("tool", "?")
            session = entry.get("session_id", "?")
            timestamp = entry.get("timestamp", "?")
            rule_id = entry.get("rule_id", "-")
            latency = entry.get("latency_ms", 0)

            icon = "✓" if verdict == "ALLOW" else "✗"
            print(f"{icon} [{verdict}] {tool} | session={session} | rule={rule_id} | {latency:.1f}ms | {timestamp}")

            if "pii_types" in entry and entry["pii_types"]:
                print(f"  PII: {', '.join(entry['pii_types'])}")

        print(f"\n({len(entries)} entries shown)")
        return 0
    except (json.JSONDecodeError, OSError) as e:
        print(f"✗ Error reading trace file: {e}", file=sys.stderr)
        return 1


# ─── generate command ────────────────────────────────────────────────


def _cmd_generate(args: argparse.Namespace) -> int:
    """Generate PolicyShield rules."""
    import asyncio

    # Template mode (offline, no LLM)
    if args.template:
        return _generate_template(args)

    # AI mode (requires LLM)
    if not args.description:
        print("Error: description is required for AI generation.")
        print("Usage: policyshield generate 'Block all file deletions' --tools delete_file read_file")
        return 1

    return asyncio.run(_generate_ai(args))


def _generate_template(args: argparse.Namespace) -> int:
    """Generate rules from templates (offline mode)."""
    from policyshield.ai.templates import recommend_rules

    if not args.tools:
        print("Error: --tools is required for template mode.")
        print("Usage: policyshield generate --template --tools delete_file send_email -o rules.yaml")
        return 1

    recs = recommend_rules(args.tools)
    if not recs:
        print("No rule recommendations for the given tools (all classified as safe).")
        return 0

    # Build YAML
    lines = ['version: "1"', "default_verdict: allow", "", "rules:"]
    for rec in recs:
        lines.append(f"  # {rec.tool_name} ({rec.danger_level.value})")
        for yaml_line in rec.yaml_snippet.split("\n"):
            lines.append(yaml_line)
        lines.append("")

    yaml_text = "\n".join(lines)

    return _output_yaml(yaml_text, args.output, recs=recs)


async def _generate_ai(args: argparse.Namespace) -> int:
    """Generate rules using LLM."""
    from policyshield.ai.generator import generate_rules

    print(f"🧠 Generating rules with {args.provider}...")
    if args.tools:
        print(f"   Tools: {', '.join(args.tools)}")

    try:
        result = await generate_rules(
            args.description,
            tool_names=args.tools,
            provider=args.provider,
            model=args.model,
        )
    except RuntimeError as e:
        print(f"Error: {e}")
        return 1

    if not result.validation_ok:
        print(f"⚠️  Generated YAML has validation errors: {result.validation_error}")
        print("─" * 60)
        print(result.yaml_text)
        print("─" * 60)
        print("\nYou can save this YAML and fix it manually with: policyshield lint <file>")

        if args.output:
            _write_file(args.output, result.yaml_text)
            print(f"\nSaved (with warnings) to: {args.output}")
        return 1

    return _output_yaml(result.yaml_text, args.output, model=result.model)


def _output_yaml(yaml_text: str, output_path: str | None, **info: object) -> int:
    """Output YAML to file or stdout."""
    if output_path:
        _write_file(str(output_path), yaml_text)
        print(f"✅ Rules saved to: {output_path}")
        if info.get("model"):
            print(f"   Model: {info['model']}")
        if info.get("recs"):
            recs = info["recs"]
            print(f"   Generated {len(recs)} rule(s) from templates")  # type: ignore[arg-type]
    else:
        print(yaml_text)

    # Validate output
    from policyshield.core.parser import parse_rules_from_string

    rule_set = parse_rules_from_string(yaml_text)
    print(f"\n✅ Valid: {len(rule_set.rules)} rule(s) parsed successfully")
    return 0


def _write_file(path: str, content: str) -> None:
    from pathlib import Path

    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(content, encoding="utf-8")


# ─── kill / resume commands ──────────────────────────────────────────


def _cmd_kill(parsed: argparse.Namespace) -> int:
    """Send kill switch activation to running server."""
    import json
    import urllib.request

    url = f"http://localhost:{parsed.port}/api/v1/kill"
    data = json.dumps({"reason": parsed.reason}).encode()
    req = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            body = json.loads(resp.read())
            print(f"🛑 Kill switch ACTIVATED: {body.get('reason', '')}")
        return 0
    except Exception as e:
        print(f"✗ Failed to activate kill switch: {e}", file=sys.stderr)
        print(f"  Is the server running on port {parsed.port}?", file=sys.stderr)
        return 1


def _cmd_resume(parsed: argparse.Namespace) -> int:
    """Send kill switch deactivation to running server."""
    import json
    import urllib.request

    url = f"http://localhost:{parsed.port}/api/v1/resume"
    req = urllib.request.Request(
        url,
        data=b"",
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            json.loads(resp.read())
            print("✅ Kill switch DEACTIVATED — normal operation resumed")
        return 0
    except Exception as e:
        print(f"✗ Failed to deactivate kill switch: {e}", file=sys.stderr)
        return 1


# ─── doctor command ──────────────────────────────────────────────────


def _cmd_doctor(parsed: argparse.Namespace) -> int:
    """Run configuration health check."""
    import json as json_mod

    from policyshield.cli.doctor import format_report, run_doctor

    config_path = Path(parsed.config) if parsed.config else None
    rules_path = Path(parsed.rules) if parsed.rules else None

    report = run_doctor(config_path=config_path, rules_path=rules_path)

    if parsed.json:
        out = {
            "score": report.score,
            "max_score": report.max_score,
            "grade": report.grade,
            "checks": [{"name": c.name, "passed": c.passed, "message": c.message} for c in report.checks],
        }
        print(json_mod.dumps(out, indent=2))
    else:
        print(format_report(report))

    return 0


# ─── generate-rules command ──────────────────────────────────────────


def _cmd_generate_rules(parsed: argparse.Namespace) -> int:
    """Generate rules from tool list or OpenClaw."""
    from policyshield.ai.auto_rules import generate_rules, rules_to_yaml

    # Get tool names
    if parsed.from_openclaw:
        from policyshield.integrations.openclaw_client import (
            OpenClawConnectionError,
            fetch_tool_names,
        )

        try:
            print(f"Fetching tools from {parsed.url}...")
            tool_names = fetch_tool_names(parsed.url)
            print(f"  Found {len(tool_names)} tools")
        except OpenClawConnectionError as e:
            print(f"✗ {e}", file=sys.stderr)
            return 1
    elif parsed.tools:
        tool_names = [t.strip() for t in parsed.tools.split(",") if t.strip()]
        print(f"Using {len(tool_names)} provided tool names")
    else:
        print("✗ Specify --from-openclaw or --tools", file=sys.stderr)
        print("  Example: policyshield generate-rules --tools exec,read_file,write_file", file=sys.stderr)
        return 1

    if not tool_names:
        print("✗ No tools found", file=sys.stderr)
        return 1

    # Generate rules
    rules = generate_rules(
        tool_names,
        include_safe=parsed.include_safe,
        default_verdict=parsed.default_verdict,
    )

    if not rules:
        print("⚠ No rules generated (all tools classified as safe)")
        print("  Use --include-safe to generate explicit ALLOW rules for safe tools")
        return 0

    # Summary
    verdicts: dict[str, int] = {}
    for r in rules:
        verdicts[r.verdict] = verdicts.get(r.verdict, 0) + 1
    print(f"\nGenerated {len(rules)} rules:")
    for v, count in sorted(verdicts.items()):
        print(f"  {v.upper()}: {count}")

    # Output
    output_path = Path(parsed.output)
    if output_path.exists() and not parsed.force:
        try:
            confirm = input(f"\n{output_path} already exists. Overwrite? [y/N]: ").strip().lower()
            if confirm not in ("y", "yes"):
                print("Aborted.")
                return 0
        except (EOFError, KeyboardInterrupt):
            print("\nAborted.")
            return 0

    output_path.parent.mkdir(parents=True, exist_ok=True)
    yaml_str = rules_to_yaml(
        rules,
        shield_name=f"auto-{parsed.default_verdict}-policy",
        default_verdict=parsed.default_verdict,
    )
    output_path.write_text(yaml_str, encoding="utf-8")
    print(f"\n✓ Rules written to {output_path}")
    print(f"  Next: policyshield validate {output_path}")
    return 0


def _cmd_openapi(parsed: argparse.Namespace) -> int:
    """Export the OpenAPI schema as JSON."""
    rules_path = Path(parsed.rules)
    if not rules_path.exists():
        print(f"✗ Rules not found: {rules_path}", file=sys.stderr)
        return 1

    try:
        from policyshield.server.app import create_app
        from policyshield.shield.async_engine import AsyncShieldEngine
    except ImportError:
        print("ERROR: server extras required. Run: pip install policyshield[server]", file=sys.stderr)
        return 1

    engine = AsyncShieldEngine(rules=rules_path)
    app = create_app(engine)
    schema = app.openapi()
    output = json.dumps(schema, indent=parsed.indent, ensure_ascii=False)

    if parsed.output:
        Path(parsed.output).write_text(output + "\n", encoding="utf-8")
        print(f"✓ OpenAPI schema written to {parsed.output}", file=sys.stderr)
    else:
        print(output)

    return 0


def _cmd_check(parsed: argparse.Namespace) -> int:
    """One-shot tool call check (dry-run)."""
    rules_path = Path(parsed.rules)
    if not rules_path.exists():
        print(f"✗ Rules not found: {rules_path}", file=sys.stderr)
        return 1

    from policyshield.shield.engine import ShieldEngine

    engine = ShieldEngine(rules=rules_path)
    try:
        args = json.loads(parsed.args)
    except json.JSONDecodeError as e:
        print(f"✗ Invalid JSON args: {e}", file=sys.stderr)
        return 1

    result = engine.check(parsed.tool, args, session_id=parsed.session_id)

    if getattr(parsed, "json_output", False):
        out = {
            "verdict": result.verdict.value,
            "message": result.message,
            "rule_id": result.rule_id,
        }
        if result.modified_args:
            out["modified_args"] = result.modified_args
        if result.pii_matches:
            out["pii_types"] = [m.pii_type.value for m in result.pii_matches]
        print(json.dumps(out, indent=2))
    else:
        icon = "✓" if result.verdict.value == "ALLOW" else "✗"
        print(f"{icon} {result.verdict.value}: {result.message}")
        if result.rule_id:
            print(f"  Rule: {result.rule_id}")

    return 0 if result.verdict.value == "ALLOW" else 2
