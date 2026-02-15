"""CLI commands for OpenClaw integration setup, teardown, and status."""

from __future__ import annotations

import argparse
import json
import os
import signal
import shutil
import subprocess
import sys
import time
import urllib.request
from pathlib import Path


def _get_cli_path() -> str:
    """Return path to the policyshield CLI entry point."""
    cli = shutil.which("policyshield")
    if cli:
        return cli
    # Fallback: look next to the current python executable
    bindir = Path(sys.executable).parent
    candidate = bindir / "policyshield"
    if candidate.exists():
        return str(candidate)
    raise FileNotFoundError("Cannot find 'policyshield' CLI. Is it installed?")


def add_openclaw_subcommands(subparsers: argparse._SubParsersAction) -> None:
    """Register 'openclaw' subcommands onto the main CLI parser."""
    oc_parser = subparsers.add_parser("openclaw", help="OpenClaw integration commands")
    oc_subs = oc_parser.add_subparsers(dest="openclaw_command")

    # setup
    setup_p = oc_subs.add_parser("setup", help="One-command OpenClaw ↔ PolicyShield setup")
    setup_p.add_argument("--rules-dir", default=".", help="Directory for rules.yaml (default: .)")
    setup_p.add_argument("--port", type=int, default=8100, help="PolicyShield server port (default: 8100)")
    setup_p.add_argument("--no-server", action="store_true", help="Skip starting the server")
    setup_p.add_argument("--api-token", default=None, help="Set API token for server auth")

    # teardown
    td_p = oc_subs.add_parser("teardown", help="Stop the PolicyShield server started by setup")
    td_p.add_argument("--rules-dir", default=".", help="Directory containing .policyshield.pid")

    # status
    oc_subs.add_parser("status", help="Check PolicyShield ↔ OpenClaw integration status")


def cmd_openclaw(parsed: argparse.Namespace) -> int:
    """Dispatch openclaw subcommands."""
    sub = getattr(parsed, "openclaw_command", None)
    if sub == "setup":
        return _cmd_setup(parsed)
    elif sub == "teardown":
        return _cmd_teardown(parsed)
    elif sub == "status":
        return _cmd_status()
    else:
        print("Usage: policyshield openclaw {setup,teardown,status}", file=sys.stderr)
        return 1


# ------------------------------------------------------------------ #
#  setup                                                              #
# ------------------------------------------------------------------ #


def _cmd_setup(parsed: argparse.Namespace) -> int:
    """Set up PolicyShield ↔ OpenClaw integration in one command."""
    rules_dir = parsed.rules_dir
    port: int = parsed.port
    no_server: bool = parsed.no_server
    api_token: str | None = parsed.api_token

    rules_dir_path = Path(rules_dir)
    # init creates policies/rules.yaml; allow plain rules.yaml too
    rules_candidates = [
        rules_dir_path / "policies" / "rules.yaml",
        rules_dir_path / "rules.yaml",
    ]
    rules_path = next((p for p in rules_candidates if p.exists()), None)

    # Step 1: Generate rules
    print("→ [1/5] Generating OpenClaw preset rules...")
    if rules_path is not None:
        print(f"  Rules already exist at {rules_path}, skipping.")
    else:
        try:
            cli = _get_cli_path()
            subprocess.run(
                [cli, "init", "--preset", "openclaw", "--no-interactive", str(rules_dir)],
                check=True,
                capture_output=True,
            )
            # re-discover after init
            rules_path = next((p for p in rules_candidates if p.exists()), None)
            if rules_path is None:
                print("  ✗ Init ran but rules.yaml was not created.", file=sys.stderr)
                return 1
            print(f"  ✓ Rules created: {rules_path}")
        except subprocess.CalledProcessError as e:
            print(f"  ✗ Failed to generate rules: {e.stderr.decode()}", file=sys.stderr)
            return 1

    # Step 2: Start server
    if not no_server:
        print(f"→ [2/5] Starting PolicyShield server on port {port}...")
        env = dict(os.environ)
        if api_token:
            env["POLICYSHIELD_API_TOKEN"] = api_token
        cli = _get_cli_path()
        server_process = subprocess.Popen(
            [cli, "server",
             "--rules", str(rules_path), "--port", str(port)],
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        # Wait for server to start
        for _ in range(20):
            try:
                urllib.request.urlopen(f"http://localhost:{port}/api/v1/health", timeout=1)
                break
            except Exception:
                time.sleep(0.5)
        else:
            print("  ✗ Server failed to start. Check logs.", file=sys.stderr)
            return 1
        print(f"  ✓ Server running (PID {server_process.pid})")
        pid_file = Path(rules_dir) / ".policyshield.pid"
        pid_file.write_text(str(server_process.pid))
    else:
        print("→ [2/5] Skipping server start (--no-server)")

    # Step 3: Install plugin via npm into OpenClaw extensions directory
    print("→ [3/5] Installing OpenClaw plugin...")
    if not shutil.which("openclaw"):
        print("  ✗ 'openclaw' CLI not found. Install OpenClaw first:", file=sys.stderr)
        print("    npm install -g @openclaw/cli", file=sys.stderr)
        return 1
    if not shutil.which("npm"):
        print("  ✗ 'npm' not found. Install Node.js first.", file=sys.stderr)
        return 1
    ext_dir = Path.home() / ".openclaw" / "extensions" / "policyshield"
    ext_dir.mkdir(parents=True, exist_ok=True)
    try:
        # Install the npm package into a temporary prefix
        subprocess.run(
            ["npm", "install", "--prefix", str(ext_dir),
             "@policyshield/openclaw-plugin@latest"],
            check=True,
            capture_output=True,
        )
        # Copy package contents to extension root (OpenClaw expects files at top level)
        pkg_dir = ext_dir / "node_modules" / "@policyshield" / "openclaw-plugin"
        if pkg_dir.exists():
            for item in pkg_dir.iterdir():
                dest = ext_dir / item.name
                if item.is_dir():
                    shutil.copytree(item, dest, dirs_exist_ok=True)
                else:
                    shutil.copy2(item, dest)
        print(f"  ✓ Plugin installed: {ext_dir}")
    except subprocess.CalledProcessError as e:
        stderr_text = e.stderr.decode() if e.stderr else str(e)
        print(f"  ✗ Failed to install plugin: {stderr_text}", file=sys.stderr)
        return 1

    # Step 4: Configure plugin in OpenClaw config
    print("→ [4/5] Configuring plugin...")
    url = f"http://localhost:{port}"
    oc_config_path = Path.home() / ".openclaw" / "openclaw.json"
    try:
        if oc_config_path.exists():
            oc_config = json.loads(oc_config_path.read_text())
        else:
            oc_config = {}
        plugins = oc_config.setdefault("plugins", {})
        plugins.setdefault("enabled", True)
        entries = plugins.setdefault("entries", {})
        ps_entry = entries.setdefault("policyshield", {})
        ps_entry["enabled"] = True
        ps_config = ps_entry.setdefault("config", {})
        ps_config["url"] = url
        if api_token:
            ps_config["api_token"] = api_token
        oc_config_path.write_text(json.dumps(oc_config, indent=2) + "\n")
        print(f"  ✓ Plugin configured: {url}")
    except Exception as e:
        print(f"  ✗ Failed to configure plugin: {e}", file=sys.stderr)
        return 1

    # Step 5: Verify
    print("→ [5/5] Verifying connection...")
    try:
        resp = urllib.request.urlopen(f"http://localhost:{port}/api/v1/health", timeout=5)
        data = json.loads(resp.read())
        print(f"  ✓ Server healthy: {data.get('rules_count', '?')} rules loaded, mode={data.get('mode', '?')}")
    except Exception as e:
        print(f"  ✗ Health check failed: {e}", file=sys.stderr)
        return 1

    print("")
    print("✅ OpenClaw ↔ PolicyShield integration ready!")
    print(f"   Server: http://localhost:{port}")
    print(f"   Rules:  {rules_path}")
    print("   To stop: policyshield openclaw teardown")
    return 0


# ------------------------------------------------------------------ #
#  teardown                                                           #
# ------------------------------------------------------------------ #


def _cmd_teardown(parsed: argparse.Namespace) -> int:
    """Stop the PolicyShield server started by setup."""
    rules_dir = parsed.rules_dir
    pid_file = Path(rules_dir) / ".policyshield.pid"
    if not pid_file.exists():
        print("No server PID file found. Nothing to stop.")
        return 0
    pid = int(pid_file.read_text().strip())
    try:
        os.kill(pid, signal.SIGTERM)
        print(f"✓ Server (PID {pid}) stopped.")
    except ProcessLookupError:
        print(f"Server (PID {pid}) was not running.")
    pid_file.unlink()
    return 0


# ------------------------------------------------------------------ #
#  status                                                             #
# ------------------------------------------------------------------ #


def _cmd_status() -> int:
    """Check current PolicyShield ↔ OpenClaw integration status."""
    # Check server
    try:
        resp = urllib.request.urlopen("http://localhost:8100/api/v1/health", timeout=2)
        data = json.loads(resp.read())
        print(f"Server: ✓ running ({data.get('rules_count', '?')} rules, {data.get('mode', '?')})")
    except Exception:
        print("Server: ✗ not reachable")

    # Check plugin
    if shutil.which("openclaw"):
        result = subprocess.run(["openclaw", "plugins", "list"], capture_output=True, text=True)
        if "policyshield" in result.stdout.lower():
            print("Plugin: ✓ installed")
        else:
            print("Plugin: ✗ not installed")
    else:
        print("Plugin: ✗ openclaw CLI not found")

    return 0
