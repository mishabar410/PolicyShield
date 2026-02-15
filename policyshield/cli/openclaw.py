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

    rules_path = Path(rules_dir) / "rules.yaml"

    # Step 1: Generate rules
    print("→ [1/5] Generating OpenClaw preset rules...")
    if rules_path.exists():
        print(f"  Rules already exist at {rules_path}, skipping.")
    else:
        try:
            subprocess.run(
                [sys.executable, "-m", "policyshield", "init", "--preset", "openclaw", "--no-interactive", str(rules_dir)],
                check=True,
                capture_output=True,
            )
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
        server_process = subprocess.Popen(
            [sys.executable, "-m", "policyshield", "server",
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

    # Step 3: Install plugin
    print("→ [3/5] Installing OpenClaw plugin...")
    if not shutil.which("openclaw"):
        print("  ✗ 'openclaw' CLI not found. Install OpenClaw first:", file=sys.stderr)
        print("    npm install -g @openclaw/cli", file=sys.stderr)
        return 1
    try:
        subprocess.run(
            ["openclaw", "plugins", "install", "@policyshield/openclaw-plugin"],
            check=True,
            capture_output=True,
        )
        print("  ✓ Plugin installed")
    except subprocess.CalledProcessError as e:
        print(f"  ✗ Failed to install plugin: {e}", file=sys.stderr)
        return 1

    # Step 4: Configure plugin
    print("→ [4/5] Configuring plugin URL...")
    url = f"http://localhost:{port}"
    try:
        subprocess.run(
            ["openclaw", "config", "set", "plugins.entries.policyshield.config.url", url],
            check=True,
            capture_output=True,
        )
        if api_token:
            subprocess.run(
                ["openclaw", "config", "set", "plugins.entries.policyshield.config.api_token", api_token],
                check=True,
                capture_output=True,
            )
        print(f"  ✓ Plugin configured: {url}")
    except subprocess.CalledProcessError as e:
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
