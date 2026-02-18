# Prompt 78 — CLI Setup Command

## Цель

Создать CLI-команду `policyshield openclaw setup`, которая автоматизирует все 5 шагов установки OpenClaw-интеграции в одну команду.

## Контекст

Текущая установка требует 5 ручных шагов:
1. `pip install "policyshield[server]"`
2. `policyshield init --preset openclaw`
3. `policyshield server --rules rules.yaml`
4. `openclaw plugins install @policyshield/openclaw-plugin`
5. `openclaw config set plugins.entries.policyshield.config.url ...`

Цель: `policyshield openclaw setup` делает шаги 2–5 автоматически.

## Что сделать

### 1. Создать `policyshield/cli/openclaw.py`

```python
"""CLI commands for OpenClaw integration setup."""
import subprocess
import sys
import time
import shutil
from pathlib import Path

import click


@click.group()
def openclaw():
    """OpenClaw integration commands."""
    pass


@openclaw.command()
@click.option("--rules-dir", default=".", help="Directory for rules.yaml")
@click.option("--port", default=8100, help="PolicyShield server port")
@click.option("--no-server", is_flag=True, help="Skip starting the server")
@click.option("--api-token", default=None, help="Set API token for server auth")
def setup(rules_dir: str, port: int, no_server: bool, api_token: str | None):
    """Set up PolicyShield ↔ OpenClaw integration in one command.

    Steps performed:
    1. Generate OpenClaw preset rules
    2. Start PolicyShield server (background)
    3. Install OpenClaw plugin
    4. Configure plugin URL in OpenClaw
    5. Verify connection
    """
    rules_path = Path(rules_dir) / "rules.yaml"

    # Step 1: Generate rules
    click.echo("→ [1/5] Generating OpenClaw preset rules...")
    if rules_path.exists():
        click.echo(f"  Rules already exist at {rules_path}, skipping.")
    else:
        subprocess.run(
            [sys.executable, "-m", "policyshield", "init", "--preset", "openclaw", "--output", str(rules_path)],
            check=True,
        )
        click.echo(f"  ✓ Rules created: {rules_path}")

    # Step 2: Start server
    server_process = None
    if not no_server:
        click.echo(f"→ [2/5] Starting PolicyShield server on port {port}...")
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
                import urllib.request
                urllib.request.urlopen(f"http://localhost:{port}/api/v1/health", timeout=1)
                break
            except Exception:
                time.sleep(0.5)
        else:
            click.echo("  ✗ Server failed to start. Check logs.")
            sys.exit(1)
        click.echo(f"  ✓ Server running (PID {server_process.pid})")
        # Save PID for teardown
        pid_file = Path(rules_dir) / ".policyshield.pid"
        pid_file.write_text(str(server_process.pid))
    else:
        click.echo("→ [2/5] Skipping server start (--no-server)")

    # Step 3: Install plugin
    click.echo("→ [3/5] Installing OpenClaw plugin...")
    if not shutil.which("openclaw"):
        click.echo("  ✗ 'openclaw' CLI not found. Install OpenClaw first:")
        click.echo("    npm install -g @openclaw/cli")
        sys.exit(1)
    subprocess.run(
        ["openclaw", "plugins", "install", "@policyshield/openclaw-plugin"],
        check=True,
    )
    click.echo("  ✓ Plugin installed")

    # Step 4: Configure plugin
    click.echo("→ [4/5] Configuring plugin URL...")
    url = f"http://localhost:{port}"
    subprocess.run(
        ["openclaw", "config", "set", "plugins.entries.policyshield.config.url", url],
        check=True,
    )
    if api_token:
        subprocess.run(
            ["openclaw", "config", "set", "plugins.entries.policyshield.config.api_token", api_token],
            check=True,
        )
    click.echo(f"  ✓ Plugin configured: {url}")

    # Step 5: Verify
    click.echo("→ [5/5] Verifying connection...")
    try:
        import urllib.request
        import json
        resp = urllib.request.urlopen(f"http://localhost:{port}/api/v1/health", timeout=5)
        data = json.loads(resp.read())
        click.echo(f"  ✓ Server healthy: {data.get('rule_count', '?')} rules loaded, mode={data.get('mode', '?')}")
    except Exception as e:
        click.echo(f"  ✗ Health check failed: {e}")
        sys.exit(1)

    click.echo("")
    click.echo("✅ OpenClaw ↔ PolicyShield integration ready!")
    click.echo(f"   Server: http://localhost:{port}")
    click.echo(f"   Rules:  {rules_path}")
    click.echo(f"   To stop: policyshield openclaw teardown")


@openclaw.command()
@click.option("--rules-dir", default=".", help="Directory containing .policyshield.pid")
def teardown(rules_dir: str):
    """Stop the PolicyShield server started by setup."""
    pid_file = Path(rules_dir) / ".policyshield.pid"
    if not pid_file.exists():
        click.echo("No server PID file found. Nothing to stop.")
        return
    pid = int(pid_file.read_text().strip())
    try:
        import signal
        os.kill(pid, signal.SIGTERM)
        click.echo(f"✓ Server (PID {pid}) stopped.")
    except ProcessLookupError:
        click.echo(f"Server (PID {pid}) was not running.")
    pid_file.unlink()


@openclaw.command()
def status():
    """Check current PolicyShield ↔ OpenClaw integration status."""
    # Check server
    try:
        import urllib.request, json
        resp = urllib.request.urlopen("http://localhost:8100/api/v1/health", timeout=2)
        data = json.loads(resp.read())
        click.echo(f"Server: ✓ running ({data.get('rule_count', '?')} rules, {data.get('mode', '?')})")
    except Exception:
        click.echo("Server: ✗ not reachable")

    # Check plugin
    if shutil.which("openclaw"):
        result = subprocess.run(["openclaw", "plugins", "list"], capture_output=True, text=True)
        if "policyshield" in result.stdout.lower():
            click.echo("Plugin: ✓ installed")
        else:
            click.echo("Plugin: ✗ not installed")
    else:
        click.echo("Plugin: ✗ openclaw CLI not found")
```

### 2. Добавить `import os` missing import

### 3. Зарегистрировать команды в CLI

В `policyshield/cli/main.py`:

```python
from policyshield.cli.openclaw import openclaw
cli.add_command(openclaw)
```

### 4. Добавить Docker Compose one-file стек

Создать `docker/docker-compose.openclaw.yml`:

```yaml
version: "3.8"
services:
  policyshield:
    image: ghcr.io/<OWNER>/policyshield:latest
    ports:
      - "8100:8100"
    volumes:
      - ./rules.yaml:/app/rules.yaml
    command: ["policyshield", "server", "--rules", "/app/rules.yaml", "--host", "0.0.0.0"]
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8100/api/v1/health"]
      interval: 5s
      timeout: 3s
      retries: 5
```

### 5. Тесты

`tests/test_cli_openclaw.py`:

```python
from click.testing import CliRunner
from policyshield.cli.main import cli

def test_openclaw_status_no_server():
    runner = CliRunner()
    result = runner.invoke(cli, ["openclaw", "status"])
    assert result.exit_code == 0
    assert "not reachable" in result.output

def test_openclaw_teardown_no_pid():
    runner = CliRunner()
    result = runner.invoke(cli, ["openclaw", "teardown"])
    assert result.exit_code == 0
    assert "Nothing to stop" in result.output
```

## Самопроверка

```bash
# CLI help
policyshield openclaw --help
policyshield openclaw setup --help
policyshield openclaw status

# Тесты
pytest tests/test_cli_openclaw.py -v
pytest tests/ -q

# TypeScript не изменён
cd plugins/openclaw && npx tsc --noEmit
```

## Коммит

```
feat(cli): add `policyshield openclaw setup/teardown/status` commands

- One-command setup: generates rules, starts server, installs plugin,
  configures URL, verifies connection
- teardown: stops background server by PID
- status: checks server + plugin health
- Add docker-compose.openclaw.yml for one-file Docker deployment
```
