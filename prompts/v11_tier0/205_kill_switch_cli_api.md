# Prompt 205 — Kill Switch CLI & API

## Цель

Добавить CLI команды `policyshield kill` / `policyshield resume` и REST API эндпоинты `/api/v1/kill`, `/api/v1/resume`, `/api/v1/status` для управления kill switch.

## Контекст

- Engine уже имеет `kill()`, `resume()`, `is_killed` (промпт 204)
- HTTP-сервер: `policyshield/server/app.py` — FastAPI/Starlette приложение
- CLI: `policyshield/cli/main.py` — argparse
- `kill` — POST-запрос на running server (kill switch должен работать для уже запущенного процесса)
- CLI `kill` отправляет POST на `http://localhost:{port}/api/v1/kill`
- CLI `resume` отправляет POST на `http://localhost:{port}/api/v1/resume`
- `/api/v1/status` возвращает текущее состояние engine включая `killed`

## Что сделать

### 1. Добавить REST эндпоинты в `policyshield/server/app.py`

```python
@app.post("/api/v1/kill")
async def kill_switch(request: Request):
    """Activate kill switch — block all tool calls."""
    body = await request.json() if request.headers.get("content-length", "0") != "0" else {}
    reason = body.get("reason", "Kill switch activated via API")
    engine.kill(reason)
    return {"status": "killed", "reason": reason}


@app.post("/api/v1/resume")
async def resume_switch():
    """Deactivate kill switch — resume normal operation."""
    engine.resume()
    return {"status": "resumed"}


@app.get("/api/v1/status")
async def server_status():
    """Get server and engine status."""
    return {
        "status": "running",
        "killed": engine.is_killed,
        "mode": engine.mode.value,
        "rules_count": len(engine.rules),
        "version": policyshield.__version__,
    }
```

### 2. Добавить CLI команды в `policyshield/cli/main.py`

```python
# --- kill subparser ---
kill_parser = subparsers.add_parser("kill", help="Activate kill switch on running server")
kill_parser.add_argument("--port", type=int, default=8282, help="Server port")
kill_parser.add_argument("--reason", type=str, default="Kill switch activated via CLI")
kill_parser.set_defaults(func=_cmd_kill)

# --- resume subparser ---
resume_parser = subparsers.add_parser("resume", help="Deactivate kill switch on running server")
resume_parser.add_argument("--port", type=int, default=8282, help="Server port")
resume_parser.set_defaults(func=_cmd_resume)


def _cmd_kill(args: argparse.Namespace) -> None:
    """Send kill switch activation to running server."""
    import urllib.request
    import json

    url = f"http://localhost:{args.port}/api/v1/kill"
    data = json.dumps({"reason": args.reason}).encode()
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            body = json.loads(resp.read())
            print(f"🛑 Kill switch ACTIVATED: {body.get('reason', '')}")
    except Exception as e:
        print(f"✗ Failed to activate kill switch: {e}")
        print(f"  Is the server running on port {args.port}?")
        raise SystemExit(1)


def _cmd_resume(args: argparse.Namespace) -> None:
    """Send kill switch deactivation to running server."""
    import urllib.request
    import json

    url = f"http://localhost:{args.port}/api/v1/resume"
    req = urllib.request.Request(url, data=b"", headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            json.loads(resp.read())
            print("✅ Kill switch DEACTIVATED — normal operation resumed")
    except Exception as e:
        print(f"✗ Failed to deactivate kill switch: {e}")
        raise SystemExit(1)
```

### 3. Тесты

#### `tests/test_kill_switch_api.py`

```python
"""Tests for kill switch REST API and CLI commands."""

import json
import pytest
from unittest.mock import patch, MagicMock

from policyshield.core.parser import RuleSet
from policyshield.shield.engine import ShieldEngine


class TestKillSwitchAPI:
    """Test kill switch API endpoints (uses test client)."""

    @pytest.fixture
    def client(self):
        """Create test client with engine."""
        from policyshield.server.app import create_app
        from starlette.testclient import TestClient

        engine = ShieldEngine(rules=RuleSet(rules=[], default_verdict="allow"))
        app = create_app(engine=engine)
        return TestClient(app), engine

    def test_kill_endpoint(self, client):
        test_client, engine = client
        resp = test_client.post("/api/v1/kill", json={"reason": "test"})
        assert resp.status_code == 200
        assert resp.json()["status"] == "killed"
        assert engine.is_killed

    def test_resume_endpoint(self, client):
        test_client, engine = client
        engine.kill()
        resp = test_client.post("/api/v1/resume")
        assert resp.status_code == 200
        assert not engine.is_killed

    def test_status_shows_killed(self, client):
        test_client, engine = client
        engine.kill()
        resp = test_client.get("/api/v1/status")
        assert resp.json()["killed"] is True

    def test_status_shows_not_killed(self, client):
        test_client, engine = client
        resp = test_client.get("/api/v1/status")
        assert resp.json()["killed"] is False

    def test_kill_then_check_blocks(self, client):
        test_client, engine = client
        test_client.post("/api/v1/kill", json={"reason": "emergency"})
        # Now try a tool check
        resp = test_client.post("/api/v1/shield/check", json={
            "tool": "any_tool",
            "args": {},
        })
        data = resp.json()
        assert data["verdict"] == "BLOCK"
        assert "__kill_switch__" in data.get("rule_id", "")

    def test_kill_default_reason(self, client):
        test_client, engine = client
        resp = test_client.post("/api/v1/kill")
        assert "Kill switch activated" in resp.json()["reason"]
```

## Самопроверка

```bash
pytest tests/test_kill_switch_api.py -v
pytest tests/test_kill_switch.py -v
pytest tests/ -q
```

## Коммит

```
feat(security): add kill switch CLI and REST API

- POST /api/v1/kill — activate kill switch with optional reason
- POST /api/v1/resume — deactivate kill switch
- GET /api/v1/status — engine status including killed state
- CLI: policyshield kill --port 8282 --reason "exploit detected"
- CLI: policyshield resume --port 8282
```
