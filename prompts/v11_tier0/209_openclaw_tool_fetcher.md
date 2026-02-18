# Prompt 209 — OpenClaw Tool Fetcher

## Цель

Создать HTTP-клиент, который получает список доступных тулов из запущенного OpenClaw-инстанса — основа для автогенерации правил.

## Контекст

- OpenClaw предоставляет список зарегистрированных tools через API
- Нужен лёгкий клиент: fetch tool list → parse → вернуть `list[str]`
- Используется для `policyshield generate-rules --from-openclaw`
- Без внешних зависимостей — только `urllib` из stdlib
- Должен работать с fallback: если OpenClaw недоступен → понятная ошибка
- OpenClaw по умолчанию на `http://localhost:3000`

## Что сделать

### 1. Создать `policyshield/integrations/openclaw_client.py`

```python
"""Lightweight client for fetching tool information from OpenClaw."""

from __future__ import annotations

import json
import urllib.request
import urllib.error
from dataclasses import dataclass


class OpenClawConnectionError(Exception):
    """Raised when OpenClaw is unreachable."""


class OpenClawAPIError(Exception):
    """Raised when OpenClaw returns an unexpected response."""


@dataclass(frozen=True)
class ToolInfo:
    """Information about a tool from OpenClaw."""
    name: str
    description: str = ""
    parameters: dict | None = None


def fetch_tools(
    base_url: str = "http://localhost:3000",
    timeout: int = 10,
) -> list[ToolInfo]:
    """Fetch registered tools from an OpenClaw instance.

    Args:
        base_url: OpenClaw server URL.
        timeout: Request timeout in seconds.

    Returns:
        List of ToolInfo objects.

    Raises:
        OpenClawConnectionError: If OpenClaw is unreachable.
        OpenClawAPIError: If response is malformed.
    """
    url = f"{base_url.rstrip('/')}/api/tools"

    try:
        req = urllib.request.Request(url, headers={
            "Accept": "application/json",
            "User-Agent": "PolicyShield/auto-rules",
        })
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read())
    except urllib.error.URLError as e:
        raise OpenClawConnectionError(
            f"Cannot connect to OpenClaw at {base_url}: {e}"
        ) from e
    except json.JSONDecodeError as e:
        raise OpenClawAPIError(f"Invalid JSON from OpenClaw: {e}") from e

    if not isinstance(data, dict):
        raise OpenClawAPIError(f"Expected JSON object, got {type(data).__name__}")

    tools_list = data.get("tools", data.get("data", []))
    if not isinstance(tools_list, list):
        raise OpenClawAPIError("Expected 'tools' to be a list")

    result = []
    for item in tools_list:
        if isinstance(item, str):
            result.append(ToolInfo(name=item))
        elif isinstance(item, dict):
            result.append(ToolInfo(
                name=item.get("name", item.get("tool_name", "")),
                description=item.get("description", ""),
                parameters=item.get("parameters", item.get("params")),
            ))
    return result


def fetch_tool_names(
    base_url: str = "http://localhost:3000",
    timeout: int = 10,
) -> list[str]:
    """Convenience: fetch just tool names.

    Args:
        base_url: OpenClaw server URL.
        timeout: Request timeout in seconds.

    Returns:
        List of tool name strings.
    """
    return [t.name for t in fetch_tools(base_url, timeout) if t.name]
```

### 2. Тесты

#### `tests/test_openclaw_client.py`

```python
"""Tests for OpenClaw tool fetcher."""

import json
from http.server import HTTPServer, BaseHTTPRequestHandler
import threading

import pytest

from policyshield.integrations.openclaw_client import (
    fetch_tools,
    fetch_tool_names,
    OpenClawConnectionError,
    OpenClawAPIError,
    ToolInfo,
)


class MockHandler(BaseHTTPRequestHandler):
    """Mock OpenClaw server for testing."""

    response_data = {"tools": []}

    def do_GET(self):
        if self.path == "/api/tools":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(self.response_data).encode())
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, *args):
        pass  # Suppress output


@pytest.fixture
def mock_server():
    """Start a mock server for testing."""
    server = HTTPServer(("127.0.0.1", 0), MockHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever)
    thread.daemon = True
    thread.start()
    yield f"http://127.0.0.1:{port}", MockHandler
    server.shutdown()


class TestFetchTools:
    def test_basic_string_tools(self, mock_server):
        url, handler = mock_server
        handler.response_data = {"tools": ["read_file", "write_file", "exec"]}
        tools = fetch_tools(url)
        assert len(tools) == 3
        assert tools[0].name == "read_file"

    def test_dict_tools(self, mock_server):
        url, handler = mock_server
        handler.response_data = {"tools": [
            {"name": "read_file", "description": "Read a file"},
            {"name": "exec", "description": "Execute command"},
        ]}
        tools = fetch_tools(url)
        assert tools[0].name == "read_file"
        assert tools[0].description == "Read a file"

    def test_tool_names(self, mock_server):
        url, handler = mock_server
        handler.response_data = {"tools": ["a", "b", "c"]}
        names = fetch_tool_names(url)
        assert names == ["a", "b", "c"]

    def test_connection_error(self):
        with pytest.raises(OpenClawConnectionError):
            fetch_tools("http://127.0.0.1:1")  # Port 1 — guaranteed failure

    def test_empty_tools(self, mock_server):
        url, handler = mock_server
        handler.response_data = {"tools": []}
        tools = fetch_tools(url)
        assert tools == []

    def test_alt_key_data(self, mock_server):
        url, handler = mock_server
        handler.response_data = {"data": ["tool1", "tool2"]}
        tools = fetch_tools(url)
        assert len(tools) == 2
```

## Самопроверка

```bash
pytest tests/test_openclaw_client.py -v
pytest tests/ -q
```

## Коммит

```
feat(integrations): add OpenClaw tool fetcher for auto-rule generation

- HTTP client fetches tool list from OpenClaw /api/tools
- Supports both string and dict tool formats
- Custom exceptions: OpenClawConnectionError, OpenClawAPIError
- Zero external dependencies (stdlib urllib)
```
