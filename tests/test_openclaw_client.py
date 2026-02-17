"""Tests for OpenClaw tool fetcher."""

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from policyshield.integrations.openclaw_client import (
    OpenClawConnectionError,
    fetch_tool_names,
    fetch_tools,
)


class MockHandler(BaseHTTPRequestHandler):
    """Mock OpenClaw server for testing."""

    response_data: dict = {"tools": []}

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
