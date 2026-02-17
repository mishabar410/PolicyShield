"""Lightweight client for fetching tool information from OpenClaw."""

from __future__ import annotations

import json
import urllib.error
import urllib.request
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
