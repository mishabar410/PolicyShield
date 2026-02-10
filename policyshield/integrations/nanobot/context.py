"""Context variables for PolicyShield nanobot integration."""

from __future__ import annotations

from contextvars import ContextVar

# Context variable for session ID — allows per-request session tracking
session_id_var: ContextVar[str] = ContextVar("policyshield_session_id", default="default")
