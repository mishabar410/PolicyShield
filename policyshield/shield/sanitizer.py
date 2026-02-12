"""Input sanitizer for tool-call arguments.

Protects against prompt injection, normalizes data, and enforces limits.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field
from typing import Any

# Control-char regex: match C0/C1 controls except \n \r \t
_CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]")


@dataclass
class SanitizerConfig:
    """Configuration for :class:`InputSanitizer`."""

    max_string_length: int = 10_000
    max_args_depth: int = 10
    max_total_keys: int = 100
    strip_whitespace: bool = True
    strip_null_bytes: bool = True
    normalize_unicode: bool = True
    strip_control_chars: bool = True
    blocked_patterns: list[str] | None = None


@dataclass
class SanitizeResult:
    """Result of sanitizing a dict of arguments."""

    sanitized_args: dict
    warnings: list[str] = field(default_factory=list)
    was_modified: bool = False
    rejected: bool = False
    rejection_reason: str = ""


class InputSanitizer:
    """Sanitize tool-call arguments before policy checks."""

    def __init__(self, config: SanitizerConfig | None = None) -> None:
        self._config = config or SanitizerConfig()
        self._compiled_patterns: list[re.Pattern] | None = None
        if self._config.blocked_patterns:
            self._compiled_patterns = [re.compile(p, re.IGNORECASE) for p in self._config.blocked_patterns]

    def sanitize(self, args: dict) -> SanitizeResult:
        """Sanitize *args* according to the current config."""
        warnings: list[str] = []
        was_modified = False

        # Check blocked patterns first (on raw args)
        if self._compiled_patterns:
            raw_str = _flatten_to_string(args)
            for pat in self._compiled_patterns:
                if pat.search(raw_str):
                    return SanitizeResult(
                        sanitized_args=args,
                        warnings=[],
                        was_modified=False,
                        rejected=True,
                        rejection_reason=f"Blocked pattern matched: {pat.pattern!r}",
                    )

        # Deep-copy and sanitize
        key_counter = _Counter()
        sanitized, modified, warns = self._walk(args, depth=0, key_counter=key_counter)
        was_modified = modified
        warnings.extend(warns)

        return SanitizeResult(
            sanitized_args=sanitized,
            warnings=warnings,
            was_modified=was_modified,
        )

    def _walk(
        self,
        value: Any,
        depth: int,
        key_counter: _Counter,
    ) -> tuple[Any, bool, list[str]]:
        """Recursively walk *value*, sanitizing as we go."""
        cfg = self._config
        warnings: list[str] = []
        modified = False

        if isinstance(value, dict):
            if depth >= cfg.max_args_depth:
                warnings.append(f"Max depth ({cfg.max_args_depth}) exceeded — truncated")
                return {}, True, warnings

            result = {}
            for k, v in value.items():
                if key_counter.count >= cfg.max_total_keys:
                    warnings.append(f"Max keys ({cfg.max_total_keys}) exceeded — truncated")
                    modified = True
                    break
                key_counter.count += 1
                new_v, m, w = self._walk(v, depth + 1, key_counter)
                if m:
                    modified = True
                warnings.extend(w)
                result[k] = new_v
            return result, modified, warnings

        if isinstance(value, list):
            if depth >= cfg.max_args_depth:
                warnings.append(f"Max depth ({cfg.max_args_depth}) exceeded — truncated")
                return [], True, warnings

            result_list = []
            for item in value:
                new_item, m, w = self._walk(item, depth + 1, key_counter)
                if m:
                    modified = True
                warnings.extend(w)
                result_list.append(new_item)
            return result_list, modified, warnings

        if isinstance(value, str):
            s = value

            if cfg.strip_null_bytes and "\x00" in s:
                s = s.replace("\x00", "")
                modified = True

            if cfg.strip_control_chars:
                new_s = _CONTROL_RE.sub("", s)
                if new_s != s:
                    modified = True
                    s = new_s

            if cfg.strip_whitespace:
                stripped = s.strip()
                if stripped != s:
                    modified = True
                    s = stripped

            if cfg.normalize_unicode:
                normed = unicodedata.normalize("NFC", s)
                if normed != s:
                    modified = True
                    s = normed

            if len(s) > cfg.max_string_length:
                s = s[: cfg.max_string_length]
                modified = True
                warnings.append(f"String truncated to {cfg.max_string_length} chars")

            return s, modified, warnings

        return value, False, []


class _Counter:
    """Simple mutable counter for key tracking."""

    def __init__(self) -> None:
        self.count = 0


def _flatten_to_string(value: Any) -> str:
    """Flatten a nested structure to a single string for pattern matching."""
    parts: list[str] = []
    _flatten_recurse(value, parts)
    return " ".join(parts)


def _flatten_recurse(value: Any, parts: list[str]) -> None:
    if isinstance(value, dict):
        for v in value.values():
            _flatten_recurse(v, parts)
    elif isinstance(value, list):
        for item in value:
            _flatten_recurse(item, parts)
    elif isinstance(value, str):
        parts.append(value)
    elif value is not None:
        parts.append(str(value))
