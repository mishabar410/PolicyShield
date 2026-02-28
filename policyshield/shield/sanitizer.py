"""Input sanitizer for tool-call arguments.

Protects against prompt injection, normalizes data, and enforces limits.
"""

from __future__ import annotations

import functools
import re
import unicodedata
from dataclasses import dataclass, field
from typing import Any

# Control-char regex: match C0/C1 controls except \n \r \t
_CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]")


@functools.lru_cache(maxsize=128)
def _compile_pattern(pattern: str) -> re.Pattern[str]:
    """Compile regex pattern with caching."""
    return re.compile(pattern, re.IGNORECASE)


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
    builtin_detectors: list[str] | None = None


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
            self._compiled_patterns = [_compile_pattern(p) for p in self._config.blocked_patterns]

        # Load built-in detectors (if configured)
        self._detectors: list | None = None
        if self._config.builtin_detectors:
            from policyshield.shield.detectors import get_detectors

            self._detectors = get_detectors(self._config.builtin_detectors)

    def sanitize(self, args: dict) -> SanitizeResult:
        """Sanitize *args* according to the current config."""
        warnings: list[str] = []
        was_modified = False

        raw_str = _flatten_to_string(args)

        # 1) Built-in detectors run FIRST (defence-in-depth)
        if self._detectors:
            from policyshield.shield.detectors import scan_all

            matches = scan_all(raw_str, detectors=self._detectors)
            if matches:
                first = matches[0]
                return SanitizeResult(
                    sanitized_args=args,
                    warnings=[],
                    was_modified=False,
                    rejected=True,
                    rejection_reason=(f"Built-in detector [{first.detector_name}] matched: {first.matched_text!r}"),
                )

        # 2) User-defined blocked patterns
        if self._compiled_patterns:
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


def _flatten_recurse(value: Any, parts: list[str], _depth: int = 0) -> None:
    if _depth > 50:  # prevent stack overflow on deeply nested input
        return
    if isinstance(value, dict):
        for k, v in value.items():
            if isinstance(k, str):
                parts.append(k)
            _flatten_recurse(v, parts, _depth + 1)
    elif isinstance(value, list):
        for item in value:
            _flatten_recurse(item, parts, _depth + 1)
    elif isinstance(value, str):
        parts.append(value)
    elif value is not None:
        parts.append(str(value))
