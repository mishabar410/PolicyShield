"""Built-in security detectors for common attack patterns.

Each detector bundles a set of compiled regex patterns that match known
attack signatures (path traversal, shell injection, SQL injection, etc.).
Detectors are designed to run **before** user-defined blocked patterns in
the :class:`InputSanitizer` for defence-in-depth.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field


# ────────────────────────────────────────────────────────────────────
# Data classes
# ────────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class DetectorMatch:
    """A single match produced by a detector."""

    detector_name: str
    matched_text: str
    start: int
    end: int


@dataclass(frozen=True)
class Detector:
    """A named set of regex patterns that detect a class of attacks."""

    name: str
    description: str
    patterns: tuple[re.Pattern[str], ...] = field(repr=False)
    severity: str = "high"

    def scan(self, text: str) -> list[DetectorMatch]:
        """Return all matches found in *text*."""
        matches: list[DetectorMatch] = []
        for pat in self.patterns:
            for m in pat.finditer(text):
                matches.append(
                    DetectorMatch(
                        detector_name=self.name,
                        matched_text=m.group(),
                        start=m.start(),
                        end=m.end(),
                    )
                )
        return matches


# ────────────────────────────────────────────────────────────────────
# Helpers
# ────────────────────────────────────────────────────────────────────

_I = re.IGNORECASE


def _compile(*raw: str, flags: int = 0) -> tuple[re.Pattern[str], ...]:
    return tuple(re.compile(p, flags) for p in raw)


# ────────────────────────────────────────────────────────────────────
# Built-in detectors
# ────────────────────────────────────────────────────────────────────

PATH_TRAVERSAL = Detector(
    name="path_traversal",
    description="Detects directory traversal sequences (../, ..\\, etc.)",
    patterns=_compile(
        r"(?:\.\./){2,}",            # ../../  (2+ levels)
        r"(?:\.\.\\){2,}",           # ..\..\  (Windows)
        r"\.\./etc/(?:passwd|shadow)",  # direct /etc/passwd
        r"\.\./windows/",            # Windows system dir
        r"%2e%2e[/\\]",              # URL-encoded traversal
        flags=_I,
    ),
    severity="high",
)

SHELL_INJECTION = Detector(
    name="shell_injection",
    description="Detects shell metacharacters and command injection patterns",
    patterns=_compile(
        r";\s*(?:rm|cat|curl|wget|bash|sh|python|perl|ruby|nc|ncat)\b",
        r"\|\s*(?:sh|bash|zsh|cmd)\b",
        r"`[^`]+`",                  # backtick command substitution
        r"\$\([^)]+\)",              # $(cmd) substitution
        r">\s*/(?:etc|dev|tmp)/",    # redirect to sensitive paths
        flags=_I,
    ),
    severity="critical",
)

SQL_INJECTION = Detector(
    name="sql_injection",
    description="Detects common SQL injection patterns",
    patterns=_compile(
        r"'\s*(?:OR|AND)\s+['\d].*?=",          # ' OR '1'='1
        r"(?:UNION\s+(?:ALL\s+)?SELECT)\b",     # UNION SELECT
        r";\s*(?:DROP|DELETE|INSERT|UPDATE)\s",  # stacked queries
        r"--\s*$",                               # SQL comment terminator
        r"'\s*;\s*--",                           # quote-semicolon-comment
        flags=_I,
    ),
    severity="critical",
)

SSRF = Detector(
    name="ssrf",
    description="Detects server-side request forgery via internal network URLs",
    patterns=_compile(
        r"https?://(?:127\.\d+\.\d+\.\d+|localhost)\b",  # localhost
        r"https?://(?:10\.\d+\.\d+\.\d+)\b",             # 10.x.x.x
        r"https?://(?:172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+)\b",  # 172.16-31
        r"https?://(?:192\.168\.\d+\.\d+)\b",             # 192.168.x.x
        r"https?://169\.254\.\d+\.\d+",                   # link-local / metadata
        r"https?://\[::1\]",                               # IPv6 loopback
        flags=_I,
    ),
    severity="high",
)

URL_SCHEMES = Detector(
    name="url_schemes",
    description="Detects dangerous URL schemes (file://, data:, javascript:, etc.)",
    patterns=_compile(
        r"\bfile://",
        r"\bdata:\s*(?:text/html|application/)",
        r"\bjavascript:",
        r"\bvbscript:",
        r"\bgopher://",
        flags=_I,
    ),
    severity="high",
)


# ────────────────────────────────────────────────────────────────────
# Registry
# ────────────────────────────────────────────────────────────────────

ALL_DETECTORS: dict[str, Detector] = {
    d.name: d
    for d in (PATH_TRAVERSAL, SHELL_INJECTION, SQL_INJECTION, SSRF, URL_SCHEMES)
}


def get_detector(name: str) -> Detector:
    """Return a single detector by name, or raise ``KeyError``."""
    return ALL_DETECTORS[name]


def get_detectors(names: list[str]) -> list[Detector]:
    """Return a list of detectors by name.

    Raises ``KeyError`` if any name is unknown.
    """
    return [ALL_DETECTORS[n] for n in names]


def scan_all(text: str, detectors: list[Detector] | None = None) -> list[DetectorMatch]:
    """Run all (or specified) detectors against *text* and return matches."""
    if detectors is None:
        detectors = list(ALL_DETECTORS.values())
    matches: list[DetectorMatch] = []
    for det in detectors:
        matches.extend(det.scan(text))
    return matches
