"""Core data models for PolicyShield."""

from __future__ import annotations

from datetime import datetime
from enum import Enum

from pydantic import BaseModel, ConfigDict


# --- Enums ---


class Verdict(str, Enum):
    """Verdict for a tool call check."""

    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    APPROVE = "APPROVE"
    REDACT = "REDACT"


class Severity(str, Enum):
    """Severity level of a rule."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class PIIType(str, Enum):
    """Types of personally identifiable information."""

    EMAIL = "EMAIL"
    PHONE = "PHONE"
    CREDIT_CARD = "CREDIT_CARD"
    SSN = "SSN"
    IBAN = "IBAN"
    IP_ADDRESS = "IP_ADDRESS"
    PASSPORT = "PASSPORT"
    DATE_OF_BIRTH = "DATE_OF_BIRTH"
    CUSTOM = "CUSTOM"


class ShieldMode(str, Enum):
    """Operating mode for the shield."""

    ENFORCE = "ENFORCE"
    AUDIT = "AUDIT"
    DISABLED = "DISABLED"


# --- Data Models ---


class ArgsMatcherConfig(BaseModel):
    """Configuration for a single argument matcher."""

    model_config = ConfigDict(frozen=True)

    field: str
    predicate: str
    value: str


class RuleConfig(BaseModel):
    """A single rule from YAML configuration."""

    model_config = ConfigDict(frozen=True)

    id: str
    description: str = ""
    when: dict = {}
    then: Verdict = Verdict.ALLOW
    message: str | None = None
    severity: Severity = Severity.LOW
    enabled: bool = True


class RuleSet(BaseModel):
    """A set of rules loaded from YAML files."""

    model_config = ConfigDict(frozen=True)

    shield_name: str
    version: int
    rules: list[RuleConfig]

    def enabled_rules(self) -> list[RuleConfig]:
        """Return only rules with enabled=True."""
        return [rule for rule in self.rules if rule.enabled]


class PIIMatch(BaseModel):
    """A detected PII match."""

    model_config = ConfigDict(frozen=True)

    pii_type: PIIType
    field: str
    span: tuple[int, int]
    masked_value: str


class ShieldResult(BaseModel):
    """Result of checking a single tool call."""

    model_config = ConfigDict(frozen=True)

    verdict: Verdict
    rule_id: str | None = None
    message: str = ""
    pii_matches: list[PIIMatch] = []
    original_args: dict | None = None
    modified_args: dict | None = None


class SessionState(BaseModel):
    """Mutable session state."""

    model_config = ConfigDict(frozen=False)

    session_id: str
    created_at: datetime
    tool_counts: dict[str, int] = {}
    total_calls: int = 0
    taints: set[PIIType] = set()

    def increment(self, tool_name: str) -> None:
        """Increment tool call counters."""
        self.tool_counts[tool_name] = self.tool_counts.get(tool_name, 0) + 1
        self.total_calls += 1


class TraceRecord(BaseModel):
    """A single audit log record."""

    model_config = ConfigDict(frozen=True)

    timestamp: datetime
    session_id: str
    tool: str
    verdict: Verdict
    rule_id: str | None = None
    pii_types: list[str] = []
    latency_ms: float = 0.0
    args_hash: str | None = None
