"""PII detector for PolicyShield — regex-based L0 detection."""

from __future__ import annotations

import re
from dataclasses import dataclass

from policyshield.core.models import PIIMatch, PIIType


@dataclass
class PIIPattern:
    """A compiled PII detection pattern."""

    pii_type: PIIType
    pattern: re.Pattern
    label: str = ""


# Luhn algorithm for credit card validation
def _luhn_check(number: str) -> bool:
    """Validate a number string with the Luhn algorithm."""
    digits = [int(d) for d in number if d.isdigit()]
    if len(digits) < 13:
        return False
    odd_digits = digits[-1::-2]
    even_digits = digits[-2::-2]
    total = sum(odd_digits)
    for d in even_digits:
        total += sum(divmod(d * 2, 10))
    return total % 10 == 0


# Built-in PII patterns
BUILTIN_PATTERNS: list[PIIPattern] = [
    PIIPattern(
        pii_type=PIIType.EMAIL,
        pattern=re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"),
        label="email",
    ),
    PIIPattern(
        pii_type=PIIType.PHONE,
        pattern=re.compile(r"\+?\d{1,3}[-.\s]?\(?\d{1,4}\)?[-.\s]?\d{1,4}[-.\s]?\d{1,9}"),
        label="phone",
    ),
    PIIPattern(
        pii_type=PIIType.CREDIT_CARD,
        pattern=re.compile(r"\b(?:\d[ -]*?){13,19}\b"),
        label="credit_card",
    ),
    PIIPattern(
        pii_type=PIIType.SSN,
        pattern=re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
        label="ssn",
    ),
    PIIPattern(
        pii_type=PIIType.IBAN,
        pattern=re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}(?:[A-Z0-9]?){0,16}\b"),
        label="iban",
    ),
    PIIPattern(
        pii_type=PIIType.IP_ADDRESS,
        pattern=re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
        label="ip_address",
    ),
    PIIPattern(
        pii_type=PIIType.PASSPORT,
        pattern=re.compile(r"\b[A-Z]{1,2}\d{6,9}\b"),
        label="passport",
    ),
    PIIPattern(
        pii_type=PIIType.DATE_OF_BIRTH,
        pattern=re.compile(r"\b(?:\d{1,2}[/.-]\d{1,2}[/.-]\d{2,4}|\d{4}[/.-]\d{1,2}[/.-]\d{1,2})\b"),
        label="date_of_birth",
    ),
]


class PIIDetector:
    """Regex-based PII detector (L0).

    Scans text for PII patterns and supports masking.
    """

    def __init__(
        self,
        patterns: list[PIIPattern] | None = None,
        custom_patterns: list[PIIPattern] | None = None,
    ):
        self._patterns: list[PIIPattern] = list(patterns or BUILTIN_PATTERNS)
        if custom_patterns:
            self._patterns.extend(custom_patterns)

    def scan(self, text: str, field_name: str = "") -> list[PIIMatch]:
        """Scan text for PII matches.

        Args:
            text: Text to scan.
            field_name: Name of the field being scanned (for reporting).

        Returns:
            List of PIIMatch objects.
        """
        matches: list[PIIMatch] = []
        for pii_pattern in self._patterns:
            for m in pii_pattern.pattern.finditer(text):
                matched_text = m.group()
                # Extra validation for credit cards via Luhn
                if pii_pattern.pii_type == PIIType.CREDIT_CARD:
                    digits = re.sub(r"[^\d]", "", matched_text)
                    if not _luhn_check(digits):
                        continue

                matches.append(
                    PIIMatch(
                        pii_type=pii_pattern.pii_type,
                        field=field_name,
                        span=(m.start(), m.end()),
                        masked_value=self.mask(matched_text),
                    )
                )
        return matches

    def scan_dict(self, data: dict, prefix: str = "") -> list[PIIMatch]:
        """Scan all string values in a dict for PII.

        Args:
            data: Dictionary to scan.
            prefix: Key prefix for nested field names.

        Returns:
            List of PIIMatch objects.
        """
        matches: list[PIIMatch] = []
        for key, value in data.items():
            field_name = f"{prefix}.{key}" if prefix else key
            if isinstance(value, str):
                matches.extend(self.scan(value, field_name))
            elif isinstance(value, dict):
                matches.extend(self.scan_dict(value, field_name))
            elif isinstance(value, list):
                for i, item in enumerate(value):
                    if isinstance(item, str):
                        matches.extend(self.scan(item, f"{field_name}[{i}]"))
                    elif isinstance(item, dict):
                        matches.extend(self.scan_dict(item, f"{field_name}[{i}]"))
        return matches

    @staticmethod
    def mask(text: str, mask_char: str = "*", keep_edges: int = 2) -> str:
        """Mask a PII value, keeping edge characters.

        Args:
            text: Text to mask.
            mask_char: Character to use for masking.
            keep_edges: Number of characters to keep at each edge.

        Returns:
            Masked string.
        """
        if len(text) <= keep_edges * 2:
            return mask_char * len(text)
        return text[:keep_edges] + mask_char * (len(text) - keep_edges * 2) + text[-keep_edges:]

    def redact_dict(self, data: dict) -> tuple[dict, list[PIIMatch]]:
        """Scan a dict and return a copy with PII values redacted.

        Args:
            data: Dictionary to scan and redact.

        Returns:
            Tuple of (redacted dict, list of PIIMatch).
        """
        all_matches = self.scan_dict(data)
        if not all_matches:
            return data, []

        # Group matches by field
        field_matches: dict[str, list[PIIMatch]] = {}
        for match in all_matches:
            field_matches.setdefault(match.field, []).append(match)

        redacted = dict(data)
        for field_name, matches in field_matches.items():
            # Simple top-level field redaction
            if field_name in redacted and isinstance(redacted[field_name], str):
                value = redacted[field_name]
                # Apply masks in reverse order to preserve positions
                for match in sorted(matches, key=lambda m: m.span[0], reverse=True):
                    start, end = match.span
                    value = value[:start] + match.masked_value + value[end:]
                redacted[field_name] = value

        return redacted, all_matches
