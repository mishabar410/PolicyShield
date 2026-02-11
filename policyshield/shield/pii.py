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


def _inn_check(inn_str: str) -> bool:
    """Validate Russian INN (10 or 12 digits) with checksum."""
    digits = [int(d) for d in inn_str if d.isdigit()]
    if len(digits) == 10:
        weights = [2, 4, 10, 3, 5, 9, 4, 6, 8]
        checksum = sum(d * w for d, w in zip(digits, weights)) % 11 % 10
        return checksum == digits[9]
    elif len(digits) == 12:
        w11 = [7, 2, 4, 10, 3, 5, 9, 4, 6, 8]
        w12 = [3, 7, 2, 4, 10, 3, 5, 9, 4, 6, 8]
        c11 = sum(d * w for d, w in zip(digits, w11)) % 11 % 10
        c12 = sum(d * w for d, w in zip(digits, w12)) % 11 % 10
        return c11 == digits[10] and c12 == digits[11]
    return False


def _snils_check(snils_str: str) -> bool:
    """Validate Russian SNILS (11 digits, format: XXX-XXX-XXX XX)."""
    digits = [int(d) for d in snils_str if d.isdigit()]
    if len(digits) != 11:
        return False
    first9 = digits[:9]
    control = digits[9] * 10 + digits[10]
    total = sum(d * (9 - i) for i, d in enumerate(first9))
    if total < 100:
        expected = total
    elif total == 100 or total == 101:
        expected = 0
    else:
        expected = total % 101
        if expected == 100:
            expected = 0
    return expected == control


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
        pattern=re.compile(
            r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
            r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
        ),
        label="ip_address",
    ),
    PIIPattern(
        pii_type=PIIType.PASSPORT,
        pattern=re.compile(r"\b[A-Z]{1,2}\d{7,9}\b"),
        label="passport",
    ),
    PIIPattern(
        pii_type=PIIType.DATE_OF_BIRTH,
        pattern=re.compile(r"\b(?:\d{1,2}[/.-]\d{1,2}[/.-]\d{2,4}|\d{4}[/.-]\d{1,2}[/.-]\d{1,2})\b"),
        label="date_of_birth",
    ),
    # --- RU-specific patterns ---
    PIIPattern(
        pii_type=PIIType.INN,
        pattern=re.compile(r"\b\d{10}(?:\d{2})?\b"),
        label="inn",
    ),
    PIIPattern(
        pii_type=PIIType.SNILS,
        pattern=re.compile(r"\b\d{3}-\d{3}-\d{3}\s?\d{2}\b"),
        label="snils",
    ),
    PIIPattern(
        pii_type=PIIType.RU_PASSPORT,
        pattern=re.compile(r"\b\d{2}\s?\d{2}\s?\d{6}\b"),
        label="ru_passport",
    ),
    PIIPattern(
        pii_type=PIIType.RU_PHONE,
        pattern=re.compile(r"(?:\+7|8)[\s(-]*\d{3}[\s)-]*\d{3}[\s-]*\d{2}[\s-]*\d{2}\b"),
        label="ru_phone",
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
                # Extra validation for INN
                if pii_pattern.pii_type == PIIType.INN:
                    if not _inn_check(matched_text):
                        continue
                # Extra validation for SNILS
                if pii_pattern.pii_type == PIIType.SNILS:
                    if not _snils_check(matched_text):
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
            elif "." in field_name:
                # Nested field: navigate into the dict to redact in-place
                parts = field_name.split(".")
                self._redact_nested(redacted, parts, matches)

        return redacted, all_matches

    def _redact_nested(
        self,
        data: dict[str, Any],
        parts: list[str],
        matches: list[PIIMatch],
    ) -> None:
        """Redact a nested field located at dot-separated path *parts*."""
        obj: Any = data
        for part in parts[:-1]:
            if isinstance(obj, dict) and part in obj:
                obj = obj[part]
            elif isinstance(obj, list):
                try:
                    obj = obj[int(part)]
                except (ValueError, IndexError):
                    return
            else:
                return

        key = parts[-1]
        if isinstance(obj, dict) and key in obj and isinstance(obj[key], str):
            value = obj[key]
            for match in sorted(matches, key=lambda m: m.span[0], reverse=True):
                start, end = match.span
                value = value[:start] + match.masked_value + value[end:]
            obj[key] = value
