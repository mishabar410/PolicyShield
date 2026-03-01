"""PII detector for PolicyShield — regex-based L0 detection."""

from __future__ import annotations

import copy
import re
from dataclasses import dataclass
from typing import Any

from policyshield.core.models import PIIMatch, PIIType

# Maximum string length to scan for PII (prevents ReDoS on huge inputs)
MAX_SCAN_LENGTH = 50_000


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


def _iban_check(iban: str) -> bool:
    """Validate IBAN checksum (ISO 13616 mod-97 check)."""
    # Remove spaces and uppercase
    iban = iban.replace(" ", "").upper()
    if len(iban) < 5:
        return False
    # Move first 4 chars to end
    rearranged = iban[4:] + iban[:4]
    # Convert letters to numbers (A=10, B=11, ..., Z=35)
    numeric = ""
    for ch in rearranged:
        if ch.isdigit():
            numeric += ch
        elif ch.isalpha():
            numeric += str(ord(ch) - ord("A") + 10)
        else:
            return False
    try:
        return int(numeric) % 97 == 1
    except (ValueError, OverflowError):
        return False


def _date_check(date_str: str) -> bool:
    """Basic plausibility check for date-of-birth strings.

    Rejects matches with month > 12 or day > 31 to reduce false positives
    on version numbers, filenames, etc.
    """
    import re as _re

    # Extract numeric parts
    parts = _re.split(r"[/.\-]", date_str)
    if len(parts) != 3:
        return False
    try:
        nums = [int(p) for p in parts]
    except ValueError:
        return False

    # Determine which is year (4-digit part)
    if nums[2] > 31:  # DD/MM/YYYY or MM/DD/YYYY
        day_or_month_1, day_or_month_2, year = nums
    elif nums[0] > 31:  # YYYY/MM/DD
        year, day_or_month_1, day_or_month_2 = nums
    else:
        # Ambiguous (all parts ≤ 31): still require at least one ≤ 12 (month)
        # to reject clear non-dates like version numbers "32.33.34" is already
        # caught above, but "5.6.7" should still be accepted cautiously.
        if all(n > 12 for n in nums):
            return False  # No part can be a month
        return True

    # At least one of the two non-year parts must be ≤ 12 (month)
    # and both must be ≤ 31
    if day_or_month_1 > 31 or day_or_month_2 > 31:
        return False
    if day_or_month_1 > 12 and day_or_month_2 > 12:
        return False  # Neither can be a month
    # Year should be reasonable for a birth date
    if year < 1900 or year > 2100:
        return False
    return True


# Built-in PII patterns
BUILTIN_PATTERNS: list[PIIPattern] = [
    PIIPattern(
        pii_type=PIIType.EMAIL,
        pattern=re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"),
        label="email",
    ),
    PIIPattern(
        pii_type=PIIType.PHONE,
        pattern=re.compile(
            r"(?:\+\d{1,3}[-.\s]?)"  # required country code (e.g. +7, +1, +44)
            r"\(?\d{2,4}\)?"  # area code
            r"[-.\s]?\d{2,4}"  # first group
            r"[-.\s]?\d{2,4}"  # second group
            r"(?:[-.\s]?\d{1,4})?"  # optional extension
        ),
        label="phone",
    ),
    PIIPattern(
        pii_type=PIIType.CREDIT_CARD,
        pattern=re.compile(
            r"\b"
            r"(?:"
            r"\d{4}[- ]\d{4}[- ]\d{4}[- ]\d{1,7}"  # with separators
            r"|"
            r"(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2}|6(?:011|5\d{2}))\d{8,12}"  # known prefixes (Visa/MC/Amex/Discover)
            r")"
            r"\b"
        ),
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
        pattern=re.compile(r"\b[A-Z]{2}\d{7}\b"),  # EU format: exactly 2 letters + 7 digits
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
        pattern=re.compile(
            r"(?<!\d)"  # not preceded by a digit
            r"\d{2}\s\d{2}"  # series with mandatory space: XX XX
            r"\s\d{6}"  # number with mandatory space: XXXXXX
            r"(?!\d)"  # not followed by a digit
        ),
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
        # Truncate extremely long strings to prevent ReDoS
        scan_text = text[:MAX_SCAN_LENGTH] if len(text) > MAX_SCAN_LENGTH else text

        matches: list[PIIMatch] = []
        for pii_pattern in self._patterns:
            for m in pii_pattern.pattern.finditer(scan_text):
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
                # Extra validation for dates (reduce false positives)
                if pii_pattern.pii_type == PIIType.DATE_OF_BIRTH:
                    if not _date_check(matched_text):
                        continue
                # Extra validation for IBAN (mod-97 checksum)
                if pii_pattern.pii_type == PIIType.IBAN:
                    if not _iban_check(matched_text):
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
                matches.extend(self._scan_list(value, field_name))
        return matches

    def _scan_list(self, items: list, prefix: str, _depth: int = 0) -> list[PIIMatch]:
        """Recursively scan list items for PII, handling nested lists."""
        if _depth > 20:  # Prevent stack overflow on deeply nested input
            return []
        matches: list[PIIMatch] = []
        for i, item in enumerate(items):
            field_name = f"{prefix}[{i}]"
            if isinstance(item, str):
                matches.extend(self.scan(item, field_name))
            elif isinstance(item, dict):
                matches.extend(self.scan_dict(item, field_name))
            elif isinstance(item, list):
                matches.extend(self._scan_list(item, field_name, _depth + 1))
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

    def redact_text(self, text: str) -> str:
        """Scan a string and return a copy with PII values masked.

        Args:
            text: Text to scan and redact.

        Returns:
            Text with PII values replaced by masked versions.
        """
        matches = self.scan(text)
        if not matches:
            return text

        # Sort by start position, then merge overlapping spans
        sorted_matches = sorted(matches, key=lambda m: m.span[0])
        merged: list[PIIMatch] = [sorted_matches[0]]
        for match in sorted_matches[1:]:
            prev = merged[-1]
            if match.span[0] <= prev.span[1]:
                # Overlapping — extend span, keep whichever has larger coverage
                if match.span[1] > prev.span[1]:
                    extended_text = text[prev.span[0] : match.span[1]]
                    # Use the higher-priority PII type (prefer the more specific one)
                    pii_type = (
                        match.pii_type if match.span[1] - match.span[0] > prev.span[1] - prev.span[0] else prev.pii_type
                    )
                    merged[-1] = PIIMatch(
                        pii_type=pii_type,
                        span=(prev.span[0], match.span[1]),
                        field=prev.field,
                        masked_value=self.mask(extended_text),
                    )
            else:
                merged.append(match)

        # Apply masks in reverse order to preserve positions
        result = text
        for match in reversed(merged):
            start, end = match.span
            result = result[:start] + match.masked_value + result[end:]
        return result

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

        redacted = copy.deepcopy(data)
        for field_name, matches in field_matches.items():
            # Simple top-level field redaction
            if field_name in redacted and isinstance(redacted[field_name], str):
                value = redacted[field_name]
                # Apply masks in reverse order to preserve positions
                for match in sorted(matches, key=lambda m: m.span[0], reverse=True):
                    start, end = match.span
                    value = value[:start] + match.masked_value + value[end:]
                redacted[field_name] = value
            elif "." in field_name or "[" in field_name:
                # Nested field: navigate into the dict to redact in-place
                parts = self._parse_field_path(field_name)
                self._redact_nested(redacted, parts, matches)

        return redacted, all_matches

    @staticmethod
    def _parse_field_path(field_name: str) -> list[str | int]:
        """Parse a field path like ``items[0].name`` into ``['items', 0, 'name']``."""
        parts: list[str | int] = []
        for segment in field_name.split("."):
            # Split "key[0]" → key, 0
            bracket = segment.find("[")
            if bracket == -1:
                parts.append(segment)
            else:
                if bracket > 0:
                    parts.append(segment[:bracket])
                # Extract all indices: e.g. "[0][1]" → 0, 1
                for idx_match in re.finditer(r"\[(\d+)\]", segment):
                    parts.append(int(idx_match.group(1)))
        return parts

    def _redact_nested(
        self,
        data: dict[str, Any],
        parts: list[str | int],
        matches: list[PIIMatch],
    ) -> None:
        """Redact a nested field located at parsed path *parts*."""
        obj: Any = data
        for part in parts[:-1]:
            if isinstance(part, int):
                if isinstance(obj, list) and part < len(obj):
                    obj = obj[part]
                else:
                    return
            elif isinstance(obj, dict) and part in obj:
                obj = obj[part]
            else:
                return

        key = parts[-1]
        if isinstance(key, int):
            if isinstance(obj, list) and key < len(obj) and isinstance(obj[key], str):
                value = obj[key]
                for match in sorted(matches, key=lambda m: m.span[0], reverse=True):
                    start, end = match.span
                    value = value[:start] + match.masked_value + value[end:]
                obj[key] = value
        elif isinstance(obj, dict) and key in obj and isinstance(obj[key], str):
            value = obj[key]
            for match in sorted(matches, key=lambda m: m.span[0], reverse=True):
                start, end = match.span
                value = value[:start] + match.masked_value + value[end:]
            obj[key] = value
