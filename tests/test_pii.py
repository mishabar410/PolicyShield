"""Tests for PII detector."""

import pytest

from policyshield.core.models import PIIType
from policyshield.shield.pii import PIIDetector, PIIPattern, _inn_check, _luhn_check, _snils_check

import re


class TestLuhnCheck:
    def test_valid_visa(self):
        assert _luhn_check("4111111111111111") is True

    def test_invalid_number(self):
        assert _luhn_check("1234567890123456") is False

    def test_too_short(self):
        assert _luhn_check("123") is False


class TestInnCheck:
    """Tests for INN checksum validation."""

    def test_valid_inn_10(self):
        assert _inn_check("7707083893") is True

    def test_invalid_inn_10(self):
        assert _inn_check("7707083890") is False

    def test_valid_inn_12(self):
        assert _inn_check("500100732259") is True

    def test_invalid_inn_12(self):
        assert _inn_check("500100732250") is False

    def test_wrong_length(self):
        assert _inn_check("12345") is False


class TestSnilsCheck:
    """Tests for SNILS checksum validation."""

    def test_valid_snils(self):
        assert _snils_check("112-233-445 95") is True

    def test_invalid_snils(self):
        assert _snils_check("112-233-445 00") is False


class TestPIIDetector:
    @pytest.fixture
    def detector(self):
        return PIIDetector()

    def test_detect_email(self, detector):
        matches = detector.scan("Contact john@example.com for info", "field")
        assert len(matches) >= 1
        email_matches = [m for m in matches if m.pii_type == PIIType.EMAIL]
        assert len(email_matches) == 1
        assert email_matches[0].field == "field"

    def test_detect_ssn(self, detector):
        matches = detector.scan("SSN: 123-45-6789", "data")
        ssn_matches = [m for m in matches if m.pii_type == PIIType.SSN]
        assert len(ssn_matches) == 1

    def test_detect_credit_card(self, detector):
        matches = detector.scan("Card: 4111 1111 1111 1111", "payment")
        cc_matches = [m for m in matches if m.pii_type == PIIType.CREDIT_CARD]
        assert len(cc_matches) == 1

    def test_reject_invalid_credit_card(self, detector):
        matches = detector.scan("Number: 1234 5678 9012 3456", "data")
        cc_matches = [m for m in matches if m.pii_type == PIIType.CREDIT_CARD]
        assert len(cc_matches) == 0

    def test_detect_ip_address(self, detector):
        matches = detector.scan("Server at 192.168.1.100", "log")
        ip_matches = [m for m in matches if m.pii_type == PIIType.IP_ADDRESS]
        assert len(ip_matches) == 1

    def test_no_matches(self, detector):
        matches = detector.scan("Hello world, nothing to see here.", "text")
        # Filter out any false positives from broad patterns
        real_matches = [m for m in matches if m.pii_type in (PIIType.EMAIL, PIIType.SSN, PIIType.CREDIT_CARD)]
        assert len(real_matches) == 0

    def test_scan_dict(self, detector):
        data = {
            "name": "John",
            "email": "john@example.com",
            "nested": {"ssn": "123-45-6789"},
        }
        matches = detector.scan_dict(data)
        assert len(matches) >= 2
        fields = {m.field for m in matches}
        assert "email" in fields

    def test_scan_dict_with_list(self, detector):
        data = {"contacts": ["john@example.com", "jane@example.com"]}
        matches = detector.scan_dict(data)
        email_matches = [m for m in matches if m.pii_type == PIIType.EMAIL]
        assert len(email_matches) == 2

    def test_mask(self):
        assert PIIDetector.mask("john@example.com") == "jo************om"

    def test_mask_short(self):
        assert PIIDetector.mask("ab", keep_edges=2) == "**"

    def test_custom_patterns(self):
        custom = PIIPattern(
            pii_type=PIIType.CUSTOM,
            pattern=re.compile(r"ACME-\d{6}"),
            label="internal_id",
        )
        detector = PIIDetector(custom_patterns=[custom])
        matches = detector.scan("ID: ACME-123456", "id_field")
        custom_matches = [m for m in matches if m.pii_type == PIIType.CUSTOM]
        assert len(custom_matches) == 1

    def test_redact_dict(self, detector):
        data = {"email": "john@example.com", "name": "John"}
        redacted, matches = detector.redact_dict(data)
        assert redacted["name"] == "John"
        assert "john@example.com" not in redacted["email"]
        assert len(matches) >= 1

    def test_redact_dict_no_pii(self, detector):
        data = {"name": "John", "age": "30"}
        redacted, matches = detector.redact_dict(data)
        assert redacted == data
        assert len(matches) == 0

    # --- RU-specific PII tests ---

    def test_detect_inn_10_valid(self, detector):
        """Detect a valid 10-digit INN."""
        matches = detector.scan("INN: 7707083893", "data")
        inn_matches = [m for m in matches if m.pii_type == PIIType.INN]
        assert len(inn_matches) == 1

    def test_reject_inn_10_invalid(self, detector):
        """Reject an INN with bad checksum."""
        matches = detector.scan("INN: 7707083890", "data")
        inn_matches = [m for m in matches if m.pii_type == PIIType.INN]
        assert len(inn_matches) == 0

    def test_detect_inn_12_valid(self, detector):
        """Detect a valid 12-digit INN."""
        matches = detector.scan("ИНН: 500100732259", "data")
        inn_matches = [m for m in matches if m.pii_type == PIIType.INN]
        assert len(inn_matches) == 1

    def test_detect_snils_valid(self, detector):
        """Detect a valid SNILS with correct checksum."""
        matches = detector.scan("СНИЛС: 112-233-445 95", "data")
        snils_matches = [m for m in matches if m.pii_type == PIIType.SNILS]
        assert len(snils_matches) == 1

    def test_reject_snils_invalid(self, detector):
        """Reject a SNILS with wrong checksum."""
        matches = detector.scan("СНИЛС: 112-233-445 00", "data")
        snils_matches = [m for m in matches if m.pii_type == PIIType.SNILS]
        assert len(snils_matches) == 0

    def test_detect_ru_phone_plus7(self, detector):
        """Detect a Russian phone: +7 (999) 123-45-67."""
        matches = detector.scan("Тел: +7 (999) 123-45-67", "data")
        ru_phone = [m for m in matches if m.pii_type == PIIType.RU_PHONE]
        assert len(ru_phone) == 1

    def test_detect_ru_phone_8(self, detector):
        """Detect a Russian phone starting with 8."""
        matches = detector.scan("Тел: 8(999)1234567", "data")
        ru_phone = [m for m in matches if m.pii_type == PIIType.RU_PHONE]
        assert len(ru_phone) == 1

    def test_detect_ru_passport(self, detector):
        """Detect a Russian passport number."""
        matches = detector.scan("Паспорт: 45 06 123456", "data")
        rp = [m for m in matches if m.pii_type == PIIType.RU_PASSPORT]
        assert len(rp) == 1

    def test_detect_multiple_ru_pii(self, detector):
        """Detect multiple RU PII types in one text."""
        text = "ИНН 7707083893, тел +7(999)123-45-67"
        matches = detector.scan(text, "data")
        types = {m.pii_type for m in matches}
        assert PIIType.INN in types
        assert PIIType.RU_PHONE in types

