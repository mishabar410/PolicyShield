"""Tests for PII detector."""

import pytest

from policyshield.core.models import PIIType
from policyshield.shield.pii import PIIDetector, PIIPattern, _luhn_check

import re


class TestLuhnCheck:
    def test_valid_visa(self):
        assert _luhn_check("4111111111111111") is True

    def test_invalid_number(self):
        assert _luhn_check("1234567890123456") is False

    def test_too_short(self):
        assert _luhn_check("123") is False


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
