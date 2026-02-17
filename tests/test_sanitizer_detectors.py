"""Tests for sanitizer + built-in detector integration (Prompt 202)."""

from __future__ import annotations

from policyshield.shield.sanitizer import InputSanitizer, SanitizerConfig


# ── helpers ────────────────────────────────────────────────────────


def _make(*, detectors: list[str] | None = None, patterns: list[str] | None = None) -> InputSanitizer:
    return InputSanitizer(
        SanitizerConfig(
            builtin_detectors=detectors,
            blocked_patterns=patterns,
        )
    )


# ── tests ──────────────────────────────────────────────────────────


class TestDetectorIntegration:
    """Built-in detectors integrated into the sanitizer."""

    def test_path_traversal_blocked(self):
        san = _make(detectors=["path_traversal"])
        result = san.sanitize({"path": "../../etc/passwd"})
        assert result.rejected
        assert "path_traversal" in result.rejection_reason

    def test_shell_injection_blocked(self):
        san = _make(detectors=["shell_injection"])
        result = san.sanitize({"cmd": "; rm -rf /"})
        assert result.rejected
        assert "shell_injection" in result.rejection_reason

    def test_sql_injection_blocked(self):
        san = _make(detectors=["sql_injection"])
        result = san.sanitize({"query": "' OR '1'='1"})
        assert result.rejected
        assert "sql_injection" in result.rejection_reason

    def test_ssrf_blocked(self):
        san = _make(detectors=["ssrf"])
        result = san.sanitize({"url": "http://169.254.169.254/latest/meta-data"})
        assert result.rejected
        assert "ssrf" in result.rejection_reason

    def test_url_schemes_blocked(self):
        san = _make(detectors=["url_schemes"])
        result = san.sanitize({"link": "file:///etc/passwd"})
        assert result.rejected
        assert "url_schemes" in result.rejection_reason

    def test_clean_input_passes(self):
        san = _make(detectors=["path_traversal", "shell_injection", "sql_injection", "ssrf", "url_schemes"])
        result = san.sanitize({"msg": "Hello, World!", "url": "https://example.com"})
        assert not result.rejected

    def test_no_detectors_attack_passes(self):
        """Without detectors enabled, the attack should pass through sanitizer."""
        san = _make()
        result = san.sanitize({"path": "../../etc/passwd"})
        assert not result.rejected

    def test_rejection_reason_includes_matched_text(self):
        san = _make(detectors=["ssrf"])
        result = san.sanitize({"url": "http://127.0.0.1/admin"})
        assert result.rejected
        assert "127.0.0.1" in result.rejection_reason


class TestDetectorPriority:
    """Detectors run before blocked_patterns."""

    def test_detector_fires_before_pattern(self):
        """If input triggers both a detector and a blocked pattern,
        the detector's rejection reason should win."""
        san = _make(
            detectors=["shell_injection"],
            patterns=["rm"],
        )
        result = san.sanitize({"cmd": "; rm -rf /"})
        assert result.rejected
        assert "Built-in detector" in result.rejection_reason
        assert "Blocked pattern" not in result.rejection_reason

    def test_pattern_still_works_without_detector(self):
        san = _make(patterns=["badword"])
        result = san.sanitize({"text": "contains badword here"})
        assert result.rejected
        assert "Blocked pattern" in result.rejection_reason


class TestNestedArgs:
    """Detectors scan flattened nested structures."""

    def test_nested_dict(self):
        san = _make(detectors=["path_traversal"])
        result = san.sanitize({"outer": {"inner": "../../etc/passwd"}})
        assert result.rejected

    def test_nested_list(self):
        san = _make(detectors=["sql_injection"])
        result = san.sanitize({"queries": ["safe query", "' OR '1'='1"]})
        assert result.rejected
