"""Tests for policyshield.shield.detectors (Prompt 201)."""

from __future__ import annotations

import pytest

from policyshield.shield.detectors import (
    ALL_DETECTORS,
    Detector,
    DetectorMatch,
    get_detector,
    get_detectors,
    scan_all,
)


# ── Registry tests ────────────────────────────────────────────────


def test_all_detectors_populated():
    assert len(ALL_DETECTORS) == 6
    for name in ("path_traversal", "shell_injection", "sql_injection", "ssrf", "url_schemes"):
        assert name in ALL_DETECTORS


def test_get_detector_exists():
    det = get_detector("sql_injection")
    assert isinstance(det, Detector)
    assert det.name == "sql_injection"


def test_get_detector_missing():
    with pytest.raises(KeyError):
        get_detector("nonexistent")


def test_get_detectors_list():
    dets = get_detectors(["path_traversal", "ssrf"])
    assert len(dets) == 2
    assert dets[0].name == "path_traversal"
    assert dets[1].name == "ssrf"


def test_get_detectors_bad_name():
    with pytest.raises(KeyError):
        get_detectors(["path_traversal", "does_not_exist"])


# ── PATH_TRAVERSAL ────────────────────────────────────────────────


class TestPathTraversal:
    det = get_detector("path_traversal")

    @pytest.mark.parametrize(
        "payload",
        [
            "../../etc/passwd",
            "..\\..\\windows\\system32",
            "../../../../etc/shadow",
            "%2e%2e/%2e%2e/etc/passwd",
        ],
    )
    def test_detects_attacks(self, payload: str):
        matches = self.det.scan(payload)
        assert len(matches) >= 1
        assert all(m.detector_name == "path_traversal" for m in matches)

    @pytest.mark.parametrize(
        "clean",
        [
            "/home/user/file.txt",
            "relative/path/to/file",
            "https://example.com/page",
        ],
    )
    def test_clean_passes(self, clean: str):
        assert self.det.scan(clean) == []


# ── SHELL_INJECTION ───────────────────────────────────────────────


class TestShellInjection:
    det = get_detector("shell_injection")

    @pytest.mark.parametrize(
        "payload",
        [
            "; rm -rf /",
            "; cat /etc/passwd",
            "| bash",
            "`whoami`",
            "$(id)",
            "> /etc/crontab",
        ],
    )
    def test_detects_attacks(self, payload: str):
        matches = self.det.scan(payload)
        assert len(matches) >= 1

    @pytest.mark.parametrize(
        "clean",
        [
            "hello world",
            "ls -la",
            "echo 'safe'",
        ],
    )
    def test_clean_passes(self, clean: str):
        assert self.det.scan(clean) == []


# ── SQL_INJECTION ─────────────────────────────────────────────────


class TestSQLInjection:
    det = get_detector("sql_injection")

    @pytest.mark.parametrize(
        "payload",
        [
            "' OR '1'='1",
            "' AND 1=1",
            "UNION SELECT * FROM users",
            "UNION ALL SELECT password FROM users",
            "; DROP TABLE users",
            "'; --",
        ],
    )
    def test_detects_attacks(self, payload: str):
        matches = self.det.scan(payload)
        assert len(matches) >= 1

    @pytest.mark.parametrize(
        "clean",
        [
            "SELECT name FROM products",
            "normal search query",
            "it's a beautiful day",
        ],
    )
    def test_clean_passes(self, clean: str):
        assert self.det.scan(clean) == []


# ── SSRF ──────────────────────────────────────────────────────────


class TestSSRF:
    det = get_detector("ssrf")

    @pytest.mark.parametrize(
        "payload",
        [
            "http://127.0.0.1/admin",
            "http://localhost:8080/secret",
            "http://10.0.0.1/internal",
            "http://172.16.0.1/api",
            "http://192.168.1.1/config",
            "http://169.254.169.254/latest/meta-data",
            "http://[::1]/admin",
        ],
    )
    def test_detects_attacks(self, payload: str):
        matches = self.det.scan(payload)
        assert len(matches) >= 1

    @pytest.mark.parametrize(
        "clean",
        [
            "https://example.com/api",
            "https://google.com",
            "http://myapp.internal.company.com",
        ],
    )
    def test_clean_passes(self, clean: str):
        assert self.det.scan(clean) == []


# ── URL_SCHEMES ───────────────────────────────────────────────────


class TestURLSchemes:
    det = get_detector("url_schemes")

    @pytest.mark.parametrize(
        "payload",
        [
            "file:///etc/passwd",
            "data:text/html,<script>alert(1)</script>",
            "javascript:alert(1)",
            "vbscript:MsgBox",
            "gopher://evil.com",
        ],
    )
    def test_detects_attacks(self, payload: str):
        matches = self.det.scan(payload)
        assert len(matches) >= 1

    @pytest.mark.parametrize(
        "clean",
        [
            "https://example.com",
            "http://safe.org",
            "ftp://files.example.com",
        ],
    )
    def test_clean_passes(self, clean: str):
        assert self.det.scan(clean) == []


# ── scan_all ──────────────────────────────────────────────────────


def test_scan_all_default_detectors():
    text = "http://127.0.0.1/admin ; rm -rf /"
    matches = scan_all(text)
    detector_names = {m.detector_name for m in matches}
    assert "ssrf" in detector_names
    assert "shell_injection" in detector_names


def test_scan_all_specific_detectors():
    dets = get_detectors(["sql_injection"])
    matches = scan_all("' OR '1'='1", detectors=dets)
    assert len(matches) >= 1
    assert all(m.detector_name == "sql_injection" for m in matches)


def test_scan_all_clean():
    matches = scan_all("perfectly normal text")
    assert matches == []


def test_detector_match_fields():
    det = get_detector("ssrf")
    matches = det.scan("visit http://127.0.0.1/secret now")
    assert len(matches) >= 1
    m = matches[0]
    assert isinstance(m, DetectorMatch)
    assert m.detector_name == "ssrf"
    assert "127.0.0.1" in m.matched_text
    assert m.start >= 0
    assert m.end > m.start
