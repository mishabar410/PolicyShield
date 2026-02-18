"""Tests for TLS server CLI support."""

from __future__ import annotations

from policyshield.cli.main import app


class TestTLSServer:
    def test_tls_partial_args_cert_only(self, tmp_path):
        """Providing only --tls-cert without --tls-key should fail."""
        rules = tmp_path / "rules.yaml"
        rules.write_text("shield_name: test\nversion: 1\nrules: []\n")
        result = app(["server", "--rules", str(rules), "--tls-cert", "cert.pem"])
        assert result == 1

    def test_tls_partial_args_key_only(self, tmp_path):
        """Providing only --tls-key without --tls-cert should fail."""
        rules = tmp_path / "rules.yaml"
        rules.write_text("shield_name: test\nversion: 1\nrules: []\n")
        result = app(["server", "--rules", str(rules), "--tls-key", "key.pem"])
        assert result == 1

    def test_tls_cert_not_found(self, tmp_path):
        """Non-existent cert file should fail."""
        rules = tmp_path / "rules.yaml"
        rules.write_text("shield_name: test\nversion: 1\nrules: []\n")
        result = app(
            [
                "server",
                "--rules",
                str(rules),
                "--tls-cert",
                "/nonexistent.pem",
                "--tls-key",
                "/nonexistent.key",
            ]
        )
        assert result == 1

    def test_tls_key_not_found(self, tmp_path):
        """Non-existent key file should fail (cert exists)."""
        rules = tmp_path / "rules.yaml"
        rules.write_text("shield_name: test\nversion: 1\nrules: []\n")
        cert = tmp_path / "cert.pem"
        cert.write_text("fake-cert")
        result = app(
            [
                "server",
                "--rules",
                str(rules),
                "--tls-cert",
                str(cert),
                "--tls-key",
                "/nonexistent.key",
            ]
        )
        assert result == 1
