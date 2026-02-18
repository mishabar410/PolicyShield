"""Tests for security & data protection hardening — prompts 321-326."""

from __future__ import annotations

import time

from policyshield.core.models import Verdict
from policyshield.server.app import create_app
from policyshield.shield.async_engine import AsyncShieldEngine
from policyshield.trace.recorder import TraceRecorder
from starlette.testclient import TestClient


def _make_client(tmp_path, monkeypatch=None, **env):
    rules = tmp_path / "rules.yaml"
    rules.write_text("shield_name: test\nversion: '1'\nrules: []\n")
    engine = AsyncShieldEngine(rules=rules)
    if monkeypatch:
        for k, v in env.items():
            monkeypatch.setenv(k, v)
    app = create_app(engine)
    return TestClient(app), engine


# ── Prompt 321: Secret Detection ─────────────────────────────────


class TestSecretDetection:
    def test_aws_key_detected(self):
        from policyshield.shield.detectors import SECRET_DETECTION

        m = SECRET_DETECTION.scan("my key is AKIAIOSFODNN7EXAMPLE")
        assert len(m) > 0
        assert "secret" in m[0].detector_name

    def test_openai_key_detected(self):
        from policyshield.shield.detectors import SECRET_DETECTION

        m = SECRET_DETECTION.scan("token: sk-abcdefghij1234567890abcdefghij1234567890")
        assert len(m) > 0

    def test_safe_value_no_threats(self):
        from policyshield.shield.detectors import SECRET_DETECTION

        m = SECRET_DETECTION.scan("Hello, world!")
        assert len(m) == 0

    def test_jwt_detected(self):
        from policyshield.shield.detectors import SECRET_DETECTION

        jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
        m = SECRET_DETECTION.scan(jwt)
        assert len(m) > 0

    def test_github_pat_detected(self):
        from policyshield.shield.detectors import SECRET_DETECTION

        m = SECRET_DETECTION.scan("ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij")
        assert len(m) > 0

    def test_scan_all_includes_secrets(self):
        from policyshield.shield.detectors import scan_all

        matches = scan_all("my key AKIAIOSFODNN7EXAMPLE here")
        names = [m.detector_name for m in matches]
        assert "secret_detection" in names


# ── Prompt 322: Admin Token Separation ───────────────────────────


class TestAdminTokenSeparation:
    def test_check_uses_api_token(self, tmp_path, monkeypatch):
        monkeypatch.setenv("POLICYSHIELD_API_TOKEN", "api-secret")
        monkeypatch.setenv("POLICYSHIELD_ADMIN_TOKEN", "admin-secret")
        client, _ = _make_client(tmp_path)
        resp = client.post(
            "/api/v1/check",
            json={"tool_name": "test"},
            headers={"Authorization": "Bearer api-secret"},
        )
        assert resp.status_code != 403

    def test_reload_rejects_api_token(self, tmp_path, monkeypatch):
        monkeypatch.setenv("POLICYSHIELD_API_TOKEN", "api-secret")
        monkeypatch.setenv("POLICYSHIELD_ADMIN_TOKEN", "admin-secret")
        client, _ = _make_client(tmp_path)
        resp = client.post(
            "/api/v1/reload",
            headers={"Authorization": "Bearer api-secret"},
        )
        assert resp.status_code == 403

    def test_reload_accepts_admin_token(self, tmp_path, monkeypatch):
        monkeypatch.setenv("POLICYSHIELD_ADMIN_TOKEN", "admin-secret")
        client, _ = _make_client(tmp_path)
        resp = client.post(
            "/api/v1/reload",
            headers={"Authorization": "Bearer admin-secret"},
        )
        assert resp.status_code != 403

    def test_fallback_to_api_token_when_no_admin(self, tmp_path, monkeypatch):
        monkeypatch.setenv("POLICYSHIELD_API_TOKEN", "api-secret")
        # No ADMIN_TOKEN set
        monkeypatch.delenv("POLICYSHIELD_ADMIN_TOKEN", raising=False)
        client, _ = _make_client(tmp_path)
        resp = client.post(
            "/api/v1/reload",
            headers={"Authorization": "Bearer api-secret"},
        )
        assert resp.status_code != 403


# ── Prompt 323: Error Scrub ──────────────────────────────────────


class TestSensitiveDataInErrors:
    def test_500_hides_stack_trace(self, tmp_path, monkeypatch):
        monkeypatch.delenv("POLICYSHIELD_DEBUG", raising=False)
        client, _ = _make_client(tmp_path)
        # Cause an internal error by sending invalid content
        resp = client.post(
            "/api/v1/check",
            content="broken",
            headers={"content-type": "application/json"},
        )
        body = resp.json()
        assert "Traceback" not in str(body)
        assert "debug" not in body

    def test_debug_mode_shows_details(self, tmp_path, monkeypatch):
        monkeypatch.setenv("POLICYSHIELD_DEBUG", "true")
        client, _ = _make_client(tmp_path)
        resp = client.post(
            "/api/v1/check",
            content="broken",
            headers={"content-type": "application/json"},
        )
        body = resp.json()
        assert "debug" in body


# ── Prompt 324: Log Filter ───────────────────────────────────────


class TestSensitiveDataInLogs:
    def test_safe_args_summary_hides_values(self):
        from policyshield.server.log_utils import safe_args_summary

        result = safe_args_summary({"password": "secret123", "user": "admin"})
        assert "secret123" not in result
        assert "password" in result

    def test_safe_args_summary_truncates(self):
        from policyshield.server.log_utils import safe_args_summary

        args = {f"key{i}": f"val{i}" for i in range(20)}
        result = safe_args_summary(args, max_keys=3)
        assert "+17 more" in result

    def test_safe_args_summary_empty(self):
        from policyshield.server.log_utils import safe_args_summary

        result = safe_args_summary({})
        assert result == "keys=[]"


# ── Prompt 325: Trace File Permissions ───────────────────────────


class TestTraceFilePermissions:
    def test_new_trace_file_is_600(self, tmp_path):
        recorder = TraceRecorder(output_dir=tmp_path)
        recorder.record("s1", "test", Verdict.BLOCK)
        recorder.flush()
        files = list(tmp_path.glob("*.jsonl"))
        assert len(files) == 1
        perms = files[0].stat().st_mode & 0o777
        assert perms == 0o600

    def test_open_file_fixes_permissions(self, tmp_path):
        trace_file = tmp_path / "trace.jsonl"
        trace_file.touch(mode=0o644)
        assert (trace_file.stat().st_mode & 0o777) == 0o644
        recorder = TraceRecorder(output_dir=tmp_path)
        recorder._open_file(trace_file).close()
        assert (trace_file.stat().st_mode & 0o777) == 0o600


# ── Prompt 326: Rate Limiting ────────────────────────────────────


class TestRateLimiting:
    def test_within_limit_allowed(self):
        from policyshield.server.rate_limiter import InMemoryRateLimiter

        rl = InMemoryRateLimiter(max_requests=3, window_seconds=60)
        assert rl.is_allowed("ip1") is True
        assert rl.is_allowed("ip1") is True
        assert rl.is_allowed("ip1") is True

    def test_over_limit_rejected(self):
        from policyshield.server.rate_limiter import InMemoryRateLimiter

        rl = InMemoryRateLimiter(max_requests=2, window_seconds=60)
        rl.is_allowed("ip1")
        rl.is_allowed("ip1")
        assert rl.is_allowed("ip1") is False

    def test_different_keys_independent(self):
        from policyshield.server.rate_limiter import InMemoryRateLimiter

        rl = InMemoryRateLimiter(max_requests=1, window_seconds=60)
        rl.is_allowed("ip1")
        assert rl.is_allowed("ip2") is True

    def test_window_resets(self):
        from policyshield.server.rate_limiter import InMemoryRateLimiter

        rl = InMemoryRateLimiter(max_requests=1, window_seconds=0.1)
        rl.is_allowed("ip1")
        time.sleep(0.15)
        assert rl.is_allowed("ip1") is True
