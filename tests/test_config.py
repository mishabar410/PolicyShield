"""Tests for policyshield.config (Prompt 09)."""

from __future__ import annotations

import textwrap
from pathlib import Path

from policyshield.config.loader import (
    PolicyShieldConfig,
    build_async_engine_from_config,
    build_engine_from_config,
    load_config,
)
from policyshield.core.models import ShieldMode


# ── helpers ────────────────────────────────────────────────────────

_VALID_YAML = textwrap.dedent("""\
    policyshield:
      version: 1
      mode: AUDIT
      fail_open: false
      rules:
        path: ./my_rules/
        watch: true
        watch_interval: 5.0
      pii:
        enabled: false
      sanitizer:
        enabled: true
        max_string_length: 5000
        blocked_patterns:
          - "<script>"
      trace:
        enabled: true
        output_dir: ./my_traces/
        batch_size: 50
        privacy_mode: true
      otel:
        enabled: true
        service_name: my-shield
        endpoint: http://otel:4317
      approval:
        backend: inmemory
        timeout: 60.0
""")

_RULES_YAML = textwrap.dedent("""\
    shield_name: test
    version: 1
    rules:
      - id: r1
        when:
          tool: test_tool
        then: ALLOW
""")


def _write(tmp_path: Path, name: str, content: str) -> Path:
    p = tmp_path / name
    p.write_text(content, encoding="utf-8")
    return p


# ── tests ──────────────────────────────────────────────────────────

def test_load_default(tmp_path, monkeypatch):
    """Default config without a file."""
    monkeypatch.chdir(tmp_path)
    # Ensure no env vars interfere
    monkeypatch.delenv("POLICYSHIELD_CONFIG", raising=False)
    cfg = load_config()
    assert cfg.mode == ShieldMode.ENFORCE
    assert cfg.fail_open is True
    assert cfg.rules_path == "./policies/"


def test_load_from_file(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    _write(tmp_path, "policyshield.yaml", _VALID_YAML)
    cfg = load_config(path=tmp_path / "policyshield.yaml")
    assert cfg.mode == ShieldMode.AUDIT
    assert cfg.fail_open is False
    assert cfg.rules_path == "./my_rules/"
    assert cfg.watch is True
    assert cfg.watch_interval == 5.0
    assert cfg.pii_enabled is False
    assert cfg.sanitizer_enabled is True
    assert cfg.sanitizer_max_string_length == 5000
    assert cfg.otel_enabled is True
    assert cfg.otel_service_name == "my-shield"
    assert cfg.approval_timeout == 60.0


def test_env_var_expansion(tmp_path, monkeypatch):
    monkeypatch.setenv("MY_SECRET", "s3cret")
    yaml_content = textwrap.dedent("""\
        policyshield:
          mode: ENFORCE
          approval:
            backend: webhook
            webhook:
              secret: ${MY_SECRET}
    """)
    cfg_path = _write(tmp_path, "cfg.yaml", yaml_content)
    cfg = load_config(path=cfg_path)
    assert cfg.approval_backend == "webhook"


def test_env_var_override(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    _write(tmp_path, "policyshield.yaml", _VALID_YAML)
    monkeypatch.setenv("POLICYSHIELD_MODE", "DISABLED")
    cfg = load_config(path=tmp_path / "policyshield.yaml")
    assert cfg.mode == ShieldMode.DISABLED


def test_invalid_mode(tmp_path):
    yaml_content = textwrap.dedent("""\
        policyshield:
          mode: INVALID_MODE
    """)
    cfg_path = _write(tmp_path, "bad.yaml", yaml_content)
    import pytest

    with pytest.raises(ValueError, match="Invalid mode"):
        load_config(path=cfg_path)


def test_missing_rules_path(tmp_path, monkeypatch):
    """Engine build fails if rules path doesn't exist."""
    monkeypatch.chdir(tmp_path)
    cfg = PolicyShieldConfig(rules_path=str(tmp_path / "nonexistent"))
    import pytest

    with pytest.raises(Exception):
        build_engine_from_config(cfg)


def test_build_engine(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    _write(rules_dir, "rules.yaml", _RULES_YAML)

    cfg = PolicyShieldConfig(
        rules_path=str(rules_dir),
        trace_enabled=False,
        sanitizer_enabled=True,
        sanitizer_blocked_patterns=["<script>"],
    )
    engine = build_engine_from_config(cfg)
    assert engine._mode == ShieldMode.ENFORCE
    assert engine._sanitizer is not None


def test_build_async_engine(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    _write(rules_dir, "rules.yaml", _RULES_YAML)

    cfg = PolicyShieldConfig(
        rules_path=str(rules_dir),
        trace_enabled=False,
    )
    engine = build_async_engine_from_config(cfg)
    from policyshield.shield.async_engine import AsyncShieldEngine

    assert isinstance(engine, AsyncShieldEngine)


def test_config_with_sanitizer(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    _write(tmp_path, "policyshield.yaml", _VALID_YAML)
    cfg = load_config(path=tmp_path / "policyshield.yaml")
    assert cfg.sanitizer_enabled is True
    assert cfg.sanitizer_max_string_length == 5000
    assert cfg.sanitizer_blocked_patterns == ["<script>"]


def test_config_with_otel(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    _write(tmp_path, "policyshield.yaml", _VALID_YAML)
    cfg = load_config(path=tmp_path / "policyshield.yaml")
    assert cfg.otel_enabled is True
    assert cfg.otel_endpoint == "http://otel:4317"


def test_cli_validate_valid(tmp_path, monkeypatch):
    from policyshield.cli.main import app

    monkeypatch.chdir(tmp_path)
    _write(tmp_path, "valid.yaml", _VALID_YAML)
    rc = app(["config", "validate", str(tmp_path / "valid.yaml")])
    assert rc == 0


def test_cli_validate_invalid(tmp_path, monkeypatch):
    from policyshield.cli.main import app

    monkeypatch.chdir(tmp_path)
    bad = textwrap.dedent("""\
        policyshield:
          mode: BADMODE
    """)
    _write(tmp_path, "bad.yaml", bad)
    rc = app(["config", "validate", str(tmp_path / "bad.yaml")])
    assert rc == 1


def test_cli_show(tmp_path, monkeypatch):
    from policyshield.cli.main import app

    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("POLICYSHIELD_CONFIG", raising=False)
    rc = app(["config", "show"])
    assert rc == 0


def test_cli_init(tmp_path, monkeypatch):
    from policyshield.cli.main import app

    monkeypatch.chdir(tmp_path)
    rc = app(["config", "init"])
    assert rc == 0
    assert (tmp_path / "policyshield.yaml").exists()
    content = (tmp_path / "policyshield.yaml").read_text()
    assert "policyshield:" in content
