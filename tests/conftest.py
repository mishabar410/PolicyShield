# PolicyShield test configuration

import pytest


@pytest.fixture
def server_rules(tmp_path):
    """Shared rules fixture for server tests."""
    rules_yaml = tmp_path / "rules.yaml"
    rules_yaml.write_text("""\
shield_name: test
version: 1
default_verdict: allow
rules:
  - id: block-rm
    description: Block rm -rf
    when:
      tool: exec
      args:
        command: { contains: "rm -rf" }
    then: BLOCK
    message: blocked
  - id: redact-pii
    description: Redact PII
    when:
      tool: "*"
      args:
        _any: { has_pii: true }
    then: REDACT
""")
    return rules_yaml


@pytest.fixture
def server_client(server_rules):
    """TestClient wired to a ShieldEngine with standard rules."""
    fastapi = pytest.importorskip("fastapi", reason="fastapi not installed")  # noqa: F841

    from fastapi.testclient import TestClient

    from policyshield.server.app import create_app
    from policyshield.shield.engine import ShieldEngine

    engine = ShieldEngine(rules=server_rules)
    app = create_app(engine)
    return TestClient(app)
