"""Tests for chain rule parsing — prompt 105."""

from policyshield.core.parser import parse_rules_from_string
from policyshield.core.models import ChainCondition


CHAIN_YAML = """\
shield_name: test
version: 1
rules:
  - id: exfil-after-read
    description: Block send_email if read_file was called recently
    when:
      tool: send_email
      chain:
        - tool: read_file
          within_seconds: 300
    then: BLOCK
    message: "Possible exfiltration: read_file → send_email"
"""


def test_chain_parsed():
    rs = parse_rules_from_string(CHAIN_YAML)
    rule = rs.rules[0]
    assert rule.id == "exfil-after-read"
    assert rule.chain is not None
    assert len(rule.chain) == 1
    assert rule.chain[0]["tool"] == "read_file"
    assert rule.chain[0]["within_seconds"] == 300


def test_chain_condition_model():
    cond = ChainCondition(tool="read_file", within_seconds=60, min_count=2, verdict="ALLOW")
    assert cond.tool == "read_file"
    assert cond.within_seconds == 60
    assert cond.min_count == 2
    assert cond.verdict == "ALLOW"


def test_chain_condition_defaults():
    cond = ChainCondition(tool="x")
    assert cond.within_seconds == 300.0
    assert cond.min_count == 1
    assert cond.verdict is None


def test_multi_step_chain():
    yaml_text = """\
shield_name: test
version: 1
rules:
  - id: multi-step
    when:
      tool: send_email
      chain:
        - tool: read_file
          within_seconds: 60
        - tool: query_db
          within_seconds: 120
          min_count: 2
    then: BLOCK
"""
    rs = parse_rules_from_string(yaml_text)
    rule = rs.rules[0]
    assert len(rule.chain) == 2
    assert rule.chain[1]["min_count"] == 2


def test_no_chain():
    yaml_text = """\
shield_name: test
version: 1
rules:
  - id: simple
    when:
      tool: read_file
    then: ALLOW
"""
    rs = parse_rules_from_string(yaml_text)
    assert rs.rules[0].chain is None


def test_chain_with_verdict_filter():
    yaml_text = """\
shield_name: test
version: 1
rules:
  - id: blocked-then-retry
    when:
      tool: send_email
      chain:
        - tool: send_email
          verdict: BLOCK
          within_seconds: 60
    then: BLOCK
    message: "Repeated blocked attempt"
"""
    rs = parse_rules_from_string(yaml_text)
    cond = rs.rules[0].chain[0]
    assert cond["verdict"] == "BLOCK"
