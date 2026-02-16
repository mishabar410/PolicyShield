"""Tests for rule templates and tool classifier — prompt 108."""

import yaml

from policyshield.ai.templates import (
    RULE_TEMPLATES,
    DangerLevel,
    classify_tool,
    classify_tools,
    recommend_rules,
)


def test_classify_critical():
    assert classify_tool("delete_file") == DangerLevel.CRITICAL
    assert classify_tool("exec_command") == DangerLevel.CRITICAL
    assert classify_tool("deploy_to_prod") == DangerLevel.CRITICAL


def test_classify_dangerous():
    assert classify_tool("send_email") == DangerLevel.DANGEROUS
    assert classify_tool("write_file") == DangerLevel.DANGEROUS
    assert classify_tool("http_request") == DangerLevel.DANGEROUS


def test_classify_moderate():
    assert classify_tool("read_file") == DangerLevel.MODERATE
    assert classify_tool("query_database") == DangerLevel.MODERATE


def test_classify_safe():
    assert classify_tool("log_event") == DangerLevel.SAFE
    assert classify_tool("format_text") == DangerLevel.SAFE
    assert classify_tool("health") == DangerLevel.SAFE


def test_classify_unknown():
    assert classify_tool("my_custom_tool_xyz") == DangerLevel.MODERATE


def test_classify_tools():
    result = classify_tools(["read_file", "delete_file", "log_event"])
    assert result["read_file"] == DangerLevel.MODERATE
    assert result["delete_file"] == DangerLevel.CRITICAL
    assert result["log_event"] == DangerLevel.SAFE


def test_recommend_rules():
    recs = recommend_rules(["delete_file", "send_email", "read_file", "log_event"])
    assert len(recs) == 3  # log_event is safe → no recommendation
    critical_rec = next(r for r in recs if r.tool_name == "delete_file")
    assert critical_rec.suggested_verdict == "approve"
    assert "approve" in critical_rec.yaml_snippet


def test_templates_valid_yaml():
    """All templates should produce valid YAML when formatted."""
    for key, template in RULE_TEMPLATES.items():
        formatted = template.format(
            tool_name="test_tool",
            outgoing_tool="send_email",
            sensitive_tool="read_database",
        )
        parsed = yaml.safe_load(formatted)
        assert parsed is not None, f"Template '{key}' produced invalid YAML"
