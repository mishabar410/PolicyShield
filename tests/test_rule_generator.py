"""Tests for LLM rule generator — prompt 109."""

from unittest.mock import AsyncMock, patch

import pytest

from policyshield.ai.generator import (
    _build_examples,
    _extract_yaml,
    _validate_yaml,
    generate_rules,
)


def test_extract_yaml_from_code_block():
    text = """Here is the YAML:
```yaml
version: "1"
default_verdict: allow
rules:
  - id: test
    when:
      tool: read_file
    then: allow
```
"""
    result = _extract_yaml(text)
    assert result.startswith("version:")
    assert "rules:" in result


def test_extract_yaml_plain():
    text = 'version: "1"\ndefault_verdict: allow\nrules: []'
    result = _extract_yaml(text)
    assert result == text


def test_validate_yaml_valid():
    yaml_text = """\
version: "1"
default_verdict: allow
rules:
  - id: test
    when:
      tool: read_file
    then: allow
"""
    ok, error = _validate_yaml(yaml_text)
    assert ok
    assert error is None


def test_validate_yaml_invalid():
    ok, error = _validate_yaml("not: valid: yaml: {{{}")
    assert not ok
    assert error is not None


def test_validate_yaml_no_rules():
    yaml_text = """\
version: "1"
default_verdict: allow
rules: []
"""
    ok, error = _validate_yaml(yaml_text)
    assert not ok
    assert "No rules" in error


def test_build_examples_with_tools():
    examples = _build_examples(["delete_file", "read_file"])
    assert "delete_file" in examples or "Recommended" in examples


def test_build_examples_without_tools():
    examples = _build_examples(None)
    assert "example_tool" in examples


@pytest.mark.asyncio
async def test_generate_rules_openai():
    mock_yaml = """\
version: "1"
default_verdict: allow
rules:
  - id: block-delete
    when:
      tool: delete_file
    then: block
    message: "Delete blocked"
"""
    with patch("policyshield.ai.generator._call_openai", new_callable=AsyncMock) as mock_call:
        mock_call.return_value = f"```yaml\n{mock_yaml}```"
        result = await generate_rules("Block all file deletions", provider="openai")
        assert result.validation_ok
        assert "delete" in result.yaml_text.lower()


@pytest.mark.asyncio
async def test_generate_rules_retry_on_invalid():
    """Test retry logic when first response is invalid."""
    bad_yaml = "not valid yaml {{{"
    good_yaml = """\
version: "1"
default_verdict: allow
rules:
  - id: test
    when:
      tool: test
    then: allow
"""
    with patch("policyshield.ai.generator._call_openai", new_callable=AsyncMock) as mock_call:
        mock_call.side_effect = [bad_yaml, good_yaml]
        result = await generate_rules("Test rules", provider="openai")
        assert result.validation_ok
        assert mock_call.call_count == 2  # Retried once


@pytest.mark.asyncio
async def test_generate_rules_unsupported_provider():
    with pytest.raises(ValueError, match="Unsupported"):
        await generate_rules("Test", provider="unknown")
