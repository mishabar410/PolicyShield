"""Tests for CLI generate command — prompt 110."""

from unittest.mock import AsyncMock, patch


from policyshield.cli.main import app as cli_main


def test_generate_template_mode(tmp_path, capsys):
    output_file = tmp_path / "generated.yaml"
    exit_code = cli_main(
        [
            "generate",
            "--template",
            "--tools",
            "delete_file",
            "send_email",
            "read_file",
            "-o",
            str(output_file),
        ]
    )
    assert exit_code == 0
    content = output_file.read_text()
    assert "delete_file" in content
    assert "send_email" in content
    output = capsys.readouterr().out
    assert "saved" in output.lower() or "✅" in output


def test_generate_template_no_tools(capsys):
    exit_code = cli_main(["generate", "--template"])
    assert exit_code == 1
    output = capsys.readouterr().out
    assert "--tools" in output


def test_generate_template_safe_tools(capsys):
    exit_code = cli_main(
        [
            "generate",
            "--template",
            "--tools",
            "log_event",
            "format_text",
        ]
    )
    assert exit_code == 0
    output = capsys.readouterr().out
    assert "safe" in output.lower() or "No rule" in output


def test_generate_ai_no_description(capsys):
    exit_code = cli_main(["generate"])
    assert exit_code == 1
    output = capsys.readouterr().out
    assert "description" in output.lower()


def test_generate_template_to_stdout(capsys):
    exit_code = cli_main(
        [
            "generate",
            "--template",
            "--tools",
            "delete_file",
        ]
    )
    assert exit_code == 0
    output = capsys.readouterr().out
    assert "version:" in output
    assert "delete_file" in output


def test_generate_ai_mode(tmp_path, capsys):
    """Test AI generation with mocked LLM."""
    mock_yaml = """\
version: "1"
default_verdict: allow
rules:
  - id: block-delete
    when:
      tool: delete_file
    then: block
    message: "Blocked by AI"
"""
    output_file = tmp_path / "ai_rules.yaml"

    with patch("policyshield.ai.generator._call_openai", new_callable=AsyncMock) as mock:
        mock.return_value = f"```yaml\n{mock_yaml}```"
        exit_code = cli_main(
            [
                "generate",
                "Block all file deletions",
                "--tools",
                "delete_file",
                "-o",
                str(output_file),
            ]
        )
        assert exit_code == 0
        content = output_file.read_text()
        assert "delete_file" in content
