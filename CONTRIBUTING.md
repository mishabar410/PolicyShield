# Contributing to PolicyShield

Thanks for your interest in PolicyShield! Here's how to get started.

## Setup

```bash
git clone https://github.com/policyshield/policyshield.git
cd policyshield
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev,langchain]"
```

## Development Workflow

1. **Create a branch** from `main`
2. **Write code + tests** — every feature must include tests
3. **Lint**: `ruff check policyshield/ tests/`
4. **Test**: `pytest tests/ -v`
5. **Open a PR** against `main`

## Code Style

- Python 3.10+ with type hints
- Formatted with `ruff`
- All public APIs must have docstrings

## Testing

```bash
# Run all tests
pytest tests/ -v

# With coverage
pytest tests/ --cov=policyshield --cov-report=term-missing

# Target coverage: ≥85%
```

## Project Structure

```
policyshield/
├── core/          # Data models, YAML parser
├── shield/        # ShieldEngine, PII detector, matcher
├── approval/      # Approval backends (CLI, Telegram, Webhook)
├── integrations/  # LangChain, CrewAI, Nanobot adapters
├── trace/         # JSONL recorder, OpenTelemetry exporter
├── cli/           # CLI commands
└── config/        # Config file loader, JSON schema
```

## Reporting Issues

- Use GitHub Issues
- Include: Python version, PolicyShield version, minimal reproduction

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
