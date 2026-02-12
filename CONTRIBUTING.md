# Contributing to PolicyShield

Thanks for your interest in PolicyShield! Here's how to get started.

## Setup

```bash
git clone https://github.com/mishabar410/PolicyShield.git
cd PolicyShield
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev,langchain]"
```

## Development Workflow

1. **Create a branch** from `main`
2. **Write code + tests** — every feature must include tests
3. **Lint**: `ruff check policyshield/ tests/`
4. **Format**: `ruff format policyshield/ tests/`
5. **Test**: `pytest tests/ -v --cov=policyshield --cov-fail-under=85`
6. **Open a PR** against `main`

## Code Style

- Python 3.10+ with type hints
- Formatted with `ruff`
- All public APIs must have docstrings
- Maximum line length: 120 characters

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
├── lint/          # Rule linter
├── cli/           # CLI commands (validate, lint, test, init, nanobot)
└── config/        # Config file loader, JSON schema
```

## Adding a new rule check

1. Add the check method to `policyshield/lint/linter.py`
2. Add tests in `tests/test_linter.py`
3. Document the check in `docs/api/linter.md`

## Adding an integration

1. Create a new module in `policyshield/integrations/`
2. Add optional dependency group in `pyproject.toml`
3. Add integration docs in `docs/integrations/`
4. Write tests in `tests/`

## Commit Messages

Use [Conventional Commits](https://www.conventionalcommits.org/):

```
feat: add new feature
fix: fix a bug
docs: update documentation
test: add tests
chore: maintenance tasks
```

## Reporting Issues

- Use GitHub Issues
- Include: Python version, PolicyShield version, minimal reproduction

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
