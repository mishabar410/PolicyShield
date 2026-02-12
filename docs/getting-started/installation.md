# Installation

## From PyPI

```bash
pip install policyshield
```

## With optional extras

```bash
# LangChain integration
pip install "policyshield[langchain]"

# CrewAI integration
pip install "policyshield[crewai]"

# OpenTelemetry tracing
pip install "policyshield[otel]"

# Documentation tools
pip install "policyshield[docs]"

# Development tools
pip install "policyshield[dev]"

# Everything
pip install "policyshield[all]"
```

## From source

```bash
git clone https://github.com/mishabar410/PolicyShield.git
cd PolicyShield
pip install -e ".[dev]"
```

## Verify installation

```bash
policyshield --version
```
