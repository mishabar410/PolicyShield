# Installation

## From PyPI

```bash
pip install policyshield
```

## With optional extras

```bash
# HTTP server (OpenClaw integration, REST API)
pip install "policyshield[server]"

# LangChain integration
pip install "policyshield[langchain]"

# CrewAI integration
pip install "policyshield[crewai]"

# OpenTelemetry tracing
pip install "policyshield[otel]"

# Development tools
pip install "policyshield[dev]"

# Everything
pip install "policyshield[all]"
```

## From source

```bash
git clone https://github.com/mishabar410/PolicyShield.git
cd PolicyShield
pip install -e ".[dev,server]"
```

## Verify installation

```bash
policyshield --version
```
