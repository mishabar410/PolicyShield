FROM python:3.12-slim

WORKDIR /app

COPY pyproject.toml README.md LICENSE ./
COPY policyshield/ policyshield/

RUN pip install --no-cache-dir .

# Default: run the CLI help
ENTRYPOINT ["policyshield"]
CMD ["--help"]
