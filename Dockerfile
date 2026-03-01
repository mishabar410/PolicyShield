# ── PolicyShield Production Image ──────────────────────────────────────
# Multi-stage build: produces a ~80 MB image with no dev dependencies.

FROM python:3.13-slim AS builder

WORKDIR /build
COPY pyproject.toml README.md ./
COPY policyshield/ policyshield/

RUN pip install --no-cache-dir --prefix=/install ".[server]"

# ── Runtime stage ────────────────────────────────────────────────────────
FROM python:3.13-slim

LABEL org.opencontainers.image.title="PolicyShield" \
      org.opencontainers.image.description="Declarative firewall for AI agent tool calls" \
      org.opencontainers.image.source="https://github.com/mishabar410/policyshield"

# Non-root user for security
RUN adduser --disabled-password --gecos '' policyshield
USER policyshield

COPY --from=builder /install /usr/local
COPY --chown=policyshield:policyshield policyshield/ /app/policyshield/

WORKDIR /app

# Default rules mount point
VOLUME /app/policies

# Default environment
ENV POLICYSHIELD_MODE=enforce \
    POLICYSHIELD_PORT=8100 \
    POLICYSHIELD_HOST=0.0.0.0 \
    POLICYSHIELD_FAIL_MODE=closed \
    POLICYSHIELD_TRACE_DIR=/app/traces \
    POLICYSHIELD_LOG_LEVEL=INFO

EXPOSE 8100

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python -c "import httpx; httpx.get('http://localhost:8100/api/v1/health').raise_for_status()" || exit 1

ENTRYPOINT ["python", "-m", "policyshield.cli.main"]
CMD ["server", "--rules", "/app/policies", "--port", "8100"]
