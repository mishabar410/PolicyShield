#!/bin/bash
# Run E2E tests via Docker Compose.
# Usage: bash scripts/e2e_docker.sh
set -e

echo "🚀 Starting PolicyShield E2E tests..."
docker compose -f docker-compose.e2e.yml up --build --abort-on-container-exit --exit-code-from e2e-test
echo "✅ E2E tests complete."
