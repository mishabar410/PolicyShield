#!/usr/bin/env bash
set -e

echo "=== Starting PolicyShield server ==="
policyshield server --rules examples/openclaw_rules.yaml --port 8100 &
SERVER_PID=$!
sleep 2

echo "=== Running Python E2E tests ==="
pytest tests/test_e2e_server.py -v

echo "=== Running TypeScript E2E tests ==="
cd plugins/openclaw
POLICYSHIELD_URL=http://localhost:8100 npm test -- --run tests/e2e.test.ts || true
cd ../..

echo "=== Stopping server ==="
kill $SERVER_PID 2>/dev/null || true

echo "=== DONE ==="
