#!/usr/bin/env bash
# PolicyShield — full E2E test suite
# Runs all Tier 0 features against a live server on port 8100.
# Usage: ./tests/e2e.sh [--start-server]
set -euo pipefail

PORT=8100
BASE="http://127.0.0.1:${PORT}"
RULES="/tmp/policyshield-e2e/rules.yaml"
PASS=0; FAIL=0; TOTAL=0

# ── Helpers ──────────────────────────────────────────────────────────
red()   { printf '\033[31m%s\033[0m' "$*"; }
green() { printf '\033[32m%s\033[0m' "$*"; }
bold()  { printf '\033[1m%s\033[0m' "$*"; }

check() {
    local name="$1" expected="$2" actual="$3"
    TOTAL=$((TOTAL + 1))
    if echo "$actual" | grep -q "$expected"; then
        PASS=$((PASS + 1))
        printf "  %-50s %s\n" "$name" "$(green '✓ PASS')"
    else
        FAIL=$((FAIL + 1))
        printf "  %-50s %s\n" "$name" "$(red '✗ FAIL')"
        printf "    expected: %s\n" "$expected"
        printf "    actual:   %s\n" "$actual"
    fi
}

api() { curl -s --max-time 5 -X "$1" "${BASE}$2" -H "Content-Type: application/json" ${3:+-d "$3"} 2>/dev/null; }

# ── Setup rules file ─────────────────────────────────────────────────
mkdir -p "$(dirname "$RULES")"
cat > "$RULES" << 'YAML'
shield_name: e2e-test
version: 1
default_verdict: BLOCK

honeypots:
  - tool: admin_panel
  - tool: get_credentials
  - tool: delete_all_data

rules:
  - id: allow-read-file
    description: "Allow reading files"
    when:
      tool: read_file
    then: allow

  - id: allow-search
    description: "Allow search"
    when:
      tool: search
    then: allow

  - id: allow-list-dir
    description: "Allow listing directories"
    when:
      tool: list_dir
    then: allow

  - id: approve-write
    description: "Require approval for file writes"
    when:
      tool: write_file
    then: approve
    severity: medium
    message: "File writes require approval"

  - id: block-exec
    description: "Block command execution"
    when:
      tool:
        - exec
        - shell
        - run_command
    then: block
    severity: critical
    message: "Command execution is blocked"

  - id: redact-pii
    description: "Redact PII from outgoing messages"
    when:
      tool:
        - send_message
        - send_email
    then: redact
    severity: high
    message: "PII redacted from outgoing message"
YAML

# ── Optionally start server ──────────────────────────────────────────
SERVER_PID=""
if [[ "${1:-}" == "--start-server" ]]; then
    echo "Starting PolicyShield server..."
    policyshield server --rules "$RULES" --port "$PORT" --host 127.0.0.1 &>/dev/null &
    SERVER_PID=$!
    sleep 2
fi

# Wait for server
for i in {1..10}; do
    if curl -s --max-time 1 "${BASE}/api/v1/health" &>/dev/null; then break; fi
    sleep 1
done

# ── 1. Health ────────────────────────────────────────────────────────
bold "Health & Status"; echo ""
# Reload rules to ensure clean state from our rules file
api POST /api/v1/reload > /dev/null 2>&1
sleep 1
R=$(api GET /api/v1/health)
check "Health check" '"status":"ok"' "$R"
check "Health shield_name" '"shield_name":"e2e-test"' "$R"
check "Health rules_count 6" '"rules_count":6' "$R"

R=$(api GET /api/v1/status)
check "Server status" '"status":"running"' "$R"

R=$(api GET /api/v1/constraints)
check "Constraints" '"summary"' "$R"

# ── 2. ALLOW verdicts ────────────────────────────────────────────────
echo ""; bold "ALLOW Verdicts"; echo ""
for tool in read_file search list_dir; do
    R=$(api POST /api/v1/check "{\"tool_name\":\"$tool\",\"args\":{}}")
    check "ALLOW: $tool" '"verdict":"ALLOW"' "$R"
done

# ── 3. BLOCK verdicts ────────────────────────────────────────────────
echo ""; bold "BLOCK Verdicts"; echo ""
for tool in exec shell unknown_tool; do
    R=$(api POST /api/v1/check "{\"tool_name\":\"$tool\",\"args\":{}}")
    check "BLOCK: $tool" '"verdict":"BLOCK"' "$R"
done

# ── 4. APPROVE verdict ───────────────────────────────────────────────
echo ""; bold "APPROVE Verdict"; echo ""
R=$(api POST /api/v1/check '{"tool_name":"write_file","args":{"path":"/tmp/x"},"session_id":"e2e"}')
check "APPROVE: write_file" '"verdict":"APPROVE"' "$R"
check "APPROVE: has approval_id" '"approval_id"' "$R"

# Extract approval_id and do round-trip
AID=$(echo "$R" | grep -o '"approval_id":"[^"]*"' | cut -d'"' -f4)
if [[ -n "$AID" ]]; then
    R=$(api POST /api/v1/respond-approval "{\"approval_id\":\"$AID\",\"approved\":true}")
    check "APPROVE: respond ok" '"status":"ok"' "$R"
    R=$(api POST /api/v1/check-approval "{\"approval_id\":\"$AID\"}")
    check "APPROVE: round-trip approved" '"status":"approved"' "$R"
fi

# Test deny round-trip
R=$(api POST /api/v1/check '{"tool_name":"write_file","args":{"path":"/tmp/y"},"session_id":"e2e-deny"}')
AID=$(echo "$R" | grep -o '"approval_id":"[^"]*"' | cut -d'"' -f4)
if [[ -n "$AID" ]]; then
    R=$(api POST /api/v1/respond-approval "{\"approval_id\":\"$AID\",\"approved\":false}")
    check "DENY: respond ok" '"status":"ok"' "$R"
    R=$(api POST /api/v1/check-approval "{\"approval_id\":\"$AID\"}")
    check "DENY: round-trip denied" '"status":"denied"' "$R"
fi

# ── 5. REDACT verdict (PII) ──────────────────────────────────────────
echo ""; bold "REDACT Verdict (PII)"; echo ""
R=$(api POST /api/v1/check '{"tool_name":"send_message","args":{"text":"Call me at 555-123-4567"}}')
check "REDACT: send_message" '"verdict":"REDACT"' "$R"
check "REDACT: has pii_types" '"pii_types"' "$R"

# ── 6. Post-check PII ────────────────────────────────────────────────
echo ""; bold "Post-check PII"; echo ""
R=$(api POST /api/v1/post-check '{"tool_name":"read_file","result":"SSN is 123-45-6789 email john@example.com"}')
check "Post-check: detects PII" '"pii_types"' "$R"
check "Post-check: redacted" '"redacted_output"' "$R"

# ── 7. Honeypots ──────────────────────────────────────────────────────
echo ""; bold "Honeypot Traps"; echo ""
for tool in admin_panel get_credentials delete_all_data; do
    R=$(api POST /api/v1/check "{\"tool_name\":\"$tool\",\"args\":{}}")
    check "HONEYPOT: $tool → BLOCK" '"verdict":"BLOCK"' "$R"
done

# ── 8. Kill switch ────────────────────────────────────────────────────
echo ""; bold "Kill Switch"; echo ""
R=$(api POST /api/v1/kill '{"reason":"e2e test"}')
check "Kill: activated" '"status":"killed"' "$R"

R=$(api POST /api/v1/check '{"tool_name":"read_file","args":{}}')
check "Kill: blocks all" '"verdict":"BLOCK"' "$R"

R=$(api POST /api/v1/resume)
check "Resume: deactivated" '"status":"resumed"' "$R"

R=$(api POST /api/v1/check '{"tool_name":"read_file","args":{}}')
check "Resume: allows again" '"verdict":"ALLOW"' "$R"

# ── 9. Sanitizer (built-in security detectors) ────────────────────────
echo ""; bold "Sanitizer (Security Detectors)"; echo ""
R=$(api POST /api/v1/check '{"tool_name":"read_file","args":{"path":"../../etc/passwd"}}')
check "Sanitizer: path traversal" '__sanitizer__' "$R"
check "Sanitizer: path traversal verdict" '"verdict":"BLOCK"' "$R"

R=$(api POST /api/v1/check '{"tool_name":"read_file","args":{"cmd":"; rm -rf /"}}')
check "Sanitizer: shell injection" '__sanitizer__' "$R"

R=$(api POST /api/v1/check '{"tool_name":"search","args":{"q":"x; DROP TABLE users; --"}}')
check "Sanitizer: SQL injection" '__sanitizer__' "$R"

R=$(api POST /api/v1/check '{"tool_name":"read_file","args":{"url":"http://169.254.169.254/meta"}}')
check "Sanitizer: SSRF" '__sanitizer__' "$R"

R=$(api POST /api/v1/check '{"tool_name":"read_file","args":{"path":"file:///etc/passwd"}}')
check "Sanitizer: url_schemes" '__sanitizer__' "$R"

# ── 10. Hot reload ────────────────────────────────────────────────────
echo ""; bold "Hot Reload"; echo ""
HASH_BEFORE=$(api GET /api/v1/health | grep -o '"rules_hash":"[^"]*"')

# Add a temporary rule
cat >> "$RULES" << 'YAML'

  - id: temp-block-test
    when:
      tool: temp_test_tool
    then: block
    message: "Temporary test rule"
YAML

R=$(api POST /api/v1/reload)
check "Reload: success" '"status"' "$R"

R=$(api GET /api/v1/health)
check "Reload: 7 rules" '"rules_count":7' "$R"
HASH_AFTER=$(echo "$R" | grep -o '"rules_hash":"[^"]*"')
if [[ "$HASH_BEFORE" != "$HASH_AFTER" ]]; then
    check "Reload: hash changed" "changed" "changed"
else
    check "Reload: hash changed" "changed" "same"
fi

R=$(api POST /api/v1/check '{"tool_name":"temp_test_tool","args":{}}')
check "Reload: new rule works" '"verdict":"BLOCK"' "$R"

# ── Summary ───────────────────────────────────────────────────────────
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
if [[ $FAIL -eq 0 ]]; then
    green "ALL $TOTAL TESTS PASSED"; echo ""
else
    red "$FAIL/$TOTAL TESTS FAILED"; echo ""
fi
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Cleanup
[[ -n "$SERVER_PID" ]] && kill "$SERVER_PID" 2>/dev/null
exit $FAIL
