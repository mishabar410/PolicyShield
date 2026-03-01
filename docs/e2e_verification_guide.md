# 🔬 PolicyShield — E2E Verification Guide

Полный гайд по проверке каждой фичи. Выполняйте секции по порядку.

---

## 0. Подготовка окружения

```bash
cd /path/to/PolicyShield
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev,server]"
```

**Проверка:**
```bash
policyshield --version   # → 0.14.0
python -c "from policyshield import ShieldEngine; print('OK')"
```

---

## 1. Автоматические проверки (CI pipeline)

Запустите полный CI pipeline локально:

```bash
# Тесты (должно быть 1350+, 0 failures)
pytest tests/ -v --tb=short --cov=policyshield --cov-fail-under=85

# Линтер (0 errors)
ruff check policyshield/ tests/

# Форматирование (0 files would be reformatted)
ruff format --check policyshield/ tests/

# Типы (0 errors в checked files)
mypy policyshield/ --ignore-missing-imports

# TypeScript (0 errors)
cd plugins/openclaw && npx tsc --noEmit && cd ../..
```

**Ожидаемый результат:**
- 1350+ passed, 0 failed
- coverage ≥ 85%
- ruff: All checks passed
- mypy: 0 errors
- tsc: 0 errors

---

## 2. Core Engine — Verdicts

### 2.1 ALLOW

```python
python3 -c "
from policyshield.shield.engine import ShieldEngine
engine = ShieldEngine(rules='policies/rules.yaml')
r = engine.check('some_safe_tool', {})
print(f'{r.verdict.value}: {r.message}')
assert r.verdict.value == 'ALLOW', f'Expected ALLOW, got {r.verdict.value}'
print('✅ ALLOW works')
"
```

### 2.2 BLOCK

```python
python3 -c "
from policyshield.shield.engine import ShieldEngine
engine = ShieldEngine(rules='policies/rules.yaml')
r = engine.check('exec', {'command': 'rm -rf /'})
print(f'{r.verdict.value}: {r.message}')
assert r.verdict.value == 'BLOCK', f'Expected BLOCK, got {r.verdict.value}'
print('✅ BLOCK works')
"
```

### 2.3 REDACT (PII)

```python
python3 -c "
from policyshield.shield.engine import ShieldEngine
engine = ShieldEngine(rules='policies/rules.yaml')
r = engine.check('send_message', {'text': 'My email is john@corp.com and SSN 123-45-6789'})
print(f'{r.verdict.value}: {r.message}')
if r.modified_args:
    print(f'Redacted: {r.modified_args}')
    assert '[EMAIL]' in str(r.modified_args) or '[SSN]' in str(r.modified_args)
print('✅ REDACT works')
"
```

### 2.4 APPROVE (human-in-the-loop)

```python
python3 -c "
from policyshield.shield.engine import ShieldEngine
engine = ShieldEngine(rules='policies/rules.yaml')
r = engine.check('write_file', {'path': '.env', 'content': 'SECRET=abc'})
print(f'{r.verdict.value}: {r.message}')
# Depending on rules, should be APPROVE or BLOCK for .env files
print('✅ APPROVE flow reachable')
"
```

---

## 3. HTTP Server — все 13 endpoints

**Запуск сервера:**
```bash
policyshield server --rules policies/rules.yaml --port 8100 &
sleep 2
```

### 3.1 POST /api/v1/check

```bash
# ALLOW
curl -s -X POST http://localhost:8100/api/v1/check \
  -H "Content-Type: application/json" \
  -d '{"tool_name": "safe_tool", "args": {}}' | python3 -m json.tool
# → verdict: ALLOW

# BLOCK
curl -s -X POST http://localhost:8100/api/v1/check \
  -H "Content-Type: application/json" \
  -d '{"tool_name": "exec", "args": {"command": "rm -rf /"}}' | python3 -m json.tool
# → verdict: BLOCK
```

### 3.2 POST /api/v1/post-check

```bash
curl -s -X POST http://localhost:8100/api/v1/post-check \
  -H "Content-Type: application/json" \
  -d '{"tool_name": "read_file", "args": {}, "result": "Email: user@test.com", "session_id": "s1"}' \
  | python3 -m json.tool
# → pii_types: ["EMAIL"]
```

### 3.3 GET /api/v1/health

```bash
curl -s http://localhost:8100/api/v1/health | python3 -m json.tool
# → shield_name, version, mode, rules_count
```

### 3.4 GET /api/v1/status

```bash
curl -s http://localhost:8100/api/v1/status | python3 -m json.tool
# → status: running, killed: false, version, mode
```

### 3.5 GET /api/v1/constraints

```bash
curl -s http://localhost:8100/api/v1/constraints | python3 -m json.tool
# → summary: human-readable policy description
```

### 3.6 POST /api/v1/reload

```bash
curl -s -X POST http://localhost:8100/api/v1/reload | python3 -m json.tool
# → rules_count, hash, reloaded_at
```

### 3.7 POST /api/v1/kill + POST /api/v1/resume

```bash
# Kill
curl -s -X POST http://localhost:8100/api/v1/kill \
  -H "Content-Type: application/json" \
  -d '{"reason": "E2E test"}' | python3 -m json.tool
# → status: killed

# All checks should now return BLOCK
curl -s -X POST http://localhost:8100/api/v1/check \
  -H "Content-Type: application/json" \
  -d '{"tool_name": "safe_tool", "args": {}}' | python3 -m json.tool
# → verdict: BLOCK (kill switch active)

# Resume
curl -s -X POST http://localhost:8100/api/v1/resume | python3 -m json.tool
# → status: resumed

# Check should work again
curl -s -X POST http://localhost:8100/api/v1/check \
  -H "Content-Type: application/json" \
  -d '{"tool_name": "safe_tool", "args": {}}' | python3 -m json.tool
# → verdict: ALLOW
```

### 3.8 Approval endpoints

```bash
# Submit a check that triggers APPROVE
# (use a rule with then: APPROVE)

# POST /api/v1/check-approval
curl -s -X POST http://localhost:8100/api/v1/check-approval \
  -H "Content-Type: application/json" \
  -d '{"approval_id": "test-123"}' | python3 -m json.tool

# GET /api/v1/pending-approvals
curl -s http://localhost:8100/api/v1/pending-approvals | python3 -m json.tool

# POST /api/v1/respond-approval
curl -s -X POST http://localhost:8100/api/v1/respond-approval \
  -H "Content-Type: application/json" \
  -d '{"approval_id": "test-123", "approved": true, "responder": "admin"}' \
  | python3 -m json.tool
```

### 3.9 Health probes (K8s)

```bash
# Liveness
curl -s http://localhost:8100/healthz | python3 -m json.tool
# → status: alive

curl -s http://localhost:8100/api/v1/livez | python3 -m json.tool
# → status: alive

# Readiness
curl -s http://localhost:8100/readyz | python3 -m json.tool
# → status: ready

curl -s http://localhost:8100/api/v1/readyz | python3 -m json.tool
# → status: ready
```

### 3.10 Prometheus metrics

```bash
curl -s http://localhost:8100/metrics
# → policyshield_requests_total, latency, etc.
```

### 3.11 Idempotency

```bash
# Два запроса с одинаковым ключом → одинаковый ответ
curl -s -X POST http://localhost:8100/api/v1/check \
  -H "Content-Type: application/json" \
  -H "X-Idempotency-Key: test-key-1" \
  -d '{"tool_name": "safe_tool", "args": {}}' | python3 -m json.tool

curl -s -X POST http://localhost:8100/api/v1/check \
  -H "Content-Type: application/json" \
  -H "X-Idempotency-Key: test-key-1" \
  -d '{"tool_name": "safe_tool", "args": {}}' | python3 -m json.tool
# → Оба ответа идентичны
```

### 3.12 API token auth

```bash
# Перезапустить сервер с токеном:
# POLICYSHIELD_API_TOKEN=secret policyshield server --rules policies/rules.yaml --port 8100

# Без токена → 401
curl -s -X POST http://localhost:8100/api/v1/check \
  -H "Content-Type: application/json" \
  -d '{"tool_name": "safe_tool"}' -w "\nHTTP: %{http_code}\n"
# → 401

# С токеном → 200
curl -s -X POST http://localhost:8100/api/v1/check \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer secret" \
  -d '{"tool_name": "safe_tool"}' | python3 -m json.tool
# → verdict: ALLOW
```

**Остановить сервер:**
```bash
kill %1  # или pkill -f "policyshield server"
```

---

## 4. CLI Commands

### 4.1 validate

```bash
policyshield validate policies/rules.yaml
# → ✓ Valid: ...
echo $?  # → 0

# Невалидный файл
echo "invalid: [[[" > /tmp/bad.yaml
policyshield validate /tmp/bad.yaml
echo $?  # → 1
```

### 4.2 lint

```bash
policyshield lint policies/rules.yaml
# → Показывает предупредения или "No issues found"
```

### 4.3 test

```bash
policyshield test tests/
# → Запускает YAML test cases
```

### 4.4 check (dry-run)

```bash
# ALLOW → exit 0
policyshield check --tool safe_tool --rules policies/rules.yaml
echo $?  # → 0

# BLOCK → exit 2
policyshield check --tool exec --rules policies/rules.yaml --args '{"command": "rm -rf /"}'
echo $?  # → 2

# JSON output
policyshield check --tool safe_tool --rules policies/rules.yaml --json
# → {"verdict": "ALLOW", ...}
```

### 4.5 quickstart

```bash
# Интерактивный — нужен stdin
echo -e "1\nread_file,write_file\n1\n4" | policyshield quickstart
# → Проверить что создались policies/rules.yaml
```

### 4.6 init + presets

```bash
cd /tmp && mkdir ps-test && cd ps-test
policyshield init --preset secure --no-interactive
ls policies/  # → rules.yaml должен существовать
cat policies/rules.yaml  # → default: BLOCK
cd - && rm -rf /tmp/ps-test
```

### 4.7 doctor

```bash
policyshield doctor --rules policies/rules.yaml
# → 10 checks, grade A-F

policyshield doctor --rules policies/rules.yaml --json
# → JSON output
```

### 4.8 generate (template mode)

```bash
policyshield generate --template --tools delete_file,exec,send_email
# → YAML rules output
```

### 4.9 generate-rules (auto)

```bash
policyshield generate-rules --tools exec,write_file,delete_file,read_file
# → Generated rules YAML
```

### 4.10 kill / resume (remote)

```bash
# Сервер должен быть запущен
policyshield kill --port 8100 --reason "Test"
policyshield resume --port 8100
```

### 4.11 trace commands

```bash
# Создать тестовый trace
python3 -c "
from policyshield.shield.engine import ShieldEngine
from policyshield.trace.recorder import TraceRecorder
import tempfile, os
d = tempfile.mkdtemp()
rec = TraceRecorder(output_dir=d)
engine = ShieldEngine(rules='policies/rules.yaml', trace_recorder=rec)
engine.check('exec', {'command': 'ls'})
engine.check('exec', {'command': 'rm -rf /'})
engine.check('safe_tool', {})
rec.flush()
f = os.listdir(d)[0]
print(os.path.join(d, f))
" > /tmp/trace_path.txt
TRACE=$(cat /tmp/trace_path.txt)

policyshield trace show $TRACE
policyshield trace violations $TRACE
policyshield trace stats --file $TRACE
policyshield trace stats --file $TRACE --format json
policyshield trace search --file $TRACE --verdict BLOCK
policyshield trace export $TRACE -f csv -o /tmp/export.csv
policyshield trace export $TRACE -f html -o /tmp/export.html
ls -la /tmp/export.*
```

### 4.12 replay

```bash
policyshield replay $TRACE --rules policies/rules.yaml
policyshield replay $TRACE --rules policies/rules.yaml --changed-only
```

### 4.13 simulate

```bash
policyshield simulate --rule policies/rules.yaml --tool exec --args '{"command":"ls"}'
```

### 4.14 diff

```bash
# Копируем rules и меняем
cp policies/rules.yaml /tmp/rules_v2.yaml
# (edit /tmp/rules_v2.yaml — change a verdict)
policyshield diff policies/rules.yaml /tmp/rules_v2.yaml
```

### 4.15 openapi

```bash
policyshield openapi --rules policies/rules.yaml --output /tmp/openapi.json
python3 -c "import json; d=json.load(open('/tmp/openapi.json')); print(f'Paths: {len(d[\"paths\"])}'); print('Tags:', [t['name'] for t in d.get('openapi_tags', d.get('tags', []))])"
```

### 4.16 report + incident

```bash
policyshield report --traces $(dirname $TRACE) --format html --output /tmp/report.html
ls -la /tmp/report.html
```

---

## 5. Built-in Security Detectors (Sanitizer)

```python
python3 -c "
from policyshield.shield.sanitizer import InputSanitizer, SanitizerConfig

# Enable all 5 built-in detectors
san = InputSanitizer(SanitizerConfig(
    builtin_detectors=['path_traversal', 'shell_injection', 'sql_injection', 'ssrf', 'url_schemes']
))

# Path traversal
r = san.sanitize({'path': '../../../etc/passwd'})
assert r.rejected, 'Path traversal not detected'
print(f'✅ Path traversal: {r.rejection_reason}')

# Shell injection
r = san.sanitize({'command': 'ls; rm -rf /'})
assert r.rejected, 'Shell injection not detected'
print(f'✅ Shell injection: {r.rejection_reason}')

# SQL injection
r = san.sanitize({'query': \"SELECT * FROM users WHERE id = '1' OR '1'='1'\"})
assert r.rejected, 'SQL injection not detected'
print(f'✅ SQL injection: {r.rejection_reason}')

# SSRF
r = san.sanitize({'url': 'http://169.254.169.254/latest/meta-data/'})
assert r.rejected, 'SSRF not detected'
print(f'✅ SSRF: {r.rejection_reason}')

# URL schemes
r = san.sanitize({'url': 'file:///etc/passwd'})
assert r.rejected, 'URL scheme not detected'
print(f'✅ URL scheme: {r.rejection_reason}')

print('✅ All 5 detectors working')
"
```

---

## 6. PII Detection

```python
python3 -c "
from policyshield.shield.pii import PIIDetector
det = PIIDetector()

tests = {
    'EMAIL': 'Contact me at john@example.com',
    'PHONE': 'Call +1-555-123-4567',
    'CREDIT_CARD': 'Card: 4111-1111-1111-1111',
    'SSN': 'SSN: 123-45-6789',
    'IP': 'Server at 192.168.1.1',
}

for pii_type, text in tests.items():
    matches = det.detect(text)
    found = [m.pii_type.value for m in matches]
    status = '✅' if pii_type in found else '❌'
    print(f'{status} {pii_type}: detected={found}')
"
```

---

## 7. Python SDK Client

```python
python3 -c "
# Без сервера — проверяем конструирование и типы
from policyshield.sdk.client import PolicyShieldClient, AsyncPolicyShieldClient, CheckResult

# CheckResult
r = CheckResult(verdict='ALLOW', message='ok', rule_id='r1')
assert r.verdict == 'ALLOW'
assert r.pii_types == []
print('✅ CheckResult works')

# Client создаётся
c = PolicyShieldClient('http://localhost:19999')
c.close()
print('✅ PolicyShieldClient creates/closes')

# Async client
import asyncio
async def test_async():
    ac = AsyncPolicyShieldClient('http://localhost:19999')
    await ac.close()
    return True
asyncio.run(test_async())
print('✅ AsyncPolicyShieldClient creates/closes')
"
```

**С сервером** (запустите `policyshield server --rules policies/rules.yaml --port 8100` отдельно):

```python
python3 -c "
from policyshield.sdk.client import PolicyShieldClient

with PolicyShieldClient('http://localhost:8100') as c:
    # check
    r = c.check('safe_tool')
    print(f'check: {r.verdict}')
    assert r.verdict == 'ALLOW'

    # health
    h = c.health()
    print(f'health: shield_name={h[\"shield_name\"]}')

    # kill + resume
    c.kill('SDK test')
    r2 = c.check('safe_tool')
    assert r2.verdict == 'BLOCK', 'Kill switch should block'
    c.resume()
    r3 = c.check('safe_tool')
    assert r3.verdict == 'ALLOW', 'Resume should restore ALLOW'

    # reload
    c.reload()

    # post_check
    pc = c.post_check('tool', 'email: user@test.com')
    print(f'post_check pii: {pc}')

    print('✅ Full SDK flow works')
"
```

---

## 8. @shield() Decorator

```python
python3 -c "
from policyshield.shield.engine import ShieldEngine
from policyshield.decorators import shield, guard

engine = ShieldEngine(rules='policies/rules.yaml')

# Sync ALLOW
@shield(engine, tool_name='safe_tool')
def read_it():
    return 'read ok'
assert read_it() == 'read ok'
print('✅ @shield sync ALLOW')

# Sync BLOCK (raises)
@shield(engine, tool_name='exec')
def exec_it():
    return 'should not reach'
try:
    exec_it()
    assert False, 'Should have raised'
except PermissionError:
    print('✅ @shield sync BLOCK raises PermissionError')

# on_block=return_none
@shield(engine, tool_name='exec', on_block='return_none')
def exec_none():
    return 'value'
assert exec_none() is None
print('✅ @shield on_block=return_none')

# Backward-compatible guard()
@guard('safe_tool', engine=engine)
def guard_test():
    return 'guarded'
assert guard_test() == 'guarded'
print('✅ guard() backward compat')
"
```

---

## 9. Role Presets

```python
python3 -c "
import yaml
from pathlib import Path

presets_dir = Path('policyshield/presets')
expected = ['strict', 'permissive', 'minimal', 'coding-agent', 'data-analyst', 'customer-support']

for name in expected:
    p = presets_dir / f'{name}.yaml'
    assert p.exists(), f'Missing preset: {name}'
    data = yaml.safe_load(p.read_text())
    assert 'rules' in data, f'{name}: no rules key'
    rules_count = len(data['rules'])
    dv = data.get('default_verdict', 'N/A')
    print(f'✅ {name}: {rules_count} rules, default={dv}')

print(f'✅ All {len(expected)} presets valid')
"
```

---

## 10. Slack Approval Backend

```python
python3 -c "
from policyshield.approval.slack import SlackApprovalBackend
from policyshield.approval.base import ApprovalRequest

backend = SlackApprovalBackend(webhook_url='https://hooks.slack.com/test')

# Health
h = backend.health()
assert h['healthy'] is True
assert h['backend'] == 'slack'
print(f'✅ Slack health: {h}')

# Submit (will fail HTTP but stores in memory)
req = ApprovalRequest.create(
    tool_name='deploy', args={'env': 'prod'},
    rule_id='r1', message='Need approval', session_id='s1',
)
backend.submit(req)
assert len(backend.pending()) == 1
print('✅ Slack submit + pending')

# Respond
backend.respond(req.request_id, approved=True, responder='admin')
assert len(backend.pending()) == 0
print('✅ Slack respond clears pending')
"
```

---

## 11. MCP Proxy

```python
python3 -c "
import asyncio
from policyshield.shield.async_engine import AsyncShieldEngine
from policyshield.mcp_proxy import MCPProxy

engine = AsyncShieldEngine(rules='policies/rules.yaml')
proxy = MCPProxy(engine, [])

async def test():
    # BLOCK
    r = await proxy.check_and_forward('exec', {'command': 'rm -rf /'})
    assert r['blocked'] is True
    print(f'✅ MCP proxy BLOCK: {r[\"message\"]}')

    # ALLOW
    r = await proxy.check_and_forward('safe_tool', {})
    assert r['blocked'] is False
    print(f'✅ MCP proxy ALLOW: verdict={r[\"verdict\"]}')

asyncio.run(test())
"
```

---

## 12. Retry/Backoff

```python
python3 -c "
import asyncio
from policyshield.approval.retry import retry_with_backoff

call_count = 0

async def flaky():
    global call_count
    call_count += 1
    if call_count < 3:
        raise ConnectionError('transient')
    return 'success'

result = asyncio.run(retry_with_backoff(flaky, max_retries=3, base_delay=0.01))
assert result == 'success'
assert call_count == 3
print(f'✅ Retry succeeded after {call_count} attempts')
"
```

---

## 13. ENV Config

```python
python3 -c "
import os
os.environ['POLICYSHIELD_MODE'] = 'audit'
os.environ['POLICYSHIELD_FAIL_OPEN'] = 'true'
os.environ['POLICYSHIELD_APPROVAL_TIMEOUT'] = '120'
os.environ['POLICYSHIELD_SLACK_WEBHOOK_URL'] = 'https://hooks.slack.com/test'

from policyshield.config.settings import PolicyShieldSettings
s = PolicyShieldSettings()

assert s.mode == 'audit', f'mode={s.mode}'
assert s.fail_open is True
assert s.approval_timeout == 120.0
assert s.slack_webhook_url == 'https://hooks.slack.com/test'
assert s.trace_dir == './traces'  # default
assert s.rules_path == 'policies/rules.yaml'  # default
print(f'✅ ENV config: {s.mode}, fail_open={s.fail_open}, timeout={s.approval_timeout}')
print(f'   Total fields: {len(s.__dataclass_fields__)}')
"
```

---

## 14. OpenAPI Schema

```bash
policyshield openapi --rules policies/rules.yaml --output /tmp/openapi.json

python3 -c "
import json
schema = json.load(open('/tmp/openapi.json'))
assert 'openapi' in schema
assert 'paths' in schema
tags = schema.get('tags', [])
tag_names = [t['name'] for t in tags]
print(f'OpenAPI version: {schema[\"openapi\"]}')
print(f'Paths: {len(schema[\"paths\"])}')
print(f'Tags: {tag_names}')
assert 'check' in tag_names, 'Missing check tag'
assert 'admin' in tag_names, 'Missing admin tag'
assert 'observability' in tag_names, 'Missing observability tag'
print('✅ OpenAPI schema with tags')
"
```

---

## 15. Chain Rules

```python
python3 -c "
from policyshield.shield.engine import ShieldEngine
engine = ShieldEngine(rules='examples/chain_rules.yaml')

# First call: read_database → ALLOW
r1 = engine.check('read_database', {'query': 'SELECT * FROM users'}, session_id='chain-test')
print(f'Step 1 (read_database): {r1.verdict.value}')

# Second call: send_email within 120s → should trigger chain rule BLOCK
r2 = engine.check('send_email', {'to': 'external@evil.com'}, session_id='chain-test')
print(f'Step 2 (send_email): {r2.verdict.value} — {r2.message}')
# If chain rule matched → BLOCK (anti-exfiltration)
print('✅ Chain rules evaluated')
"
```

---

## 16. Rate Limiting

```python
python3 -c "
from policyshield.shield.engine import ShieldEngine
engine = ShieldEngine(rules='policies/rules.yaml')

# Make many calls to trigger rate limit (if configured in rules)
for i in range(100):
    r = engine.check('exec', {'command': 'echo hi'}, session_id='rate-test')
    if r.verdict.value == 'BLOCK' and 'rate' in r.message.lower():
        print(f'✅ Rate limit triggered after {i+1} calls: {r.message}')
        break
else:
    print('⚠️ No rate limit triggered (may not be configured in current rules)')
"
```

---

## 17. Hot Reload

```bash
# Запустить сервер
policyshield server --rules /tmp/hotreload.yaml --port 8100 &
sleep 1

# Начальные правила
cat > /tmp/hotreload.yaml << 'EOF'
shield_name: hotreload-test
version: '1'
rules:
  - id: r1
    when: { tool: test_tool }
    then: ALLOW
EOF

sleep 2  # Дать серверу подхватить

# Проверить ALLOW
curl -s -X POST http://localhost:8100/api/v1/check \
  -H "Content-Type: application/json" \
  -d '{"tool_name": "test_tool"}' | python3 -c "import sys,json; d=json.load(sys.stdin); print(f'Before: {d[\"verdict\"]}'); assert d['verdict']=='ALLOW'"

# Изменить правило на BLOCK
cat > /tmp/hotreload.yaml << 'EOF'
shield_name: hotreload-test
version: '1'
rules:
  - id: r1
    when: { tool: test_tool }
    then: BLOCK
    message: hot-reloaded
EOF

# Вызвать reload
curl -s -X POST http://localhost:8100/api/v1/reload | python3 -m json.tool

# Проверить BLOCK
curl -s -X POST http://localhost:8100/api/v1/check \
  -H "Content-Type: application/json" \
  -d '{"tool_name": "test_tool"}' | python3 -c "import sys,json; d=json.load(sys.stdin); print(f'After: {d[\"verdict\"]}'); assert d['verdict']=='BLOCK'"

echo "✅ Hot reload works"
kill %1
```

---

## 18. Honeypot Tools

```python
python3 -c "
from policyshield.shield.engine import ShieldEngine

# Rules with honeypot
import tempfile, os
rules = tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False)
rules.write('''
shield_name: honeypot-test
version: \"1\"
rules: []
honeypots:
  - tool: get_admin_password
    message: Honeypot triggered
''')
rules.close()

engine = ShieldEngine(rules=rules.name)
r = engine.check('get_admin_password', {})
print(f'{r.verdict.value}: {r.message}')
assert r.verdict.value == 'BLOCK'
print('✅ Honeypot detection works')
os.unlink(rules.name)
"
```

---

## 19. Quickstart Wizard

```bash
# Проверить что модуль загружается и функции работают
python3 -c "
from policyshield.cli.quickstart import _generate_rules, _discover_openclaw_tools

# Custom rules generation
rules = _generate_rules(['read_file', 'exec', 'write_file'], 'block', 'custom')
assert 'shield_name: quickstart-shield' in rules
assert 'default_verdict: BLOCK' in rules
assert 'read_file' in rules
print('✅ Custom rules generation')

# Preset rules
rules = _generate_rules([], 'block', 'coding-agent')
assert 'coding-agent' in rules
print('✅ Preset rules loading')

# Tool discovery (no server → empty)
tools = _discover_openclaw_tools()
assert tools == []
print('✅ Tool discovery (graceful fallback)')
"
```

---

## 20. TypeScript SDK (plugins/openclaw)

```bash
cd plugins/openclaw

# Typecheck
npx tsc --noEmit
echo "✅ TypeScript compiles"

# Tests
npx vitest run
echo "✅ Vitest tests pass"

# Check exports
node -e "
const path = require('path');
const fs = require('fs');
const pkg = JSON.parse(fs.readFileSync('package.json', 'utf8'));
console.log('Package:', pkg.name, pkg.version);
console.log('Main:', pkg.main);
console.log('Types:', pkg.types);
console.log('✅ Package metadata OK');
"

cd ../..
```

---

## 21. OpenClaw Integration

```bash
# Проверить что setup/status работает (без запущенного OpenClaw)
policyshield openclaw status 2>&1 || true
# → Покажет статус или ошибку подключения

# SDK sync check
python3 scripts/check_sdk_sync.py
# → ✅ SDK types in sync
```

---

## 22. Docker

```bash
# Build
docker build -f Dockerfile.server -t policyshield-server .
echo "✅ Docker build"

# Run and test
docker run -d --name ps-test -p 8101:8100 \
  -v $(pwd)/policies:/app/policies policyshield-server \
  --rules /app/policies/rules.yaml

sleep 3

curl -s http://localhost:8101/api/v1/health | python3 -m json.tool
echo "✅ Docker container healthy"

docker stop ps-test && docker rm ps-test
```

---

## Итоговый чеклист

| # | Область | Проверить |
|---|---------|-----------|
| 1 | CI pipeline | pytest, ruff, mypy, tsc — 0 failures |
| 2 | Verdicts | ALLOW, BLOCK, REDACT, APPROVE |
| 3 | Server endpoints | 13 endpoints ответ OK |
| 4 | Kill switch | kill → все BLOCK, resume → нормальная работа |
| 5 | K8s probes | /healthz, /readyz, /api/v1/livez, /api/v1/readyz |
| 6 | Idempotency | Повтор с X-Idempotency-Key → same response |
| 7 | Auth | Без токена → 401, с токеном → 200 |
| 8 | CLI validate | Валидный → 0, невалидный → 1 |
| 9 | CLI lint | Показывает предупреждения |
| 10 | CLI check | ALLOW → exit 0, BLOCK → exit 2, --json |
| 11 | CLI quickstart | Генерирует rules.yaml |
| 12 | CLI doctor | 10 checks, grade |
| 13 | CLI generate | Template + AI mode |
| 14 | CLI trace | show, violations, stats, search, export, cost |
| 15 | CLI replay | Replay traces |
| 16 | CLI simulate | What-if analysis |
| 17 | CLI kill/resume | Remote kill switch |
| 18 | CLI openapi | JSON export with tags |
| 19 | Python SDK | check, health, kill, resume, reload, post_check |
| 20 | Async SDK | Same as sync via async |
| 21 | @shield() | Sync ALLOW, sync BLOCK, async, on_block, guard() |
| 22 | Presets | 6 presets загружаются и валидны |
| 23 | Slack backend | health, submit, pending, respond |
| 24 | MCP proxy | BLOCK и ALLOW forwarding |
| 25 | Retry/backoff | Retries на transient errors |
| 26 | ENV config | 31+ env vars, defaults и overrides |
| 27 | OpenAPI | Tags: check, admin, observability |
| 28 | Security detectors | 5 detectors: path traversal, shell, SQL, SSRF, URL |
| 29 | PII detection | EMAIL, PHONE, CREDIT_CARD, SSN, IP |
| 30 | Chain rules | Multi-step pattern detection |
| 31 | Rate limiting | Per-tool rate limits |
| 32 | Hot reload | Изменение файла → новые правила |
| 33 | Honeypots | Decoy tools → BLOCK |
| 34 | TS SDK | tsc clean, vitest pass |
| 35 | Docker | Build + run + health check |
