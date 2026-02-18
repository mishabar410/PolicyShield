# Prompt 75 — E2E Test Scenarios

## Статус: 🔄 ПЕРЕРАБОТАН по результатам разведки (prompt 73)

### Изменения после разведки

Оригинальный план предполагал REST API для tool calls. Разведка показала:
WebSocket-only gateway, нет test mode. Поэтому E2E сценарии переориентированы
на программный hook dispatch (Tier 1/2), а не на Docker + WebSocket.

## Цель

Расширить `openclaw-compat.test.ts` пятью E2E-подобными сценариями с реальными
правилами и реальным PolicyShield сервером (если запущен).

## Что сделать

### 1. Добавить integration-level сценарии в `tests/openclaw-compat.test.ts`

5 сценариев, каждый тестирует полный цикл hook dispatch → PolicyShield → verdict:

| # | Сценарий | Инструмент | Правило | Ожидаемый результат |
|---|----------|-----------|---------|---------------------|
| 1 | BLOCK | `exec` | `rm -rf /` | `{ blocked: true }` |
| 2 | REDACT | `send_email` | PII email | args redacted |
| 3 | ALLOW | `read_file` | no match | passthrough |
| 4 | APPROVE timeout | `write_file` to `/etc/` | approve rule | timeout → block |
| 5 | Fail-open | любой | server unreachable | passthrough |

### 2. Структура каждого сценария

```typescript
describe("E2E Scenario: BLOCK rm -rf", () => {
  it("dispatches before_tool_call and receives BLOCK verdict", async () => {
    // 1. Create plugin instance with real or mock PolicyShield URL
    // 2. Simulate OpenClaw hook dispatch (same pattern as compat test)
    // 3. Assert verdict is BLOCK
    // 4. Assert error message matches rule
  });
});
```

### 3. Conditional integration vs unit

```typescript
const POLICYSHIELD_URL = process.env.POLICYSHIELD_URL;
const isIntegration = !!POLICYSHIELD_URL;

describe.skipIf(!isIntegration)("Integration scenarios", () => {
  // Runs only when PolicyShield server is available
});

describe("Mock scenarios", () => {
  // Always runs — uses msw or fetch mock
});
```

## Самопроверка

```bash
# Unit mode (no server)
cd plugins/openclaw && npx vitest run

# Integration mode (with running PolicyShield server)
POLICYSHIELD_URL=http://localhost:8100 npx vitest run
```

## Коммит

```
test(e2e): add 5 E2E-style scenarios to openclaw-compat tests

- BLOCK, REDACT, ALLOW, APPROVE timeout, fail-open
- Conditional integration/unit based on POLICYSHIELD_URL
- Based on prompt 73 recon: no REST API, use hook dispatch
```
