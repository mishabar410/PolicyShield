# Prompt 65 — Plugin Tests Overhaul

## Цель

Обновить тесты под все изменения из промптов 62–64, добавить type-check тест, переписать E2E тест чтобы он не был skipped.

## Контекст

- Текущие тесты:
  - `hooks.test.ts` (278 строк) — unit тесты hook handlers, используют `createMockApi()`
  - `client.test.ts` (183 строки) — unit тесты клиента, мокают `fetch`
  - `e2e.test.ts` (46 строк) — `describe.skip` если нет `POLICYSHIELD_URL`
  - `types.test.ts` — добавлен в промпте 62
- Все тесты используют Vitest
- Запуск: `cd plugins/openclaw && npm test`

## Что сделать

### 1. Обновить `client.test.ts`

| # | Тест | Изменение |
|---|------|-----------|
| 1 | ~~`test_audit_mode`~~ | **Удалить** — audit mode убран из клиента (промпт 63) |
| 2 | `test_disabled_mode` | **Добавить** — `mode: "disabled"` → return ALLOW без fetch |
| 3 | `test_postcheck_logs_error` | **Добавить** — mock fetch throws → `logger.warn` вызывается |
| 4 | `test_postcheck_logs_http_error` | **Добавить** — mock fetch returns 500 → `logger.warn` вызывается |
| 5 | `test_constraints_logs_error` | **Добавить** — mock fetch throws → `logger.debug` вызывается |
| 6 | `test_check_no_audit_override` | **Добавить** — сервер вернул BLOCK → клиент **не** override-ит на ALLOW |

Пример теста 3:

```typescript
it("logs warning when postCheck fails", async () => {
    const mockLogger = { info: vi.fn(), warn: vi.fn(), error: vi.fn() };
    const client = new PolicyShieldClient({ url: "http://localhost:8100" }, mockLogger);

    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new Error("connection refused")));

    await client.postCheck({
        tool_name: "exec",
        args: {},
        result: "output",
        session_id: "s1",
    });

    expect(mockLogger.warn).toHaveBeenCalledWith(
        expect.stringContaining("post-check failed"),
    );
});
```

### 2. Обновить `hooks.test.ts`

| # | Тест | Изменение |
|---|------|-----------|
| 1 | `test_approve_uses_config_timeout` | **Добавить** — approveTimeoutMs из конфига используется |
| 2 | `test_hook_error_fails_open` | **Добавить** — client.check throws → hook returns undefined (allow) |
| 3 | `test_result_truncation_config` | **Добавить** — maxResultBytes из конфига |
| 4 | Все существующие | **Обновить** если API клиента изменился (mode → enabled) |

### 3. Переписать `e2e.test.ts`

Текущий `describe.skip` — заменить на **реальный тест с MockServer**:

```typescript
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { PolicyShieldClient } from "../src/client.js";

// Start a minimal mock HTTP server that simulates PolicyShield API
import { createServer, type Server } from "node:http";

let server: Server;
let serverUrl: string;

beforeAll(async () => {
    server = createServer((req, res) => {
        let body = "";
        req.on("data", (chunk) => (body += chunk));
        req.on("end", () => {
            const url = req.url ?? "";

            if (url === "/api/v1/health") {
                res.writeHead(200);
                res.end(JSON.stringify({ status: "ok" }));
                return;
            }

            if (url === "/api/v1/check" && req.method === "POST") {
                const parsed = JSON.parse(body);
                if (parsed.tool_name === "exec" && parsed.args?.command?.includes("rm -rf")) {
                    res.writeHead(200);
                    res.end(JSON.stringify({
                        verdict: "BLOCK",
                        message: "Destructive command blocked",
                    }));
                    return;
                }
                res.writeHead(200);
                res.end(JSON.stringify({ verdict: "ALLOW", message: "" }));
                return;
            }

            if (url === "/api/v1/post-check" && req.method === "POST") {
                res.writeHead(200);
                res.end(JSON.stringify({ pii_types: [] }));
                return;
            }

            if (url === "/api/v1/constraints") {
                res.writeHead(200);
                res.end(JSON.stringify({ summary: "- No destructive commands" }));
                return;
            }

            res.writeHead(404);
            res.end();
        });
    });

    await new Promise<void>((resolve) => {
        server.listen(0, () => {
            const addr = server.address();
            if (addr && typeof addr !== "string") {
                serverUrl = `http://localhost:${addr.port}`;
            }
            resolve();
        });
    });
});

afterAll(() => {
    server?.close();
});

describe("e2e: plugin ↔ mock server", () => {
    it("health check succeeds", async () => {
        const client = new PolicyShieldClient({ url: serverUrl });
        expect(await client.healthCheck()).toBe(true);
    });

    it("blocks destructive commands", async () => {
        const client = new PolicyShieldClient({ url: serverUrl });
        const result = await client.check({
            tool_name: "exec",
            args: { command: "rm -rf /" },
            session_id: "test",
        });
        expect(result.verdict).toBe("BLOCK");
    });

    it("allows safe commands", async () => {
        const client = new PolicyShieldClient({ url: serverUrl });
        const result = await client.check({
            tool_name: "exec",
            args: { command: "ls" },
            session_id: "test",
        });
        expect(result.verdict).toBe("ALLOW");
    });

    it("post-check returns PII types", async () => {
        const client = new PolicyShieldClient({ url: serverUrl });
        const result = await client.postCheck({
            tool_name: "exec",
            args: {},
            result: "safe output",
            session_id: "test",
        });
        expect(result).toBeDefined();
        expect(result?.pii_types).toEqual([]);
    });

    it("constraints returns summary", async () => {
        const client = new PolicyShieldClient({ url: serverUrl });
        const result = await client.getConstraints();
        expect(result).toBe("- No destructive commands");
    });
});
```

**Ключевое отличие от старого e2e.test.ts:**
- Не требует `POLICYSHIELD_URL` env var
- Не `describe.skip`
- Использует встроенный mock HTTP server (node:http) — тестирует реальный HTTP round-trip
- Запускается в CI без дополнительной настройки

## Самопроверка

```bash
cd plugins/openclaw

# Type check
npx tsc --noEmit

# All tests pass
npm test

# Нет skipped тестов
npx vitest run 2>&1 | grep -i "skip"  # должно быть 0
```

## Коммит

```
test(plugin): overhaul tests — remove skip, add mock server e2e

- Replace skipped e2e tests with mock HTTP server approach
- Add tests for error logging in client (postCheck, getConstraints)
- Remove audit-mode tests (mode removed from client)
- Add disabled-mode and config-based tests
- All tests run in CI without external dependencies
```
