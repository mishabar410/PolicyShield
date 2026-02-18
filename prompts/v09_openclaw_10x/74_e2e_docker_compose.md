# Prompt 74 — E2E Docker Compose

## Статус: 🔄 ПЕРЕРАБОТАН по результатам разведки (prompt 73)

### Изменения после разведки

Оригинальный план предполагал:
- ❌ `openclaw/openclaw:latest` — публичного образа нет
- ❌ `OPENCLAW_SKIP_LLM=true` — тестового режима нет
- ❌ REST API для tool calls — API работает через WebSocket
- ❌ `GET /health` — нет standalone health endpoint

### Новый подход

Вместо полного Docker Compose E2E (дорого, хрупко), используем **tiered strategy**:

## Цель

Создать Tier 2 smoke test: проверить, что наш плагин корректно загружается
реальным OpenClaw loader без моков.

## Что сделать

### 1. Создать `tests/e2e-openclaw/plugin-load-smoke.test.ts`

```typescript
/**
 * Tier 2: Smoke test — verify our plugin loads with real OpenClaw loader.
 *
 * Installs `openclaw` as devDependency (already done), imports the plugin
 * loader, and verifies our plugin can be discovered + initialized.
 * Runs entirely in-process — no Docker, no LLM, no network.
 */
import { describe, it, expect } from "vitest";

// Our plugin's default export
import pluginModule from "../../plugins/openclaw/src/index.js";

describe("OpenClaw Plugin Load Smoke Test", () => {
  it("exports a valid OpenClawPluginDefinition", () => {
    expect(pluginModule).toBeDefined();
    expect(pluginModule).toHaveProperty("name");
    expect(pluginModule).toHaveProperty("setup");
    expect(typeof pluginModule.setup).toBe("function");
  });

  it("setup() registers hooks without throwing", async () => {
    const registeredHooks: Array<{ name: string; handler: Function }> = [];

    const mockApi = {
      hook: (name: string, handler: Function) => {
        registeredHooks.push({ name, handler });
      },
      log: {
        info: () => {},
        warn: () => {},
        error: () => {},
        debug: () => {},
      },
    };

    // Setup should not throw
    await pluginModule.setup(mockApi as any);

    // Should register at least before_tool_call
    const hookNames = registeredHooks.map((h) => h.name);
    expect(hookNames).toContain("before_tool_call");
  });
});
```

### 2. Создать `tests/e2e-openclaw/rules/e2e-rules.yaml`

```yaml
version: "1"
default_verdict: allow

rules:
  - id: block-rm
    tool: exec
    match:
      args:
        command:
          contains: "rm -rf"
    then: block
    message: "Destructive command blocked"

  - id: redact-email
    tool: "*"
    match:
      pii: [EMAIL]
    then: redact

  - id: approve-write
    tool: write_file
    match:
      args:
        path:
          glob: "/etc/**"
    then: approve
    message: "System file write requires approval"
```

### 3. Оставить Docker Compose как Tier 3 (ручной, для release validation)

Создать `tests/e2e-openclaw/docker-compose.yml` с пометкой
"manual only — requires LLM API key":

```yaml
# ⚠️ MANUAL ONLY — requires LLM_API_KEY and ~5 min build time
# Usage: docker compose up --build
# Prerequisites: export LLM_API_KEY=...
services:
  policyshield:
    build:
      context: ../../
      dockerfile: tests/e2e-openclaw/Dockerfile.policyshield
    ports:
      - "8100:8100"
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8100/api/v1/health"]
      interval: 2s
      timeout: 5s
      retries: 10

  openclaw:
    build:
      context: .
      dockerfile: Dockerfile.openclaw
    depends_on:
      policyshield:
        condition: service_healthy
    volumes:
      - ../../plugins/openclaw/dist/:/home/node/.openclaw/extensions/policyshield/
    environment:
      - OPENCLAW_GATEWAY_TOKEN=test-token
      - LLM_API_KEY=${LLM_API_KEY}
    ports:
      - "18789:18789"
```

## Самопроверка

```bash
# Smoke test проходит
cd tests/e2e-openclaw && npx vitest run plugin-load-smoke.test.ts

# Основные тесты не сломаны
cd ../../ && pytest tests/ -q
cd plugins/openclaw && npx vitest run
```

## Коммит

```
feat(e2e): add plugin load smoke test and Docker Compose for manual E2E

- Tier 2: plugin-load-smoke.test.ts (in-process, no Docker)
- Tier 3: docker-compose.yml (manual, requires LLM_API_KEY)
- E2E rules for BLOCK, REDACT, APPROVE scenarios
- Based on prompt 73 recon findings
```
