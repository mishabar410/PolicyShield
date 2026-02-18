# Prompt 62 — SDK Stubs Sync

## Цель

Синхронизировать `plugins/openclaw/src/openclaw-plugin-sdk.d.ts` с реальным OpenClaw Plugin API (`openclaw/src/plugins/types.ts`), чтобы стубы гарантированно совпадали с реальными типами.

## Контекст

- Текущие стубы в целом верны (сигнатуры хуков совпадают), но:
  1. Ссылка на upstream уже исправлена в промпте 61
  2. Отсутствует `OpenClawPluginToolFactory` и `OpenClawPluginToolOptions` — не критично, но для полноты
  3. В реальном `types.ts` есть `configSchema?: OpenClawPluginConfigSchema` — позволяет валидировать конфиг плагина
  4. Нет `activate?:` callback в `OpenClawPluginDefinition`
- **Цель:** стубы должны содержать **ровно те типы**, которые использует PolicyShield плагин, и ничего лишнего
- Реальный API взят из: `openclaw/src/plugins/types.ts` (563 строки)

## Реальные типы (source of truth)

Из `openclaw/src/plugins/types.ts`:

```typescript
// Plugin Definition (lines 229-242)
export type OpenClawPluginDefinition = {
  id?: string;
  name?: string;
  description?: string;
  version?: string;
  kind?: PluginKind;
  configSchema?: OpenClawPluginConfigSchema;
  register?: (api: OpenClawPluginApi) => void | Promise<void>;
  activate?: (api: OpenClawPluginApi) => void | Promise<void>;
};

// Plugin API (lines 244-283) — only methods PolicyShield uses:
export type OpenClawPluginApi = {
  id: string;
  name: string;
  version?: string;
  description?: string;
  source: string;
  config: OpenClawConfig;        // full app config
  pluginConfig?: Record<string, unknown>;  // plugin-specific config from openclaw.yaml
  runtime: PluginRuntime;
  logger: PluginLogger;
  registerTool: (...) => void;
  registerHook: (...) => void;
  // ...other register methods...
  on: <K extends PluginHookName>(
    hookName: K,
    handler: PluginHookHandlerMap[K],
    opts?: { priority?: number },
  ) => void;
};

// Hook types used by PolicyShield:
// PluginHookBeforeToolCallEvent = { toolName: string; params: Record<string, unknown> }
// PluginHookBeforeToolCallResult = { params?: Record<string, unknown>; block?: boolean; blockReason?: string }
// PluginHookAfterToolCallEvent = { toolName: string; params: Record<string, unknown>; result?: unknown; error?: string; durationMs?: number }
// PluginHookToolContext = { agentId?: string; sessionKey?: string; toolName: string }
// PluginHookBeforeAgentStartEvent = { prompt: string; messages?: unknown[] }
// PluginHookBeforeAgentStartResult = { systemPrompt?: string; prependContext?: string }
// PluginHookAgentContext = { agentId?: string; sessionKey?: string; sessionId?: string; workspaceDir?: string; messageProvider?: string }
```

## Что сделать

### 1. Переписать `plugins/openclaw/src/openclaw-plugin-sdk.d.ts`

Правила:
- Включить **только типы, используемые PolicyShield** (не всё из types.ts)
- Каждый тип должен **точно совпадать** с реальным (поля, optionality, типы)
- Добавить header с hash/date для отслеживания синхронизации:

```typescript
/**
 * Type stubs for the OpenClaw Plugin SDK.
 *
 * Manually synchronized with openclaw/src/plugins/types.ts
 * Source of truth: https://github.com/openclaw/openclaw → src/plugins/types.ts
 * Last sync: 2026-02-14
 *
 * Only types used by the PolicyShield plugin are included.
 * To re-sync: compare this file with the real types.ts and update any differences.
 */
```

- Убедиться что `OpenClawPluginDefinition` включает `activate?:` и `configSchema?:`
- `OpenClawPluginApi` — включать только используемые поля + `on()`
- Все hook event/result/context типы — копировать точно

### 2. Добавить type test

Создать `plugins/openclaw/tests/types.test.ts`:

```typescript
import { describe, it, expect } from "vitest";
import type { OpenClawPluginDefinition, OpenClawPluginApi } from "../src/openclaw-plugin-sdk.js";
import plugin from "../src/index.js";

describe("SDK type compatibility", () => {
    it("plugin satisfies OpenClawPluginDefinition", () => {
        // This is a compile-time check — if types don't match, tsc will fail
        const def: OpenClawPluginDefinition = plugin;
        expect(def.id).toBe("policyshield");
        expect(def.register).toBeTypeOf("function");
    });

    it("plugin has required fields", () => {
        expect(plugin.id).toBe("policyshield");
        expect(plugin.name).toBe("PolicyShield");
        expect(plugin.version).toBeDefined();
        expect(plugin.description).toBeDefined();
    });
});
```

## Самопроверка

```bash
cd plugins/openclaw

# Type check — must pass
npx tsc --noEmit

# Run type test
npx vitest run tests/types.test.ts

# All tests
npm test
```

## Коммит

```
fix(plugin): sync SDK stubs with real OpenClaw types.ts

- Update openclaw-plugin-sdk.d.ts to match openclaw/src/plugins/types.ts
- Add last-sync date header for future maintenance
- Add compile-time type compatibility test
- Ensure OpenClawPluginDefinition includes activate/configSchema fields
```
