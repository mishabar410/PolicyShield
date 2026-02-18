# Prompt 64 — Plugin Logic Fixes

## Цель

Исправить 3 проблемы в `plugins/openclaw/src/index.ts`:
1. APPROVE polling — сделать конфигурируемым вместо hardcoded 60s/2s
2. Magic number 10000 — сделать конфигурируемым
3. Контекст ошибок — логировать все ошибки в hook handlers

## Контекст

### Проблема 1: Hardcoded APPROVE polling (строки 90-109)

```typescript
const maxWaitMs = 60_000;
const intervalMs = 2_000;
```

**Почему это плохо:**
- 60 секунд блокировки event loop — OpenClaw hook runner вызывает хуки последовательно (`runModifyingHook` — sequential, не parallel)
- Нет способа уменьшить/увеличить timeout
- Нет cancel механизма
- Нет exponential backoff

**Решение:** вынести в конфиг `PluginConfig`:
```typescript
approve_timeout_ms?: number;  // default: 60000
approve_poll_interval_ms?: number;  // default: 2000
```

### Проблема 2: Magic number 10000 (строка 126)

```typescript
JSON.stringify(event.result ?? "").slice(0, 10000)
```

**Почему это плохо:**
- 10KB limit не документирован и не конфигурируем
- Если tool result > 10KB — молча обрезает, PII в обрезанной части не проверяется

**Решение:** вынести в конфиг:
```typescript
max_result_bytes?: number;  // default: 10000
```

### Проблема 3: Нет error logging в hook handlers

Если `client.check()` или `client.postCheck()` бросят исключение, OpenClaw hook runner его поймает и залогирует, но без контекста PolicyShield. Лучше ловить и логировать самим.

## Что сделать

### 1. Обновить `types.ts`

```typescript
export type PluginConfig = {
    url?: string;
    /** "enforce" (default) or "disabled". Audit mode is configured on the server. */
    mode?: "enforce" | "disabled";
    fail_open?: boolean;
    timeout_ms?: number;
    /** Max time to wait for human approval (ms). Default: 60000 */
    approve_timeout_ms?: number;
    /** Polling interval for approval status (ms). Default: 2000 */
    approve_poll_interval_ms?: number;
    /** Max bytes of tool result to send for post-check PII scan. Default: 10000 */
    max_result_bytes?: number;
};
```

### 2. Обновить `openclaw.plugin.json`

Добавить новые поля в schema:

```json
{
    "approve_timeout_ms": {
        "type": "number",
        "default": 60000,
        "description": "Max time to wait for human approval (ms)"
    },
    "approve_poll_interval_ms": {
        "type": "number",
        "default": 2000,
        "description": "Polling interval for approval status (ms)"
    },
    "max_result_bytes": {
        "type": "number",
        "default": 10000,
        "description": "Max bytes of tool result to send for PII scan"
    }
}
```

### 3. Обновить `index.ts`

В `register()`:

```typescript
const approveTimeoutMs = rawConfig.approve_timeout_ms ?? 60_000;
const approvePollMs = rawConfig.approve_poll_interval_ms ?? 2_000;
const maxResultBytes = rawConfig.max_result_bytes ?? 10_000;
```

APPROVE polling:

```typescript
if (verdict.verdict === "APPROVE" && verdict.approval_id) {
    const deadline = Date.now() + approveTimeoutMs;
    while (Date.now() < deadline) {
        await new Promise((r) => setTimeout(r, approvePollMs));
        try {
            const status = await client.checkApproval(verdict.approval_id);
            if (status.status === "approved") return undefined;
            if (status.status === "denied") {
                return {
                    block: true,
                    blockReason: `🛡️ PolicyShield: approval denied${status.responder ? ` by ${status.responder}` : ""}`,
                };
            }
        } catch (err) {
            log.warn(`Approval poll error: ${String(err)}`);
        }
    }
    return {
        block: true,
        blockReason: `⏳ PolicyShield: approval timed out after ${approveTimeoutMs / 1000}s`,
    };
}
```

Post-check result truncation:

```typescript
const resultStr =
    typeof event.result === "string"
        ? event.result.slice(0, maxResultBytes)
        : JSON.stringify(event.result ?? "").slice(0, maxResultBytes);
```

### 4. Wrap hook handlers в try-catch с logging

```typescript
api.on(
    "before_tool_call",
    async (event, ctx) => {
        try {
            // ... existing logic ...
        } catch (err) {
            log.warn(`before_tool_call hook error: ${String(err)}`);
            // fail-open: don't block on plugin error
            return undefined;
        }
    },
    { priority: 100 },
);
```

Аналогично для `after_tool_call` и `before_agent_start`.

## Самопроверка

```bash
cd plugins/openclaw
npx tsc --noEmit
npm test
```

Ручная проверка:
- `grep -n "60.000\|60_000\|10.000\|10000\|2.000\|2_000" src/index.ts` — все magic numbers заменены на переменные
- Все три hook handler обёрнуты в try-catch

## Коммит

```
fix(plugin): configurable APPROVE polling, remove magic numbers

- approve_timeout_ms, approve_poll_interval_ms, max_result_bytes now configurable
- Add try-catch with logging to all hook handlers
- Update openclaw.plugin.json schema with new options
- Fixes hardcoded values and silent failures in hooks
```
