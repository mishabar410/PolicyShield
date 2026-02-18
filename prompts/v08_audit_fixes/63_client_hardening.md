# Prompt 63 — Client Hardening

## Цель

Исправить 3 проблемы в `plugins/openclaw/src/client.ts`:
1. Убрать дублирование audit-mode (нарушение philosophy.md: «adapters don't modify engine behavior»)
2. Добавить логирование ошибок вместо silent catch (нарушение «no quiet mode»)
3. Улучшить error handling для надёжности

## Контекст

### Проблема 1: Audit-mode в клиенте (строки 42-47)

```typescript
if (this.mode === "audit") {
    this.logger?.info(`[policyshield:audit] ${req.tool_name}: ${verdict.verdict} — ${verdict.message}`);
    return { verdict: "ALLOW", message: "" };
}
```

**Почему это плохо:**
- PolicyShield **сервер** уже обрабатывает audit mode — в `ShieldMode.AUDIT` engine логирует но не блокирует
- Клиент override-ит BLOCK → ALLOW, дублируя логику engine
- Если сервер в enforce mode, а клиент в audit — рассинхронизация
- **philosophy.md:** «Adapters [...] must not modify the engine's core verdict logic»

**Решение:**
- Удалить audit-mode из клиента полностью
- Mode конфигурируется на **сервере** при запуске (`policyshield server --mode audit`)
- В клиенте `mode` остаётся только для `disabled` (полное отключение плагина, без обращения к серверу)

### Проблема 2: Silent catch в `postCheck()` (строки 76-78)

```typescript
} catch {
    /* fire and forget */
}
```

**Почему это плохо:**
- Если сервер упал, post-check молча пропускается
- Ни один лог не пишется — «no quiet mode» нарушен
- PII в tool output не будет обнаружен, и никто об этом не узнает

**Решение:** логировать ошибку через `this.logger?.warn()`

### Проблема 3: Silent catch в `getConstraints()` (строки 91-93)

Аналогично — добавить логирование.

## Что сделать

### 1. Изменить `client.ts`

```typescript
async check(req: CheckRequest): Promise<CheckResponse> {
    if (this.mode === "disabled") {
        return { verdict: "ALLOW", message: "" };
    }
    try {
        const res = await fetch(`${this.url}/api/v1/check`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(req),
            signal: AbortSignal.timeout(this.timeout),
        });
        if (!res.ok) {
            throw new Error(`HTTP ${res.status}: ${res.statusText}`);
        }
        // REMOVED: audit-mode override. Audit mode is configured server-side.
        return (await res.json()) as CheckResponse;
    } catch (err) {
        if (this.failOpen) {
            this.logger?.warn(
                `[policyshield] server unreachable, fail-open: ${String(err)}`,
            );
            return { verdict: "ALLOW", message: "" };
        }
        return {
            verdict: "BLOCK",
            message: "PolicyShield server unreachable (fail-closed)",
        };
    }
}
```

### 2. Добавить логирование в `postCheck()`

```typescript
async postCheck(req: PostCheckRequest): Promise<PostCheckResponse | undefined> {
    try {
        const res = await fetch(`${this.url}/api/v1/post-check`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(req),
            signal: AbortSignal.timeout(this.timeout),
        });
        if (res.ok) {
            return (await res.json()) as PostCheckResponse;
        }
        this.logger?.warn(
            `[policyshield] post-check HTTP ${res.status} for ${req.tool_name}`,
        );
    } catch (err) {
        this.logger?.warn(
            `[policyshield] post-check failed for ${req.tool_name}: ${String(err)}`,
        );
    }
    return undefined;
}
```

### 3. Добавить логирование в `getConstraints()`

```typescript
async getConstraints(): Promise<string | undefined> {
    try {
        const res = await fetch(`${this.url}/api/v1/constraints`, {
            signal: AbortSignal.timeout(2000),
        });
        if (res.ok) {
            const data = (await res.json()) as ConstraintsResponse;
            return data.summary;
        }
    } catch (err) {
        this.logger?.debug?.(
            `[policyshield] constraints fetch failed: ${String(err)}`,
        );
    }
    return undefined;
}
```

### 4. Удалить поле `mode` из конструктора, кроме `disabled`

Переименовать `mode` → `enabled`:

```typescript
constructor(config: PluginConfig = {}, logger?: PluginLogger) {
    this.url = (config.url ?? "http://localhost:8100").replace(/\/$/, "");
    this.timeout = config.timeout_ms ?? 5000;
    this.enabled = (config.mode ?? "enforce") !== "disabled";
    this.failOpen = config.fail_open ?? true;
    this.logger = logger;
}
```

И метод `check()`:
```typescript
if (!this.enabled) {
    return { verdict: "ALLOW", message: "" };
}
```

### 5. Обновить `types.ts`

В `PluginConfig` — изменить JSDoc для `mode`:

```typescript
export type PluginConfig = {
    url?: string;
    /** "enforce" (default) or "disabled". Audit mode is configured on the server. */
    mode?: "enforce" | "disabled";
    fail_open?: boolean;
    timeout_ms?: number;
};
```

## Самопроверка

```bash
cd plugins/openclaw
npx tsc --noEmit

# Обновить тесты клиента:
# - test_audit_mode → убрать или заменить на test_disabled_mode
# - test_postcheck_error_logging → новый тест: при ошибке, logger.warn вызывается
npx vitest run tests/client.test.ts
```

## Коммит

```
fix(plugin): remove audit-mode from client, add error logging

- Remove client-side audit-mode override (audit is server-side only)
- Add logger.warn calls to postCheck() and getConstraints() catch blocks
- Rename mode field to enabled flag for clarity
- Fixes philosophy.md violation: adapters must not modify engine verdicts
```
