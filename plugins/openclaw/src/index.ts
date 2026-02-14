import { PolicyShieldClient } from "./client.js";
import type { PluginConfig } from "./types.js";

export { PolicyShieldClient } from "./client.js";

/**
 * OpenClaw Plugin API interface.
 */
export interface OpenClawPluginApi {
    pluginConfig?: Record<string, unknown>;
    logger: {
        info: (msg: string) => void;
        warn: (msg: string) => void;
        debug: (msg: string) => void;
    };
    on: (
        hookName: string,
        handler: (...args: unknown[]) => unknown,
        opts?: { priority?: number },
    ) => void;
}

/**
 * OpenClaw Plugin definition conforming to the real OpenClaw Plugin API.
 */
export const plugin = {
    name: "policyshield",
    version: "0.7.0",
    description: "PolicyShield — AI agent guardrails for tool-call safety",

    async register(api: OpenClawPluginApi) {
        const rawConfig = (api.pluginConfig ?? {}) as PluginConfig;
        const log = api.logger;

        // Config validation
        if (rawConfig.url && typeof rawConfig.url !== "string") {
            log.warn("Invalid config: url must be a string");
        }
        if (
            rawConfig.timeout_ms &&
            (rawConfig.timeout_ms < 100 || rawConfig.timeout_ms > 30000)
        ) {
            log.warn("timeout_ms should be between 100 and 30000");
        }

        const client = new PolicyShieldClient(rawConfig);

        // Async startup check (non-blocking)
        client
            .healthCheck()
            .then((ok: boolean) => {
                if (ok) {
                    log.info("✓ Connected to PolicyShield server");
                } else {
                    log.warn("⚠ PolicyShield server unreachable — running in degraded mode");
                }
            })
            .catch(() => {
                log.warn("⚠ PolicyShield server unreachable — running in degraded mode");
            });

        // ── before_tool_call: check policy ──────────────────────
        api.on(
            "before_tool_call",
            async (...args: unknown[]) => {
                const event = (args[0] ?? {}) as Record<string, unknown>;
                const toolCtx = (args[1] ?? {}) as Record<string, unknown>;
                const verdict = await client.check({
                    tool_name: (event.toolName as string) ?? "",
                    args: (event.params ?? {}) as Record<string, unknown>,
                    session_id: (toolCtx.sessionKey as string) ?? "default",
                    sender: toolCtx.agentId as string | undefined,
                });

                if (verdict.verdict === "BLOCK") {
                    return {
                        block: true,
                        blockReason: `🛡️ PolicyShield: ${verdict.message}`,
                    };
                }
                if (verdict.verdict === "REDACT" && verdict.modified_args) {
                    return { params: verdict.modified_args };
                }
                if (verdict.verdict === "APPROVE" && verdict.approval_id) {
                    // Poll for approval decision (max 60s, every 2s)
                    const maxWaitMs = 60_000;
                    const intervalMs = 2_000;
                    const deadline = Date.now() + maxWaitMs;
                    while (Date.now() < deadline) {
                        await new Promise((r) => setTimeout(r, intervalMs));
                        const status = await client.checkApproval(verdict.approval_id);
                        if (status.status === "approved") {
                            return undefined; // proceed
                        }
                        if (status.status === "denied") {
                            return {
                                block: true,
                                blockReason: `🛡️ PolicyShield: approval denied${status.responder ? ` by ${status.responder}` : ""}`,
                            };
                        }
                    }
                    return {
                        block: true,
                        blockReason: "⏳ PolicyShield: approval timed out",
                    };
                }
                return undefined; // ALLOW
            },
            { priority: 100 },
        );

        // ── after_tool_call: post-check for PII in output ──────
        api.on(
            "after_tool_call",
            async (...args: unknown[]) => {
                const event = (args[0] ?? {}) as Record<string, unknown>;
                const toolCtx = (args[1] ?? {}) as Record<string, unknown>;
                const resultStr =
                    typeof event.result === "string"
                        ? event.result
                        : JSON.stringify(event.result ?? "").slice(0, 10000);
                await client.postCheck({
                    tool_name: (event.toolName as string) ?? "",
                    args: (event.params ?? {}) as Record<string, unknown>,
                    result: resultStr,
                    session_id: (toolCtx.sessionKey as string) ?? "default",
                });
            },
            { priority: 100 },
        );

        // ── before_agent_start: inject policy constraints ──────
        api.on(
            "before_agent_start",
            async () => {
                const constraints = await client.getConstraints();
                if (!constraints) return undefined;
                return {
                    prependContext: `\n## 🛡️ PolicyShield Active Rules\n${constraints}\n`,
                };
            },
            { priority: 50 },
        );
    },
};

export default plugin;
