import type {
    OpenClawPluginApi,
    OpenClawPluginDefinition,
    PluginHookBeforeToolCallEvent,
    PluginHookBeforeToolCallResult,
    PluginHookAfterToolCallEvent,
    PluginHookToolContext,
    PluginHookBeforeAgentStartEvent,
    PluginHookBeforeAgentStartResult,
    PluginHookAgentContext,
} from "./openclaw-plugin-sdk.js";
import { PolicyShieldClient } from "./client.js";
import type { PluginConfig } from "./types.js";

export { PolicyShieldClient } from "./client.js";

// Re-export SDK types that consumers may need
export type { OpenClawPluginApi, OpenClawPluginDefinition } from "./openclaw-plugin-sdk.js";

/**
 * PolicyShield plugin for OpenClaw.
 *
 * Intercepts tool calls at runtime to enforce declarative YAML-based
 * security policies: BLOCK, REDACT, APPROVE (human-in-the-loop), ALLOW.
 *
 * Conforms to the OpenClaw Plugin SDK — see openclaw/src/plugins/types.ts.
 */
const plugin: OpenClawPluginDefinition = {
    id: "policyshield",
    name: "PolicyShield",
    version: "0.7.0",
    description: "PolicyShield — runtime policy enforcement for AI agent tool calls",

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

        const client = new PolicyShieldClient(rawConfig, log);

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
            async (
                event: PluginHookBeforeToolCallEvent,
                ctx: PluginHookToolContext,
            ): Promise<PluginHookBeforeToolCallResult | void> => {
                const verdict = await client.check({
                    tool_name: event.toolName ?? "",
                    args: event.params ?? {},
                    session_id: ctx.sessionKey ?? "default",
                    sender: ctx.agentId,
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
            async (
                event: PluginHookAfterToolCallEvent,
                ctx: PluginHookToolContext,
            ): Promise<void> => {
                const resultStr =
                    typeof event.result === "string"
                        ? event.result
                        : JSON.stringify(event.result ?? "").slice(0, 10000);
                await client.postCheck({
                    tool_name: event.toolName ?? "",
                    args: event.params ?? {},
                    result: resultStr,
                    session_id: ctx.sessionKey ?? "default",
                });
            },
            { priority: 100 },
        );

        // ── before_agent_start: inject policy constraints ──────
        api.on(
            "before_agent_start",
            async (
                _event: PluginHookBeforeAgentStartEvent,
                _ctx: PluginHookAgentContext,
            ): Promise<PluginHookBeforeAgentStartResult | void> => {
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
