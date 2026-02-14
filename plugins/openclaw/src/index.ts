import { PolicyShieldClient } from "./client.js";
import type { PluginConfig } from "./types.js";

export { PolicyShieldClient } from "./client.js";

export default function register(ctx: { config: PluginConfig }) {
    const config = ctx.config ?? {};

    // Config validation
    if (config.url && typeof config.url !== "string") {
        console.error("[policyshield] Invalid config: url must be a string");
    }
    if (
        config.timeout_ms &&
        (config.timeout_ms < 100 || config.timeout_ms > 30000)
    ) {
        console.warn("[policyshield] timeout_ms should be between 100 and 30000");
    }

    const client = new PolicyShieldClient(config);

    // Async startup check (non-blocking)
    client
        .healthCheck()
        .then((ok: boolean) => {
            if (ok) {
                console.log("[policyshield] ✓ Connected to PolicyShield server");
            } else {
                console.warn(
                    "[policyshield] ⚠ PolicyShield server unreachable — running in degraded mode",
                );
            }
        })
        .catch(() => {
            console.warn(
                "[policyshield] ⚠ PolicyShield server unreachable — running in degraded mode",
            );
        });

    return {
        hooks: [
            {
                hookName: "before_tool_call" as const,
                priority: 100,
                async handler(
                    event: { toolName: string; params: Record<string, unknown> },
                    toolCtx: {
                        toolName: string;
                        agentId?: string;
                        sessionKey?: string;
                    },
                ) {
                    const verdict = await client.check({
                        tool_name: event.toolName,
                        args: event.params ?? {},
                        session_id: toolCtx.sessionKey ?? "default",
                        sender: toolCtx.agentId,
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
                    if (verdict.verdict === "APPROVE") {
                        return {
                            block: true,
                            blockReason: `⏳ PolicyShield: ${verdict.message} (approval required)`,
                        };
                    }
                    return undefined; // ALLOW
                },
            },
            {
                hookName: "after_tool_call" as const,
                priority: 100,
                async handler(
                    event: { toolName: string; params: unknown; result: unknown },
                    toolCtx: {
                        toolName: string;
                        agentId?: string;
                        sessionKey?: string;
                    },
                ) {
                    const resultStr =
                        typeof event.result === "string"
                            ? event.result
                            : JSON.stringify(event.result ?? "").slice(0, 10000);
                    await client.postCheck({
                        tool_name: event.toolName,
                        args: ((event.params ?? {}) as Record<string, unknown>),
                        result: resultStr,
                        session_id: toolCtx.sessionKey ?? "default",
                    });
                },
            },
            {
                hookName: "before_agent_start" as const,
                priority: 50,
                async handler() {
                    const constraints = await client.getConstraints();
                    if (!constraints) return undefined;
                    return {
                        prependContext: `\n## 🛡️ PolicyShield Active Rules\n${constraints}\n`,
                    };
                },
            },
        ],
    };
}
