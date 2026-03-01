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
    PluginLogger,
} from "./openclaw-plugin-sdk.js";
import { PolicyShieldClient } from "./client.js";
import type { PluginConfig } from "./types.js";

export { PolicyShieldClient } from "./client.js";

// Re-export SDK types that consumers may need
export type { OpenClawPluginApi, OpenClawPluginDefinition } from "./openclaw-plugin-sdk.js";

/**
 * Polls the PolicyShield server for approval status with clean timeout handling.
 * Uses AbortController + Promise.race for cancellation instead of a raw while loop.
 */
async function waitForApproval(
    client: PolicyShieldClient,
    approvalId: string,
    timeoutMs: number,
    pollIntervalMs: number,
    log: PluginLogger,
): Promise<PluginHookBeforeToolCallResult | void> {
    const controller = new AbortController();
    const { signal } = controller;

    // Set hard timeout
    const timeoutHandle = setTimeout(() => controller.abort(), timeoutMs);

    try {
        while (!signal.aborted) {
            await new Promise<void>((resolve, reject) => {
                const timer = setTimeout(resolve, pollIntervalMs);
                signal.addEventListener("abort", () => {
                    clearTimeout(timer);
                    reject(new DOMException("Aborted", "AbortError"));
                }, { once: true });
            });

            try {
                const status = await client.checkApproval(approvalId);
                if (status.status === "approved") {
                    return undefined; // proceed with tool call
                }
                if (status.status === "denied") {
                    return {
                        block: true,
                        blockReason: `🛡️ PolicyShield: approval denied${status.responder ? ` by ${status.responder}` : ""}`,
                    };
                }
                // status === "pending" → continue polling
            } catch (pollErr) {
                log.warn(`Approval poll error: ${String(pollErr)}`);
            }
        }
    } catch {
        // AbortError from timeout — expected
    } finally {
        clearTimeout(timeoutHandle);
    }

    return {
        block: true,
        blockReason: `⏳ PolicyShield: approval timed out after ${timeoutMs / 1000}s`,
    };
}

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
    version: "0.9.0",
    description: "PolicyShield — runtime policy enforcement for AI agent tool calls",

    register(api: OpenClawPluginApi) {
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

        // Read configurable values (with defaults)
        const approveTimeoutMs = rawConfig.approve_timeout_ms ?? 60_000;
        const approvePollMs = rawConfig.approve_poll_interval_ms ?? 2_000;
        const maxResultBytes = rawConfig.max_result_bytes ?? 10_000;

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
                try {
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
                        return await waitForApproval(
                            client, verdict.approval_id,
                            approveTimeoutMs, approvePollMs, log,
                        );
                    }
                    return undefined; // ALLOW
                } catch (err) {
                    log.warn(`before_tool_call hook error: ${String(err)}`);
                    return undefined; // fail-open
                }
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
                try {
                    const resultStr =
                        typeof event.result === "string"
                            ? event.result.slice(0, maxResultBytes)
                            : JSON.stringify(event.result ?? "").slice(0, maxResultBytes);
                    const postResult = await client.postCheck({
                        tool_name: event.toolName ?? "",
                        args: event.params ?? {},
                        result: resultStr,
                        session_id: ctx.sessionKey ?? "default",
                    });
                    if (postResult && postResult.pii_types.length > 0) {
                        log.warn(
                            `PII detected in ${event.toolName} output: ${postResult.pii_types.join(", ")}`,
                        );
                    }
                } catch (err) {
                    log.warn(`after_tool_call hook error: ${String(err)}`);
                }
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
                try {
                    const constraints = await client.getConstraints();
                    if (!constraints) return undefined;
                    return {
                        prependContext: `\n## 🛡️ PolicyShield Active Rules\n${constraints}\n`,
                    };
                } catch (err) {
                    log.warn(`before_agent_start hook error: ${String(err)}`);
                    return undefined;
                }
            },
            { priority: 50 },
        );

        // ── /policyshield command: manage PolicyShield from chat ──
        api.registerCommand({
            name: "policyshield",
            description: "PolicyShield management: status, rules, kill, resume, reload, compile",
            acceptsArgs: true,
            requireAuth: true,
            handler: async (ctx: { args?: string }) => {
                const sub = ctx.args?.split(/\s+/)[0]?.toLowerCase();
                try {
                    switch (sub) {
                        case "status": {
                            const ok = await client.healthCheck();
                            return {
                                text: ok
                                    ? "🛡️ PolicyShield: ✅ online"
                                    : "🛡️ PolicyShield: ❌ unreachable",
                            };
                        }
                        case "rules": {
                            const status = await client.getStatus();
                            const constraints = await client.getConstraints();
                            let text = `🛡️ PolicyShield: ${status.rules_count} rules (${status.mode})`;
                            if (status.killed) text += " ⛔ KILLED";
                            if (constraints) text += "\n\n" + constraints;
                            return { text };
                        }
                        case "kill": {
                            const reason = ctx.args?.slice(4).trim() || "Telegram kill switch";
                            await client.kill(reason);
                            return {
                                text: "🛡️ PolicyShield: 🔴 KILLED — all tool calls blocked",
                            };
                        }
                        case "resume": {
                            await client.resume();
                            return {
                                text: "🛡️ PolicyShield: 🟢 Resumed — normal operation",
                            };
                        }
                        case "reload": {
                            await client.reload();
                            return {
                                text: "🛡️ PolicyShield: 🔄 Rules reloaded",
                            };
                        }
                        case "compile": {
                            const desc = ctx.args?.slice(7).trim();
                            if (!desc) {
                                return {
                                    text: "Usage: /policyshield compile <description>\n\nExample: /policyshield compile Block all file deletions in production",
                                };
                            }
                            const result = await client.compile(desc);
                            if (result.is_valid) {
                                return {
                                    text: `✅ Generated rule:\n\`\`\`yaml\n${result.yaml_text}\n\`\`\``,
                                };
                            }
                            return {
                                text: `❌ Compilation failed:\n${result.errors.join("\n")}`,
                            };
                        }
                        case "apply": {
                            const desc = ctx.args?.slice(5).trim();
                            if (!desc) {
                                return {
                                    text: "Usage: /policyshield apply <description>\n\nCompiles, saves, and reloads rules.\nExample: /policyshield apply Allow file reads in staging",
                                };
                            }
                            const result = await client.compileAndApply(desc);
                            if (result.applied) {
                                return {
                                    text: `✅ Rule applied! (${result.rules_count} total rules)\n\`\`\`yaml\n${result.yaml_text}\n\`\`\``,
                                };
                            }
                            if (result.errors.length > 0) {
                                return {
                                    text: `❌ Apply failed:\n${result.errors.join("\n")}`,
                                };
                            }
                            return {
                                text: `❌ Compilation failed:\n${result.errors.join("\n")}`,
                            };
                        }
                        default:
                            return {
                                text: "Usage: /policyshield {status|rules|kill|resume|reload|compile|apply}",
                            };
                    }
                } catch (err) {
                    return {
                        text: `🛡️ PolicyShield: ⚠️ command failed — ${String(err)}`,
                    };
                }
            },
        });
    },
};

export default plugin;
