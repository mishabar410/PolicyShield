/**
 * OpenClaw Compatibility Integration Test
 *
 * This test replicates the EXACT behavior of OpenClaw's plugin system:
 *   1. loader.ts → resolvePluginModuleExport(): resolves default export, calls register/activate
 *   2. registry.ts → createApi(): builds the OpenClawPluginApi with `on()` 
 *   3. hooks.ts → runBeforeToolCall/runAfterToolCall/runBeforeAgentStart: dispatches hooks
 *
 * The patterns below are copied from the real OpenClaw source code (Feb 2026).
 * If this test passes, our plugin will load and work in a real OpenClaw instance.
 */

import { describe, it, expect, vi, beforeAll } from "vitest";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";

// Import our plugin exactly as OpenClaw would (default export)
import pluginModule from "../src/index.js";

// ─── Types mirroring OpenClaw's internal structures ─────────────────────────

type PluginHookName =
    | "before_agent_start"
    | "agent_end"
    | "before_compaction"
    | "after_compaction"
    | "before_reset"
    | "message_received"
    | "message_sending"
    | "message_sent"
    | "before_tool_call"
    | "after_tool_call"
    | "tool_result_persist"
    | "session_start"
    | "session_end"
    | "gateway_start"
    | "gateway_stop";

type HookRegistration = {
    pluginId: string;
    hookName: PluginHookName;
    handler: (...args: unknown[]) => unknown;
    priority: number;
    source: string;
};

// ─── Replicate OpenClaw's resolvePluginModuleExport (from loader.ts) ────────

function resolvePluginModuleExport(moduleExport: unknown): {
    definition?: {
        id?: string;
        name?: string;
        version?: string;
        register?: (api: unknown) => void | Promise<void>;
        activate?: (api: unknown) => void | Promise<void>;
    };
    register?: (api: unknown) => void | Promise<void>;
} {
    const resolved =
        moduleExport &&
            typeof moduleExport === "object" &&
            "default" in (moduleExport as Record<string, unknown>)
            ? (moduleExport as { default: unknown }).default
            : moduleExport;
    if (typeof resolved === "function") {
        return {
            register: resolved as (api: unknown) => void | Promise<void>,
        };
    }
    if (resolved && typeof resolved === "object") {
        const def = resolved as {
            id?: string;
            name?: string;
            version?: string;
            register?: (api: unknown) => void | Promise<void>;
            activate?: (api: unknown) => void | Promise<void>;
        };
        const register = def.register ?? def.activate;
        return { definition: def, register };
    }
    return {};
}

// ─── Replicate OpenClaw's createApi (from registry.ts) ─────────────────────

function createOpenClawPluginApi(hooks: HookRegistration[], pluginConfig?: Record<string, unknown>) {
    const pluginId = "policyshield";
    return {
        id: pluginId,
        name: "PolicyShield",
        version: "0.8.1",
        description: "test",
        source: "/test/policyshield",
        config: {},            // OpenClawConfig — we don't use it
        pluginConfig,          // This is what api.pluginConfig provides
        runtime: { version: "2026.2.13" },
        logger: {
            debug: vi.fn(),
            info: vi.fn(),
            warn: vi.fn(),
            error: vi.fn(),
        },
        registerTool: vi.fn(),
        registerHook: vi.fn(),
        registerHttpHandler: vi.fn(),
        registerHttpRoute: vi.fn(),
        registerChannel: vi.fn(),
        registerGatewayMethod: vi.fn(),
        registerCli: vi.fn(),
        registerService: vi.fn(),
        registerProvider: vi.fn(),
        registerCommand: vi.fn(),
        resolvePath: (input: string) => input,
        // This is the critical method — replicates registry.ts createApi
        on: <K extends PluginHookName>(
            hookName: K,
            handler: (...args: unknown[]) => unknown,
            opts?: { priority?: number },
        ) => {
            hooks.push({
                pluginId,
                hookName,
                handler,
                priority: opts?.priority ?? 0,
                source: "/test/policyshield",
            });
        },
    };
}

// ─── Replicate OpenClaw's hook runners (from hooks.ts) ──────────────────────

function getHooksForName(hooks: HookRegistration[], hookName: PluginHookName): HookRegistration[] {
    return hooks
        .filter((h) => h.hookName === hookName)
        .sort((a, b) => (b.priority ?? 0) - (a.priority ?? 0));
}

/** Replicates hooks.ts runBeforeToolCall — sequential, merging results */
async function runBeforeToolCall(
    hooks: HookRegistration[],
    event: { toolName: string; params: Record<string, unknown> },
    ctx: { agentId?: string; sessionKey?: string; toolName: string },
): Promise<{ params?: Record<string, unknown>; block?: boolean; blockReason?: string } | undefined> {
    const matching = getHooksForName(hooks, "before_tool_call");
    let result: { params?: Record<string, unknown>; block?: boolean; blockReason?: string } | undefined;

    for (const hook of matching) {
        const handlerResult = (await hook.handler(event, ctx)) as
            | { params?: Record<string, unknown>; block?: boolean; blockReason?: string }
            | void;
        if (handlerResult !== undefined && handlerResult !== null) {
            if (result !== undefined) {
                result = {
                    params: handlerResult.params ?? result.params,
                    block: handlerResult.block ?? result.block,
                    blockReason: handlerResult.blockReason ?? result.blockReason,
                };
            } else {
                result = handlerResult;
            }
        }
    }
    return result;
}

/** Replicates hooks.ts runAfterToolCall — parallel, fire-and-forget */
async function runAfterToolCall(
    hooks: HookRegistration[],
    event: {
        toolName: string;
        params: Record<string, unknown>;
        result?: unknown;
        error?: string;
        durationMs?: number;
    },
    ctx: { agentId?: string; sessionKey?: string; toolName: string },
): Promise<void> {
    const matching = getHooksForName(hooks, "after_tool_call");
    await Promise.all(matching.map((h) => h.handler(event, ctx)));
}

/** Replicates hooks.ts runBeforeAgentStart — sequential, merging results */
async function runBeforeAgentStart(
    hooks: HookRegistration[],
    event: { prompt: string; messages?: unknown[] },
    ctx: { agentId?: string; sessionKey?: string; sessionId?: string; workspaceDir?: string; messageProvider?: string },
): Promise<{ systemPrompt?: string; prependContext?: string } | undefined> {
    const matching = getHooksForName(hooks, "before_agent_start");
    let result: { systemPrompt?: string; prependContext?: string } | undefined;

    for (const hook of matching) {
        const handlerResult = (await hook.handler(event, ctx)) as
            | { systemPrompt?: string; prependContext?: string }
            | void;
        if (handlerResult !== undefined && handlerResult !== null) {
            if (result !== undefined) {
                result = {
                    systemPrompt: handlerResult.systemPrompt ?? result.systemPrompt,
                    prependContext:
                        result.prependContext && handlerResult.prependContext
                            ? `${result.prependContext}\n\n${handlerResult.prependContext}`
                            : (handlerResult.prependContext ?? result.prependContext),
                };
            } else {
                result = handlerResult;
            }
        }
    }
    return result;
}

// ─── Mock PolicyShield Server ───────────────────────────────────────────────

function createMockPolicyShieldServer() {
    const server = createServer((req: IncomingMessage, res: ServerResponse) => {
        let body = "";
        req.on("data", (chunk) => (body += chunk));
        req.on("end", () => {
            const url = req.url ?? "";

            if (url === "/api/v1/health") {
                res.writeHead(200, { "Content-Type": "application/json" });
                res.end(JSON.stringify({ status: "ok" }));
                return;
            }

            if (url === "/api/v1/check") {
                const parsed = JSON.parse(body);
                // Block rm -rf
                if (parsed.tool_name === "exec" && JSON.stringify(parsed.args).includes("rm -rf")) {
                    res.writeHead(200, { "Content-Type": "application/json" });
                    res.end(JSON.stringify({
                        verdict: "BLOCK",
                        rule_id: "block-destructive",
                        message: "Destructive command blocked",
                    }));
                    return;
                }
                // Redact PII
                if (parsed.tool_name === "send_message" && JSON.stringify(parsed.args).includes("555-")) {
                    res.writeHead(200, { "Content-Type": "application/json" });
                    res.end(JSON.stringify({
                        verdict: "REDACT",
                        rule_id: "redact-pii",
                        message: "PII redacted",
                        modified_args: { content: "[REDACTED]" },
                    }));
                    return;
                }
                // Allow everything else
                res.writeHead(200, { "Content-Type": "application/json" });
                res.end(JSON.stringify({ verdict: "ALLOW", rule_id: "__default__", message: "" }));
                return;
            }

            if (url === "/api/v1/post-check") {
                const parsed = JSON.parse(body);
                const hasPII = (parsed.result ?? "").includes("john@");
                res.writeHead(200, { "Content-Type": "application/json" });
                res.end(JSON.stringify({
                    pii_detected: hasPII,
                    pii_types: hasPII ? ["email"] : [],
                }));
                return;
            }

            if (url === "/api/v1/constraints") {
                res.writeHead(200, { "Content-Type": "application/json" });
                res.end(JSON.stringify({
                    summary: "- exec: destructive commands are blocked\n- send_message: PII will be redacted",
                }));
                return;
            }

            res.writeHead(404);
            res.end();
        });
    });

    return server;
}

// ─── TESTS ──────────────────────────────────────────────────────────────────

describe("OpenClaw Compatibility Integration", () => {
    let server: ReturnType<typeof createMockPolicyShieldServer>;
    let serverUrl: string;

    beforeAll(async () => {
        server = createMockPolicyShieldServer();
        await new Promise<void>((resolve) => server.listen(0, resolve));
        const port = (server.address() as AddressInfo).port;
        serverUrl = `http://127.0.0.1:${port}`;

        return () => {
            server.close();
        };
    });

    describe("Step 1: Plugin Module Resolution (replicating loader.ts)", () => {
        it("resolves default export as OpenClawPluginDefinition", () => {
            // This is exactly what OpenClaw's loader.ts does:
            // const resolved = moduleExport.default ?? moduleExport
            const { definition, register } = resolvePluginModuleExport({ default: pluginModule });

            expect(definition).toBeDefined();
            expect(definition!.id).toBe("policyshield");
            expect(definition!.name).toBe("PolicyShield");
            expect(definition!.version).toBe("0.9.0");
            expect(register).toBeTypeOf("function");
        });

        it("resolves direct import as OpenClawPluginDefinition", () => {
            // Also handle case where the module is imported directly (no .default wrapper)
            const { definition, register } = resolvePluginModuleExport(pluginModule);

            expect(definition).toBeDefined();
            expect(definition!.id).toBe("policyshield");
            expect(register).toBeTypeOf("function");
        });
    });

    describe("Step 2: Plugin Registration (replicating registry.ts createApi)", () => {
        it("register() hooks into before_tool_call, after_tool_call, before_agent_start", async () => {
            const hooks: HookRegistration[] = [];
            const api = createOpenClawPluginApi(hooks, { url: serverUrl });

            // Call register — this is what OpenClaw does after resolving the module
            const { register } = resolvePluginModuleExport(pluginModule);
            await register!(api);

            // Wait for async health check to settle
            await new Promise((r) => setTimeout(r, 200));

            // Verify hooks were registered
            const hookNames = hooks.map((h) => h.hookName);
            expect(hookNames).toContain("before_tool_call");
            expect(hookNames).toContain("after_tool_call");
            expect(hookNames).toContain("before_agent_start");
            expect(hooks.length).toBe(3);

            // Verify priorities match what we expect
            const btc = hooks.find((h) => h.hookName === "before_tool_call");
            const atc = hooks.find((h) => h.hookName === "after_tool_call");
            const bas = hooks.find((h) => h.hookName === "before_agent_start");
            expect(btc!.priority).toBe(100);
            expect(atc!.priority).toBe(100);
            expect(bas!.priority).toBe(50);
        });
    });

    describe("Step 3: Hook Dispatch (replicating hooks.ts runners)", () => {
        let hooks: HookRegistration[];

        beforeAll(async () => {
            hooks = [];
            const api = createOpenClawPluginApi(hooks, { url: serverUrl });
            const { register } = resolvePluginModuleExport(pluginModule);
            await register!(api);
            await new Promise((r) => setTimeout(r, 200));
        });

        it("runBeforeToolCall BLOCKS destructive commands", async () => {
            const result = await runBeforeToolCall(
                hooks,
                { toolName: "exec", params: { command: "rm -rf /" } },
                { toolName: "exec", sessionKey: "sess-1", agentId: "test-agent" },
            );

            expect(result).toBeDefined();
            expect(result!.block).toBe(true);
            expect(result!.blockReason).toContain("PolicyShield");
            expect(result!.blockReason).toContain("Destructive command blocked");
        });

        it("runBeforeToolCall REDACTS PII and returns modified params", async () => {
            const result = await runBeforeToolCall(
                hooks,
                { toolName: "send_message", params: { content: "Call me at 555-1234" } },
                { toolName: "send_message", sessionKey: "sess-1" },
            );

            expect(result).toBeDefined();
            expect(result!.params).toEqual({ content: "[REDACTED]" });
            expect(result!.block).toBeUndefined();
        });

        it("runBeforeToolCall ALLOWS safe commands (returns undefined)", async () => {
            const result = await runBeforeToolCall(
                hooks,
                { toolName: "read_file", params: { path: "/tmp/safe.txt" } },
                { toolName: "read_file", sessionKey: "sess-1" },
            );

            // OpenClaw treats undefined return as "proceed normally"
            expect(result).toBeUndefined();
        });

        it("runAfterToolCall fires post-check (fire-and-forget)", async () => {
            // This should not throw — OpenClaw's hooks.ts runs this in parallel
            await expect(
                runAfterToolCall(
                    hooks,
                    {
                        toolName: "exec",
                        params: { command: "echo hello" },
                        result: "hello",
                        durationMs: 50,
                    },
                    { toolName: "exec", sessionKey: "sess-1" },
                ),
            ).resolves.toBeUndefined();
        });

        it("runAfterToolCall logs PII warning when PII detected in output", async () => {
            // Re-register to get fresh logger spy
            const localHooks: HookRegistration[] = [];
            const api = createOpenClawPluginApi(localHooks, { url: serverUrl });
            const { register } = resolvePluginModuleExport(pluginModule);
            await register!(api);
            await new Promise((r) => setTimeout(r, 200));

            await runAfterToolCall(
                localHooks,
                {
                    toolName: "exec",
                    params: { command: "cat contacts.txt" },
                    result: "Name: John, Email: john@example.com",
                    durationMs: 100,
                },
                { toolName: "exec", sessionKey: "sess-1" },
            );

            // Give the async post-check time to complete
            await new Promise((r) => setTimeout(r, 200));

            expect(api.logger.warn).toHaveBeenCalledWith(
                expect.stringContaining("PII detected"),
            );
        });

        it("runBeforeAgentStart injects policy constraints as prependContext", async () => {
            const result = await runBeforeAgentStart(
                hooks,
                { prompt: "You are a helpful assistant" },
                { agentId: "test-agent", sessionKey: "sess-1" },
            );

            expect(result).toBeDefined();
            expect(result!.prependContext).toContain("PolicyShield Active Rules");
            expect(result!.prependContext).toContain("destructive commands are blocked");
            // systemPrompt should NOT be set (we only use prependContext)
            expect(result!.systemPrompt).toBeUndefined();
        });
    });

    describe("Step 4: Edge Cases (fail-open, server down)", () => {
        it("runBeforeToolCall returns undefined (ALLOW) when server is unreachable", async () => {
            const hooks: HookRegistration[] = [];
            const api = createOpenClawPluginApi(hooks, {
                url: "http://127.0.0.1:1",  // unreachable
                fail_open: true,
                timeout_ms: 500,
            });
            const { register } = resolvePluginModuleExport(pluginModule);
            await register!(api);
            await new Promise((r) => setTimeout(r, 200));

            const result = await runBeforeToolCall(
                hooks,
                { toolName: "exec", params: { command: "rm -rf /" } },
                { toolName: "exec", sessionKey: "sess-1" },
            );

            // fail-open: tool call should proceed
            expect(result).toBeUndefined();
        });
    });
});
