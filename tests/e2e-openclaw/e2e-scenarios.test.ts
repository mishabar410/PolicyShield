/**
 * E2E Test Scenarios — Hook Dispatch Integration
 *
 * Five complete E2E scenarios testing the full cycle:
 *   OpenClaw hook dispatch → PolicyShield plugin → mock server → verdict
 *
 * Each scenario replicates the real OpenClaw hook runner patterns
 * (from hooks.ts) to ensure our plugin integrates correctly.
 *
 * Scenarios:
 *   1. BLOCK — destructive exec command
 *   2. REDACT — PII in tool args
 *   3. ALLOW — safe read_file
 *   4. APPROVE timeout — write to /etc, no approver responds
 *   5. Fail-open — server unreachable, tool call proceeds
 */

import { describe, it, expect, vi, beforeAll, afterAll } from "vitest";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";

// Import plugin (same as OpenClaw would)
import pluginModule from "../../plugins/openclaw/src/index.js";

// ─── OpenClaw Hook System Replica ───────────────────────────────────────────

type PluginHookName =
    | "before_tool_call"
    | "after_tool_call"
    | "before_agent_start";

type HookRegistration = {
    hookName: PluginHookName;
    handler: (...args: unknown[]) => unknown;
    priority: number;
};

function createMockApi(
    hooks: HookRegistration[],
    pluginConfig: Record<string, unknown>,
) {
    return {
        id: "policyshield",
        name: "PolicyShield",
        version: pluginModule.version,
        description: "e2e scenario test",
        source: "/e2e/policyshield",
        config: {},
        pluginConfig,
        runtime: { version: "2026.2.14" },
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
        on: <K extends PluginHookName>(
            hookName: K,
            handler: (...args: unknown[]) => unknown,
            opts?: { priority?: number },
        ) => {
            hooks.push({
                hookName,
                handler,
                priority: opts?.priority ?? 0,
            });
        },
    };
}

/** Replicate OpenClaw's sequential chain hook runner (hooks.ts) */
async function runChainHook(
    hooks: HookRegistration[],
    hookName: PluginHookName,
    event: Record<string, unknown>,
    ctx: Record<string, unknown>,
): Promise<Record<string, unknown> | undefined> {
    const matching = hooks
        .filter((h) => h.hookName === hookName)
        .sort((a, b) => b.priority - a.priority);

    let result: Record<string, unknown> | undefined;
    for (const hook of matching) {
        const r = (await hook.handler(event, ctx)) as Record<string, unknown> | void;
        if (r !== undefined && r !== null) {
            result = result ? { ...result, ...r } : r;
        }
    }
    return result;
}

/** Replicate OpenClaw's fire-and-forget void hook runner */
async function runVoidHook(
    hooks: HookRegistration[],
    hookName: PluginHookName,
    event: Record<string, unknown>,
    ctx: Record<string, unknown>,
): Promise<void> {
    const matching = hooks
        .filter((h) => h.hookName === hookName)
        .sort((a, b) => b.priority - a.priority);
    await Promise.all(matching.map((h) => h.handler(event, ctx)));
}

// ─── Mock PolicyShield Server ───────────────────────────────────────────────

function createScenarioServer() {
    let approvalStatus: "pending" | "approved" | "denied" = "pending";

    const setApprovalStatus = (s: typeof approvalStatus) => {
        approvalStatus = s;
    };

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

                // Scenario 1: BLOCK rm -rf
                if (
                    parsed.tool_name === "exec" &&
                    JSON.stringify(parsed.args).includes("rm -rf")
                ) {
                    res.writeHead(200, { "Content-Type": "application/json" });
                    res.end(
                        JSON.stringify({
                            verdict: "BLOCK",
                            rule_id: "block-rm",
                            message: "Destructive command blocked",
                        }),
                    );
                    return;
                }

                // Scenario 2: REDACT email PII
                if (
                    parsed.tool_name === "send_email" &&
                    JSON.stringify(parsed.args).includes("@")
                ) {
                    res.writeHead(200, { "Content-Type": "application/json" });
                    res.end(
                        JSON.stringify({
                            verdict: "REDACT",
                            rule_id: "redact-email",
                            message: "PII redacted",
                            modified_args: {
                                to: "[EMAIL REDACTED]",
                                body: parsed.args.body,
                            },
                        }),
                    );
                    return;
                }

                // Scenario 4: APPROVE for /etc writes
                if (
                    parsed.tool_name === "write_file" &&
                    JSON.stringify(parsed.args).includes("/etc/")
                ) {
                    res.writeHead(200, { "Content-Type": "application/json" });
                    res.end(
                        JSON.stringify({
                            verdict: "APPROVE",
                            rule_id: "approve-write",
                            message: "System file write requires approval",
                            approval_id: "apr-e2e-001",
                        }),
                    );
                    return;
                }

                // Scenario 3: ALLOW everything else
                res.writeHead(200, { "Content-Type": "application/json" });
                res.end(
                    JSON.stringify({
                        verdict: "ALLOW",
                        rule_id: "__default__",
                        message: "",
                    }),
                );
                return;
            }

            // Approval polling endpoint (client sends POST /api/v1/check-approval)
            if (url === "/api/v1/check-approval") {
                res.writeHead(200, { "Content-Type": "application/json" });
                res.end(
                    JSON.stringify({
                        approval_id: "apr-e2e-001",
                        status: approvalStatus,
                    }),
                );
                return;
            }

            if (url === "/api/v1/post-check") {
                res.writeHead(200, { "Content-Type": "application/json" });
                res.end(JSON.stringify({ pii_types: [] }));
                return;
            }

            if (url === "/api/v1/constraints") {
                res.writeHead(200, { "Content-Type": "application/json" });
                res.end(
                    JSON.stringify({
                        summary:
                            "- exec: destructive commands blocked\n- write_file: /etc writes need approval",
                    }),
                );
                return;
            }

            res.writeHead(404);
            res.end();
        });
    });

    return { server, setApprovalStatus };
}

// ─── E2E SCENARIOS ──────────────────────────────────────────────────────────

describe("E2E Scenarios: Full Hook Dispatch Cycle", () => {
    let server: ReturnType<typeof createScenarioServer>["server"];
    let setApprovalStatus: ReturnType<typeof createScenarioServer>["setApprovalStatus"];
    let serverUrl: string;

    beforeAll(async () => {
        const s = createScenarioServer();
        server = s.server;
        setApprovalStatus = s.setApprovalStatus;
        await new Promise<void>((resolve) => server.listen(0, resolve));
        const port = (server.address() as AddressInfo).port;
        serverUrl = `http://127.0.0.1:${port}`;
    });

    afterAll(() => {
        server.close();
    });

    // ── Scenario 1: BLOCK ──────────────────────────────────────────

    describe("Scenario 1: BLOCK — destructive exec command", () => {
        it("blocks rm -rf via before_tool_call hook", async () => {
            const hooks: HookRegistration[] = [];
            const api = createMockApi(hooks, { url: serverUrl });
            await pluginModule.register(api as any);
            await new Promise((r) => setTimeout(r, 200));

            const result = await runChainHook(
                hooks,
                "before_tool_call",
                { toolName: "exec", params: { command: "rm -rf /" } },
                { toolName: "exec", sessionKey: "e2e-sess-1", agentId: "e2e-agent" },
            );

            expect(result).toBeDefined();
            expect(result!.block).toBe(true);
            expect(result!.blockReason).toContain("PolicyShield");
            expect(result!.blockReason).toContain("Destructive command blocked");
        });
    });

    // ── Scenario 2: REDACT ─────────────────────────────────────────

    describe("Scenario 2: REDACT — email PII in tool args", () => {
        it("redacts email address and returns modified params", async () => {
            const hooks: HookRegistration[] = [];
            const api = createMockApi(hooks, { url: serverUrl });
            await pluginModule.register(api as any);
            await new Promise((r) => setTimeout(r, 200));

            const result = await runChainHook(
                hooks,
                "before_tool_call",
                {
                    toolName: "send_email",
                    params: { to: "secret@company.com", body: "Hello" },
                },
                { toolName: "send_email", sessionKey: "e2e-sess-2" },
            );

            expect(result).toBeDefined();
            expect(result!.block).toBeUndefined();
            expect(result!.params).toEqual({
                to: "[EMAIL REDACTED]",
                body: "Hello",
            });
        });
    });

    // ── Scenario 3: ALLOW ──────────────────────────────────────────

    describe("Scenario 3: ALLOW — safe read_file", () => {
        it("returns undefined (proceed) for safe operations", async () => {
            const hooks: HookRegistration[] = [];
            const api = createMockApi(hooks, { url: serverUrl });
            await pluginModule.register(api as any);
            await new Promise((r) => setTimeout(r, 200));

            const result = await runChainHook(
                hooks,
                "before_tool_call",
                { toolName: "read_file", params: { path: "/tmp/safe.txt" } },
                { toolName: "read_file", sessionKey: "e2e-sess-3" },
            );

            // undefined = proceed with tool call (OpenClaw convention)
            expect(result).toBeUndefined();
        });
    });

    // ── Scenario 4: APPROVE timeout ────────────────────────────────

    describe("Scenario 4: APPROVE timeout — no one approves /etc write", () => {
        it("blocks after approval timeout expires", async () => {
            const hooks: HookRegistration[] = [];
            const api = createMockApi(hooks, {
                url: serverUrl,
                approve_timeout_ms: 500, // Short timeout for test
                approve_poll_interval_ms: 100,
            });
            await pluginModule.register(api as any);
            await new Promise((r) => setTimeout(r, 200));

            // Keep approval status as "pending" — no one approves
            setApprovalStatus("pending");

            const start = Date.now();
            const result = await runChainHook(
                hooks,
                "before_tool_call",
                {
                    toolName: "write_file",
                    params: { path: "/etc/passwd", content: "hacked" },
                },
                { toolName: "write_file", sessionKey: "e2e-sess-4" },
            );
            const elapsed = Date.now() - start;

            expect(result).toBeDefined();
            expect(result!.block).toBe(true);
            expect(result!.blockReason).toContain("timed out");
            // Should have waited roughly the timeout period
            expect(elapsed).toBeGreaterThanOrEqual(400);
            expect(elapsed).toBeLessThan(2000);
        }, 10_000);

        it("allows when approval is granted before timeout", async () => {
            const hooks: HookRegistration[] = [];
            const api = createMockApi(hooks, {
                url: serverUrl,
                approve_timeout_ms: 3000,
                approve_poll_interval_ms: 100,
            });
            await pluginModule.register(api as any);
            await new Promise((r) => setTimeout(r, 200));

            // Approve after a short delay
            setApprovalStatus("pending");
            setTimeout(() => setApprovalStatus("approved"), 300);

            const result = await runChainHook(
                hooks,
                "before_tool_call",
                {
                    toolName: "write_file",
                    params: { path: "/etc/config.yaml", content: "safe: true" },
                },
                { toolName: "write_file", sessionKey: "e2e-sess-4b" },
            );

            // Approved → undefined means proceed
            expect(result).toBeUndefined();
        }, 10_000);

        it("blocks when approval is explicitly denied", async () => {
            const hooks: HookRegistration[] = [];
            const api = createMockApi(hooks, {
                url: serverUrl,
                approve_timeout_ms: 3000,
                approve_poll_interval_ms: 100,
            });
            await pluginModule.register(api as any);
            await new Promise((r) => setTimeout(r, 200));

            // Deny after a short delay
            setApprovalStatus("pending");
            setTimeout(() => setApprovalStatus("denied"), 300);

            const result = await runChainHook(
                hooks,
                "before_tool_call",
                {
                    toolName: "write_file",
                    params: { path: "/etc/hosts", content: "bad" },
                },
                { toolName: "write_file", sessionKey: "e2e-sess-4c" },
            );

            expect(result).toBeDefined();
            expect(result!.block).toBe(true);
            expect(result!.blockReason).toContain("denied");
        }, 10_000);
    });

    // ── Scenario 5: Fail-open ──────────────────────────────────────

    describe("Scenario 5: Fail-open — server unreachable", () => {
        it("allows tool call when server is down (fail_open=true)", async () => {
            const hooks: HookRegistration[] = [];
            const api = createMockApi(hooks, {
                url: "http://127.0.0.1:1", // unreachable
                fail_open: true,
                timeout_ms: 300,
            });
            await pluginModule.register(api as any);
            await new Promise((r) => setTimeout(r, 200));

            const result = await runChainHook(
                hooks,
                "before_tool_call",
                { toolName: "exec", params: { command: "rm -rf /" } },
                { toolName: "exec", sessionKey: "e2e-sess-5" },
            );

            // fail-open: proceed even for dangerous commands
            expect(result).toBeUndefined();
            // Should have warned about the error
            expect(api.logger.warn).toHaveBeenCalled();
        });

        it("after_tool_call does not throw when server unreachable", async () => {
            const hooks: HookRegistration[] = [];
            const api = createMockApi(hooks, {
                url: "http://127.0.0.1:1",
                fail_open: true,
                timeout_ms: 300,
            });
            await pluginModule.register(api as any);
            await new Promise((r) => setTimeout(r, 200));

            // after_tool_call should silently fail — fire-and-forget
            await expect(
                runVoidHook(
                    hooks,
                    "after_tool_call",
                    {
                        toolName: "exec",
                        params: { command: "echo hello" },
                        result: "hello",
                    },
                    { toolName: "exec", sessionKey: "e2e-sess-5b" },
                ),
            ).resolves.toBeUndefined();
        });
    });
});
