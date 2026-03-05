/**
 * Real Server E2E Tests — Plugin ↔ Real PolicyShield Server
 *
 * Unlike e2e-scenarios.test.ts which uses a mock Node.js HTTP server,
 * this test spawns a REAL PolicyShield Python server process and tests
 * the full integration: OpenClaw plugin → HTTP → real engine evaluation.
 *
 * This runs WITHOUT Docker, WITHOUT OpenClaw, WITHOUT LLM API keys.
 * It can be included in CI on every PR.
 *
 * Scenarios:
 *   1. Health check — server is up and reports correct rule count
 *   2. BLOCK — destructive exec command evaluated by real engine
 *   3. REDACT — PII email detected by real PII detector
 *   4. ALLOW — safe tool call passes through
 *   5. APPROVE — /etc write returns approval_id from real engine
 *   6. Kill switch — kill and resume via real API
 *   7. Hot reload — reload rules via real API
 *   8. Post-check — PII detection in tool output
 *   9. Constraints — real policy summary from engine
 *  10. Full hook cycle — before_agent_start + before_tool_call + after_tool_call
 *  11. /policyshield commands — status, rules
 *  12. Status and rules endpoints
 */

import { describe, it, expect, vi, beforeAll, afterAll } from "vitest";
import { spawn, execSync, type ChildProcess } from "node:child_process";
import { resolve } from "node:path";
import { existsSync } from "node:fs";

// Import the real plugin
import pluginModule from "../../plugins/openclaw/src/index.js";

// ─── Types ──────────────────────────────────────────────────────────────────

type PluginHookName =
    | "before_tool_call"
    | "after_tool_call"
    | "before_agent_start";

type HookRegistration = {
    hookName: PluginHookName;
    handler: (...args: unknown[]) => unknown;
    priority: number;
};

// ─── OpenClaw Hook Runner Replica ───────────────────────────────────────────

function createMockApi(
    hooks: HookRegistration[],
    pluginConfig: Record<string, unknown>,
) {
    return {
        id: "policyshield",
        name: "PolicyShield",
        version: pluginModule.version,
        description: "real-server e2e",
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

// ─── Server Management ─────────────────────────────────────────────────────

const RULES_PATH = resolve(__dirname, "rules/e2e-rules.yaml");
const PORT = 18199; // Non-standard port to avoid conflicts
const SERVER_URL = `http://127.0.0.1:${PORT}`;
const STARTUP_TIMEOUT = 15_000; // 15s for server startup
const HEALTH_POLL_INTERVAL = 300; // 300ms between health polls

let serverProcess: ChildProcess | null = null;

/** Find the policyshield CLI executable — venv if available, else system */
function findPolicyShieldCmd(): { cmd: string; args: string[] } {
    // Try venv first
    const venvBin = resolve(__dirname, "../../.venv/bin/policyshield");
    if (existsSync(venvBin)) {
        return { cmd: venvBin, args: [] };
    }
    // CI: policyshield installed globally via pip
    try {
        execSync("policyshield --version", { stdio: "ignore" });
        return { cmd: "policyshield", args: [] };
    } catch {
        // Fallback: invoke via python -c
        const pythonCandidates = ["python3", "python"];
        for (const py of pythonCandidates) {
            try {
                execSync(`${py} -c "from policyshield.cli.main import app"`, { stdio: "ignore" });
                return {
                    cmd: py,
                    args: ["-c", "import sys; from policyshield.cli.main import app; sys.exit(app())"],
                };
            } catch {
                // try next
            }
        }
    }
    throw new Error(
        "Cannot find policyshield CLI. " +
        "Either create a .venv or pip install policyshield[server].",
    );
}

async function startServer(): Promise<void> {
    const { cmd, args: extraArgs } = findPolicyShieldCmd();

    serverProcess = spawn(
        cmd,
        [
            ...extraArgs,
            "server",
            "--rules", RULES_PATH,
            "--port", String(PORT),
            "--host", "127.0.0.1",
        ],
        {
            cwd: resolve(__dirname, "../.."),
            env: {
                ...process.env,
                POLICYSHIELD_MODE: "enforce",
                POLICYSHIELD_API_RATE_LIMIT: "1000", // Higher limit for tests
                POLICYSHIELD_MAX_CONCURRENT_CHECKS: "100",
            },
            stdio: ["pipe", "pipe", "pipe"],
        },
    );

    // Collect stderr for debugging
    let stderr = "";
    serverProcess.stderr!.on("data", (data: Buffer) => {
        stderr += data.toString();
    });
    let stdout = "";
    serverProcess.stdout!.on("data", (data: Buffer) => {
        stdout += data.toString();
    });

    serverProcess.on("error", (err: Error) => {
        throw new Error(`Failed to start PolicyShield server: ${err.message}\nstderr: ${stderr}\nstdout: ${stdout}`);
    });

    // Wait for server to become healthy
    const deadline = Date.now() + STARTUP_TIMEOUT;
    while (Date.now() < deadline) {
        // Check if process exited early
        if (serverProcess.exitCode !== null) {
            throw new Error(
                `PolicyShield server exited with code ${serverProcess.exitCode}\n` +
                `stdout: ${stdout}\nstderr: ${stderr}`,
            );
        }

        try {
            const res = await fetch(`${SERVER_URL}/api/v1/health`, {
                signal: AbortSignal.timeout(1000),
            });
            if (res.ok) {
                return; // Server is up!
            }
        } catch {
            // Not ready yet
        }
        await new Promise((r) => setTimeout(r, HEALTH_POLL_INTERVAL));
    }

    // Timeout — dump logs and fail
    stopServer();
    throw new Error(
        `PolicyShield server failed to start within ${STARTUP_TIMEOUT}ms.\n` +
        `stdout: ${stdout}\nstderr: ${stderr}`,
    );
}

function stopServer(): void {
    if (serverProcess && !serverProcess.killed) {
        serverProcess.kill("SIGTERM");
        // Give it a moment, then force kill
        setTimeout(() => {
            if (serverProcess && !serverProcess.killed) {
                serverProcess.kill("SIGKILL");
            }
        }, 3000);
    }
    serverProcess = null;
}

// ─── Helper ─────────────────────────────────────────────────────────────────

/** Register plugin and wait for non-blocking health check to complete */
async function registerPlugin(
    hooks: HookRegistration[],
    config: Record<string, unknown> = {},
): Promise<ReturnType<typeof createMockApi>> {
    const api = createMockApi(hooks, { url: SERVER_URL, ...config });
    await pluginModule.register(api as any);
    await new Promise((r) => setTimeout(r, 500));
    return api;
}

// ─── TESTS ──────────────────────────────────────────────────────────────────

describe("Real Server E2E: Plugin ↔ PolicyShield Server", () => {
    // Start real server before all tests
    beforeAll(async () => {
        await startServer();
    }, 20_000);

    afterAll(() => {
        stopServer();
    });

    // ── Scenario 1: Health check ───────────────────────────────────

    describe("Scenario 1: Server health and configuration", () => {
        it("server responds to health check with correct rule count", async () => {
            const res = await fetch(`${SERVER_URL}/api/v1/health`);
            expect(res.ok).toBe(true);

            const data = (await res.json()) as { rules_count: number; mode: string };
            expect(data.rules_count).toBe(4);
            expect(data.mode).toBe("ENFORCE");
        });

        it("server exposes K8s probes", async () => {
            const [liveness, readiness] = await Promise.all([
                fetch(`${SERVER_URL}/healthz`),
                fetch(`${SERVER_URL}/readyz`),
            ]);
            expect(liveness.ok).toBe(true);
            expect(readiness.ok).toBe(true);
        });
    });

    // ── Scenario 2: BLOCK — real engine evaluation ─────────────────

    describe("Scenario 2: BLOCK — destructive exec via real engine", () => {
        it("blocks rm -rf through real PolicyShield engine", async () => {
            const hooks: HookRegistration[] = [];
            await registerPlugin(hooks);

            const result = await runChainHook(
                hooks,
                "before_tool_call",
                { toolName: "exec", params: { command: "rm -rf /" } },
                { toolName: "exec", sessionKey: "real-e2e-1", agentId: "e2e-agent" },
            );

            expect(result).toBeDefined();
            expect(result!.block).toBe(true);
            expect(result!.blockReason).toContain("PolicyShield");
            expect(String(result!.blockReason)).toMatch(/destructive|block/i);
        });

        it("blocks env dump through real engine", async () => {
            const hooks: HookRegistration[] = [];
            await registerPlugin(hooks);

            const result = await runChainHook(
                hooks,
                "before_tool_call",
                { toolName: "exec", params: { command: "printenv" } },
                { toolName: "exec", sessionKey: "real-e2e-1b" },
            );

            expect(result).toBeDefined();
            expect(result!.block).toBe(true);
            expect(String(result!.blockReason)).toMatch(/environment|block/i);
        });
    });

    // ── Scenario 3: REDACT — real PII detection ────────────────────

    describe("Scenario 3: REDACT — real PII detection by engine", () => {
        it("redacts email via real PII detector", async () => {
            const hooks: HookRegistration[] = [];
            await registerPlugin(hooks);

            const result = await runChainHook(
                hooks,
                "before_tool_call",
                {
                    toolName: "send_message",
                    params: { text: "Contact me at admin@company.com for details" },
                },
                { toolName: "send_message", sessionKey: "real-e2e-2" },
            );

            // REDACT returns modified params
            expect(result).toBeDefined();
            expect(result!.block).toBeUndefined();
            expect(result!.params).toBeDefined();

            // The modified args should have the email redacted (masked)
            const modifiedParams = result!.params as Record<string, string>;
            expect(modifiedParams.text).not.toContain("admin@company.com");
        });
    });

    // ── Scenario 4: ALLOW — safe tool call ─────────────────────────

    describe("Scenario 4: ALLOW — safe tool passes through", () => {
        it("allows safe read_file through real engine", async () => {
            const hooks: HookRegistration[] = [];
            await registerPlugin(hooks);

            const result = await runChainHook(
                hooks,
                "before_tool_call",
                { toolName: "read_file", params: { path: "/tmp/safe.txt" } },
                { toolName: "read_file", sessionKey: "real-e2e-3" },
            );

            // ALLOW returns undefined (proceed)
            expect(result).toBeUndefined();
        });

        it("allows safe exec (no dangerous pattern)", async () => {
            const hooks: HookRegistration[] = [];
            await registerPlugin(hooks);

            const result = await runChainHook(
                hooks,
                "before_tool_call",
                { toolName: "exec", params: { command: "echo hello" } },
                { toolName: "exec", sessionKey: "real-e2e-3b" },
            );

            expect(result).toBeUndefined();
        });
    });

    // ── Scenario 5: APPROVE — real approval flow ───────────────────

    describe("Scenario 5: APPROVE — /etc write returns approval ID", () => {
        it("returns APPROVE verdict with approval_id for /etc write via API", async () => {
            const res = await fetch(`${SERVER_URL}/api/v1/check`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    tool_name: "write_file",
                    args: { path: "/etc/hosts", content: "bad" },
                    session_id: "real-e2e-5",
                }),
            });
            expect(res.ok).toBe(true);
            const data = (await res.json()) as { verdict: string; approval_id?: string };
            expect(data.verdict).toBe("APPROVE");
            expect(data.approval_id).toBeDefined();
        });
    });

    // ── Scenario 6: Kill switch ────────────────────────────────────

    describe("Scenario 6: Kill switch — real kill/resume cycle", () => {
        it("kill blocks all tool calls, resume restores", async () => {
            // 1. Kill
            const killRes = await fetch(`${SERVER_URL}/api/v1/kill`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ reason: "E2E test" }),
            });
            expect(killRes.ok).toBe(true);

            // 2. Verify a safe tool call is now BLOCKED
            const checkRes = await fetch(`${SERVER_URL}/api/v1/check`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    tool_name: "read_file",
                    args: { path: "/tmp/safe.txt" },
                    session_id: "real-e2e-6",
                }),
            });
            const checkData = (await checkRes.json()) as { verdict: string };
            expect(checkData.verdict).toBe("BLOCK");

            // 3. Resume
            const resumeRes = await fetch(`${SERVER_URL}/api/v1/resume`, {
                method: "POST",
            });
            expect(resumeRes.ok).toBe(true);

            // 4. Verify tool calls work again
            const afterRes = await fetch(`${SERVER_URL}/api/v1/check`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    tool_name: "read_file",
                    args: { path: "/tmp/safe.txt" },
                    session_id: "real-e2e-6b",
                }),
            });
            const afterData = (await afterRes.json()) as { verdict: string };
            expect(afterData.verdict).toBe("ALLOW");
        });
    });

    // ── Scenario 7: Hot reload ─────────────────────────────────────

    describe("Scenario 7: Hot reload — reload rules from disk", () => {
        it("reload endpoint returns updated rule count", async () => {
            const res = await fetch(`${SERVER_URL}/api/v1/reload`, {
                method: "POST",
            });
            expect(res.ok).toBe(true);
            const data = (await res.json()) as { rules_count: number; rules_hash: string };
            expect(data.rules_count).toBe(4);
            expect(data.rules_hash).toBeDefined();
            expect(typeof data.rules_hash).toBe("string");
        });
    });

    // ── Scenario 8: Post-check PII detection ───────────────────────

    describe("Scenario 8: Post-check — PII in tool output", () => {
        it("detects email PII in tool output via post-check", async () => {
            const res = await fetch(`${SERVER_URL}/api/v1/post-check`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    tool_name: "exec",
                    args: {},
                    result: "User: John, email: john.doe@example.com, phone: 555-1234",
                    session_id: "real-e2e-8",
                }),
            });
            expect(res.ok).toBe(true);
            const data = (await res.json()) as { pii_types: string[] };
            expect(data.pii_types).toContain("EMAIL");
        });
    });

    // ── Scenario 9: Constraints / policy summary ───────────────────

    describe("Scenario 9: Constraints — real policy summary", () => {
        it("returns non-empty policy summary from real engine", async () => {
            const res = await fetch(`${SERVER_URL}/api/v1/constraints`);
            expect(res.ok).toBe(true);
            const data = (await res.json()) as { summary: string };
            expect(data.summary).toBeDefined();
            expect(data.summary.length).toBeGreaterThan(0);
            // Should mention our rules
            expect(data.summary).toContain("block-rm");
        });
    });

    // ── Scenario 10: Full hook lifecycle ────────────────────────────

    describe("Scenario 10: Full hook lifecycle — agent start + tool + post", () => {
        it("runs complete agent lifecycle: start → tool check → post check", async () => {
            const hooks: HookRegistration[] = [];
            const api = await registerPlugin(hooks);

            // 1. before_agent_start — should inject constraints
            const agentResult = await runChainHook(
                hooks,
                "before_agent_start",
                {},
                { agentId: "lifecycle-agent", sessionKey: "real-e2e-10" },
            );

            // Should return prependContext with policy summary
            expect(agentResult).toBeDefined();
            expect(agentResult!.prependContext).toBeDefined();
            const context = agentResult!.prependContext as string;
            expect(context).toContain("PolicyShield");

            // 2. before_tool_call — safe call → ALLOW
            const toolResult = await runChainHook(
                hooks,
                "before_tool_call",
                { toolName: "read_file", params: { path: "/tmp/data.txt" } },
                { toolName: "read_file", sessionKey: "real-e2e-10" },
            );
            expect(toolResult).toBeUndefined(); // ALLOW

            // 3. after_tool_call — post-check with PII email in output
            await expect(
                runVoidHook(
                    hooks,
                    "after_tool_call",
                    {
                        toolName: "read_file",
                        params: { path: "/tmp/data.txt" },
                        result: "Content: user@example.com is the admin",
                    },
                    { toolName: "read_file", sessionKey: "real-e2e-10" },
                ),
            ).resolves.toBeUndefined();

            // Verify the PII warning was logged
            expect(api.logger.warn).toHaveBeenCalledWith(
                expect.stringContaining("PII detected"),
            );
        });
    });

    // ── Scenario 11: Plugin /policyshield command ──────────────────

    describe("Scenario 11: /policyshield commands via real server", () => {
        it("status command returns online", async () => {
            const hooks: HookRegistration[] = [];
            let registeredCommand: { name: string; handler: (ctx: { args?: string }) => Promise<{ text: string }> } | null = null;
            const api = createMockApi(hooks, { url: SERVER_URL });
            api.registerCommand = vi.fn((cmd: any) => {
                registeredCommand = cmd;
            });

            await pluginModule.register(api as any);
            await new Promise((r) => setTimeout(r, 500));

            expect(registeredCommand).not.toBeNull();
            expect(registeredCommand!.name).toBe("policyshield");

            const result = await registeredCommand!.handler({ args: "status" });
            expect(result.text).toContain("online");
        });

        it("rules command returns rule count", async () => {
            const hooks: HookRegistration[] = [];
            let registeredCommand: { name: string; handler: (ctx: { args?: string }) => Promise<{ text: string }> } | null = null;
            const api = createMockApi(hooks, { url: SERVER_URL });
            api.registerCommand = vi.fn((cmd: any) => {
                registeredCommand = cmd;
            });

            await pluginModule.register(api as any);
            await new Promise((r) => setTimeout(r, 500));

            const result = await registeredCommand!.handler({ args: "rules" });
            expect(result.text).toContain("4 rules");
        });
    });

    // ── Scenario 12: Server status endpoint ────────────────────────

    describe("Scenario 12: Status and rules endpoints", () => {
        it("status endpoint returns correct state", async () => {
            const res = await fetch(`${SERVER_URL}/api/v1/status`);
            expect(res.ok).toBe(true);
            const data = (await res.json()) as Record<string, unknown>;
            expect(data.status).toBe("running");
            expect(data.killed).toBe(false);
            expect(data.mode).toBe("ENFORCE");
            expect(data.rules_count).toBe(4);
        });

        it("rules endpoint lists all rules", async () => {
            const res = await fetch(`${SERVER_URL}/api/v1/rules`);
            expect(res.ok).toBe(true);
            const data = (await res.json()) as { rules: Array<{ id: string }>; count: number };
            expect(data.count).toBe(4);
            const ids = data.rules.map((r) => r.id);
            expect(ids).toContain("block-rm");
            expect(ids).toContain("redact-pii-messages");
            expect(ids).toContain("approve-etc-write");
            expect(ids).toContain("block-env-dump");
        });
    });
});
