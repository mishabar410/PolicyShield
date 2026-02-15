import { describe, it, expect, vi, afterEach } from "vitest";
import plugin, { type OpenClawPluginApi } from "../src/index.js";

function mockFetch(response: unknown, status = 200) {
    return vi.spyOn(globalThis, "fetch").mockResolvedValue({
        ok: status >= 200 && status < 300,
        status,
        statusText: status === 200 ? "OK" : "Error",
        json: async () => response,
    } as Response);
}

function mockFetchError() {
    return vi
        .spyOn(globalThis, "fetch")
        .mockRejectedValue(new Error("ECONNREFUSED"));
}

type HookHandler = (...args: unknown[]) => unknown;

/** Create a mock OpenClaw Plugin API that matches the real shape. */
function createMockApi(config: Record<string, unknown> = {}) {
    const hooks = new Map<string, { handler: HookHandler; priority?: number }>();
    const logs: string[] = [];
    const api = {
        id: "policyshield",
        name: "PolicyShield",
        source: "test",
        config: {},
        pluginConfig: config,
        runtime: {},
        logger: {
            info: (msg: string) => logs.push(`INFO: ${msg}`),
            warn: (msg: string) => logs.push(`WARN: ${msg}`),
            debug: (msg: string) => logs.push(`DEBUG: ${msg}`),
            error: (msg: string) => logs.push(`ERROR: ${msg}`),
        },
        registerTool: () => { },
        registerHook: () => { },
        registerHttpHandler: () => { },
        registerHttpRoute: () => { },
        registerChannel: () => { },
        registerGatewayMethod: () => { },
        registerCli: () => { },
        registerService: () => { },
        registerProvider: () => { },
        registerCommand: () => { },
        resolvePath: (input: string) => input,
        on: (hookName: string, handler: HookHandler, opts?: { priority?: number }) => {
            hooks.set(hookName, { handler, priority: opts?.priority });
        },
    } as unknown as OpenClawPluginApi;
    return { api, hooks, logs };
}

describe("Plugin Registration (api.on pattern)", () => {
    afterEach(() => {
        vi.restoreAllMocks();
    });

    it("registers three hooks via api.on()", async () => {
        mockFetch({}, 200); // health check
        const { api, hooks } = createMockApi({ mode: "disabled" });
        await plugin.register!(api);
        expect(hooks.size).toBe(3);
        expect(hooks.has("before_tool_call")).toBe(true);
        expect(hooks.has("after_tool_call")).toBe(true);
        expect(hooks.has("before_agent_start")).toBe(true);
    });

    it("sets correct priorities", async () => {
        mockFetch({}, 200);
        const { api, hooks } = createMockApi({ mode: "disabled" });
        await plugin.register!(api);
        expect(hooks.get("before_tool_call")?.priority).toBe(100);
        expect(hooks.get("after_tool_call")?.priority).toBe(100);
        expect(hooks.get("before_agent_start")?.priority).toBe(50);
    });

    it("exports correct metadata", () => {
        expect(plugin.id).toBe("policyshield");
        expect(plugin.name).toBe("PolicyShield");
        expect(plugin.version).toBe("0.9.0");
        expect(plugin.description).toContain("PolicyShield");
    });
});

describe("before_tool_call hook", () => {
    afterEach(() => {
        vi.restoreAllMocks();
    });

    it("BLOCK verdict", async () => {
        mockFetch({ verdict: "BLOCK", message: "dangerous" });
        const { api, hooks } = createMockApi({});
        await plugin.register!(api);
        const handler = hooks.get("before_tool_call")!.handler;
        const result = await handler(
            { toolName: "rm", params: {} },
            { sessionKey: "sess-1", agentId: "agent-1", toolName: "rm" },
        );
        expect(result).toEqual({
            block: true,
            blockReason: expect.stringContaining("PolicyShield"),
        });
    });

    it("REDACT verdict", async () => {
        mockFetch({
            verdict: "REDACT",
            message: "pii",
            modified_args: { x: "***" },
        });
        const { api, hooks } = createMockApi({});
        await plugin.register!(api);
        const handler = hooks.get("before_tool_call")!.handler;
        const result = await handler(
            { toolName: "send", params: { x: "secret" } },
            { sessionKey: "sess-1", agentId: "agent-1", toolName: "send" },
        );
        expect(result).toEqual({ params: { x: "***" } });
    });

    it("ALLOW verdict", async () => {
        mockFetch({ verdict: "ALLOW", message: "" });
        const { api, hooks } = createMockApi({});
        await plugin.register!(api);
        const handler = hooks.get("before_tool_call")!.handler;
        const result = await handler(
            { toolName: "echo", params: {} },
            { sessionKey: "sess-1", agentId: "agent-1", toolName: "echo" },
        );
        expect(result).toBeUndefined();
    });

    it("APPROVE verdict — approved via polling", async () => {
        vi.spyOn(globalThis, "fetch").mockImplementation(async (url) => {
            const urlStr = String(url);
            if (urlStr.includes("/check-approval")) {
                return {
                    ok: true,
                    json: async () => ({
                        approval_id: "apr-1",
                        status: "approved",
                    }),
                } as Response;
            }
            return {
                ok: true,
                json: async () => ({
                    verdict: "APPROVE",
                    message: "needs approval",
                    approval_id: "apr-1",
                }),
            } as Response;
        });

        const { api, hooks } = createMockApi({});
        await plugin.register!(api);
        const handler = hooks.get("before_tool_call")!.handler;
        const result = await handler(
            { toolName: "deploy", params: {} },
            { sessionKey: "sess-1", agentId: "agent-1", toolName: "deploy" },
        );
        expect(result).toBeUndefined(); // approved → proceed
    });

    it("APPROVE verdict — denied via polling", async () => {
        vi.spyOn(globalThis, "fetch").mockImplementation(async (url) => {
            const urlStr = String(url);
            if (urlStr.includes("/check-approval")) {
                return {
                    ok: true,
                    json: async () => ({
                        approval_id: "apr-2",
                        status: "denied",
                        responder: "admin",
                    }),
                } as Response;
            }
            return {
                ok: true,
                json: async () => ({
                    verdict: "APPROVE",
                    message: "needs approval",
                    approval_id: "apr-2",
                }),
            } as Response;
        });

        const { api, hooks } = createMockApi({});
        await plugin.register!(api);
        const handler = hooks.get("before_tool_call")!.handler;
        const result = await handler(
            { toolName: "deploy", params: {} },
            { sessionKey: "sess-1", agentId: "agent-1", toolName: "deploy" },
        );
        expect(result).toEqual({
            block: true,
            blockReason: expect.stringContaining("denied"),
        });
    });

    it("hook error fails open — returns undefined", async () => {
        // The client.check() has its own try-catch, so to trigger the *hook-level*
        // catch we need an error outside the client call. We do this via a Proxy
        // that throws on property access for the event object.
        mockFetch({}, 200); // health check
        const { api, hooks, logs } = createMockApi({});
        await plugin.register!(api);
        const handler = hooks.get("before_tool_call")!.handler;

        const badEvent = new Proxy(
            {},
            {
                get() {
                    throw new Error("synthetic hook error");
                },
            },
        );
        const result = await handler(
            badEvent,
            { sessionKey: "sess-1", agentId: "agent-1", toolName: "test" },
        );
        expect(result).toBeUndefined(); // fail-open
        expect(logs.some((l) => l.includes("before_tool_call hook error"))).toBe(true);
    });
});

describe("after_tool_call hook", () => {
    afterEach(() => {
        vi.restoreAllMocks();
    });

    it("sends post-check", async () => {
        const spy = mockFetch({ pii_types: [] });
        const { api, hooks } = createMockApi({ mode: "disabled" });
        await plugin.register!(api);
        const handler = hooks.get("after_tool_call")!.handler;
        await handler(
            { toolName: "echo", params: { x: 1 }, result: "ok" },
            { sessionKey: "sess-1", agentId: "agent-1", toolName: "echo" },
        );
        const calls = spy.mock.calls.filter((c) =>
            String(c[0]).includes("/post-check"),
        );
        expect(calls.length).toBe(1);
    });

    it("handles non-string result", async () => {
        const spy = mockFetch({ pii_types: [] });
        const { api, hooks } = createMockApi({ mode: "disabled" });
        await plugin.register!(api);
        const handler = hooks.get("after_tool_call")!.handler;
        await handler(
            {
                toolName: "query",
                params: {},
                result: { rows: [1, 2, 3] },
            },
            { sessionKey: "sess-1", agentId: "agent-1", toolName: "query" },
        );
        const calls = spy.mock.calls.filter((c) =>
            String(c[0]).includes("/post-check"),
        );
        expect(calls.length).toBe(1);
        const body = JSON.parse(calls[0][1]!.body as string);
        expect(body.result).toContain("rows");
    });
});

describe("before_agent_start hook", () => {
    afterEach(() => {
        vi.restoreAllMocks();
    });

    it("injects constraints", async () => {
        mockFetch({ summary: "No file deletions allowed" });
        const { api, hooks } = createMockApi({ mode: "disabled" });
        await plugin.register!(api);
        const handler = hooks.get("before_agent_start")!.handler;
        const result = (await handler(
            { prompt: "help me" },
            { agentId: "a1", sessionKey: "sess-1" },
        )) as { prependContext: string } | undefined;
        expect(result).toBeDefined();
        expect(result!.prependContext).toContain("PolicyShield");
        expect(result!.prependContext).toContain("No file deletions");
    });

    it("server down — returns undefined", async () => {
        mockFetchError();
        const { api, hooks } = createMockApi({});
        await plugin.register!(api);
        const handler = hooks.get("before_agent_start")!.handler;
        const result = await handler(
            { prompt: "hello" },
            { agentId: "a1" },
        );
        expect(result).toBeUndefined();
    });
});
