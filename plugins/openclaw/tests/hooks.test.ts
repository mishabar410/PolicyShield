import { describe, it, expect, vi, afterEach } from "vitest";
import register from "../src/index.js";

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

const ctx = (toolName: string) => ({
    toolName,
    agentId: "agent-1",
    sessionKey: "sess-1",
});

describe("Plugin Hooks", () => {
    afterEach(() => {
        vi.restoreAllMocks();
    });

    it("register returns hooks array", () => {
        mockFetch({}, 200); // for health check
        const plugin = register({ config: { mode: "disabled" } });
        expect(plugin.hooks).toHaveLength(3);
        const names = plugin.hooks.map((h) => h.hookName);
        expect(names).toContain("before_tool_call");
        expect(names).toContain("after_tool_call");
        expect(names).toContain("before_agent_start");
    });

    describe("before_tool_call", () => {
        it("BLOCK", async () => {
            mockFetch({ verdict: "BLOCK", message: "dangerous" });
            const plugin = register({ config: {} });
            const hook = plugin.hooks.find((h) => h.hookName === "before_tool_call")!;
            const result = await hook.handler(
                { toolName: "rm", params: {} } as any,
                ctx("rm") as any,
            );
            expect(result).toEqual({
                block: true,
                blockReason: expect.stringContaining("PolicyShield"),
            });
        });

        it("REDACT", async () => {
            mockFetch({
                verdict: "REDACT",
                message: "pii",
                modified_args: { x: "***" },
            });
            const plugin = register({ config: {} });
            const hook = plugin.hooks.find((h) => h.hookName === "before_tool_call")!;
            const result = await hook.handler(
                { toolName: "send", params: { x: "secret" } } as any,
                ctx("send") as any,
            );
            expect(result).toEqual({ params: { x: "***" } });
        });

        it("ALLOW", async () => {
            mockFetch({ verdict: "ALLOW", message: "" });
            const plugin = register({ config: {} });
            const hook = plugin.hooks.find((h) => h.hookName === "before_tool_call")!;
            const result = await hook.handler(
                { toolName: "echo", params: {} } as any,
                ctx("echo") as any,
            );
            expect(result).toBeUndefined();
        });

        it("APPROVE", async () => {
            mockFetch({ verdict: "APPROVE", message: "needs approval" });
            const plugin = register({ config: {} });
            const hook = plugin.hooks.find((h) => h.hookName === "before_tool_call")!;
            const result = await hook.handler(
                { toolName: "deploy", params: {} } as any,
                ctx("deploy") as any,
            );
            expect(result).toEqual({
                block: true,
                blockReason: expect.stringContaining("approval"),
            });
        });
    });

    describe("after_tool_call", () => {
        it("sends post-check", async () => {
            const spy = mockFetch({ pii_types: [] });
            const plugin = register({ config: { mode: "disabled" } });
            const hook = plugin.hooks.find((h) => h.hookName === "after_tool_call")!;
            await hook.handler(
                { toolName: "echo", params: { x: 1 }, result: "ok" } as any,
                ctx("echo") as any,
            );
            // Fetch was called for the health check at startup + postCheck call
            const calls = spy.mock.calls.filter((c) =>
                String(c[0]).includes("/post-check"),
            );
            expect(calls.length).toBe(1);
        });

        it("handles non-string result", async () => {
            const spy = mockFetch({ pii_types: [] });
            const plugin = register({ config: { mode: "disabled" } });
            const hook = plugin.hooks.find((h) => h.hookName === "after_tool_call")!;
            await hook.handler(
                {
                    toolName: "query",
                    params: {},
                    result: { rows: [1, 2, 3] },
                } as any,
                ctx("query") as any,
            );
            const calls = spy.mock.calls.filter((c) =>
                String(c[0]).includes("/post-check"),
            );
            expect(calls.length).toBe(1);
            const body = JSON.parse(calls[0][1]!.body as string);
            expect(body.result).toContain("rows");
        });
    });

    describe("before_agent_start", () => {
        it("injects constraints", async () => {
            mockFetch({ summary: "No file deletions allowed" });
            const plugin = register({ config: { mode: "disabled" } });
            const hook = plugin.hooks.find(
                (h) => h.hookName === "before_agent_start",
            )!;
            const result = await hook.handler({} as any, {} as any);
            expect(result).toBeDefined();
            expect(result!.prependContext).toContain("PolicyShield");
            expect(result!.prependContext).toContain("No file deletions");
        });

        it("server down — returns undefined", async () => {
            mockFetchError();
            const plugin = register({ config: {} });
            const hook = plugin.hooks.find(
                (h) => h.hookName === "before_agent_start",
            )!;
            const result = await hook.handler({} as any, {} as any);
            expect(result).toBeUndefined();
        });
    });
});
