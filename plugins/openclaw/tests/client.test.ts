import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { PolicyShieldClient } from "../src/client.js";

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

describe("PolicyShieldClient", () => {
    afterEach(() => {
        vi.restoreAllMocks();
    });

    it("check: allow verdict", async () => {
        mockFetch({ verdict: "ALLOW", message: "ok" });
        const client = new PolicyShieldClient();
        const res = await client.check({
            tool_name: "test",
            args: {},
            session_id: "s1",
        });
        expect(res.verdict).toBe("ALLOW");
    });

    it("check: block verdict", async () => {
        mockFetch({ verdict: "BLOCK", message: "forbidden" });
        const client = new PolicyShieldClient();
        const res = await client.check({
            tool_name: "rm",
            args: {},
            session_id: "s1",
        });
        expect(res.verdict).toBe("BLOCK");
        expect(res.message).toBe("forbidden");
    });

    it("check: redact verdict", async () => {
        mockFetch({
            verdict: "REDACT",
            message: "pii found",
            modified_args: { text: "***" },
        });
        const client = new PolicyShieldClient();
        const res = await client.check({
            tool_name: "send",
            args: { text: "secret" },
            session_id: "s1",
        });
        expect(res.verdict).toBe("REDACT");
        expect(res.modified_args).toEqual({ text: "***" });
    });

    it("check: server down, fail_open=true", async () => {
        mockFetchError();
        const client = new PolicyShieldClient({ fail_open: true });
        const res = await client.check({
            tool_name: "test",
            args: {},
            session_id: "s1",
        });
        expect(res.verdict).toBe("ALLOW");
    });

    it("check: server down, fail_open=false", async () => {
        mockFetchError();
        const client = new PolicyShieldClient({ fail_open: false });
        const res = await client.check({
            tool_name: "test",
            args: {},
            session_id: "s1",
        });
        expect(res.verdict).toBe("BLOCK");
        expect(res.message).toContain("unreachable");
    });

    it("check: mode=disabled", async () => {
        const spy = vi.spyOn(globalThis, "fetch");
        const client = new PolicyShieldClient({ mode: "disabled" });
        const res = await client.check({
            tool_name: "test",
            args: {},
            session_id: "s1",
        });
        expect(res.verdict).toBe("ALLOW");
        expect(spy).not.toHaveBeenCalled();
    });

    it("check: mode=audit", async () => {
        mockFetch({ verdict: "BLOCK", message: "would block" });
        const client = new PolicyShieldClient({ mode: "audit" });
        const res = await client.check({
            tool_name: "test",
            args: {},
            session_id: "s1",
        });
        expect(res.verdict).toBe("ALLOW"); // audit does not enforce
        expect(globalThis.fetch).toHaveBeenCalledOnce();
    });

    it("check: timeout (fail_open)", async () => {
        vi.spyOn(globalThis, "fetch").mockRejectedValue(
            new DOMException("The operation was aborted", "AbortError"),
        );
        const client = new PolicyShieldClient({
            timeout_ms: 100,
            fail_open: true,
        });
        const res = await client.check({
            tool_name: "test",
            args: {},
            session_id: "s1",
        });
        expect(res.verdict).toBe("ALLOW");
    });

    it("postCheck: fire and forget", async () => {
        mockFetch({ pii_types: ["email"] });
        const client = new PolicyShieldClient();
        const res = await client.postCheck({
            tool_name: "test",
            args: {},
            result: "done",
            session_id: "s1",
        });
        expect(res).toBeDefined();
        expect(res!.pii_types).toContain("email");
    });

    it("postCheck: does not throw on 500", async () => {
        mockFetch({}, 500);
        const client = new PolicyShieldClient();
        const res = await client.postCheck({
            tool_name: "test",
            args: {},
            result: "done",
            session_id: "s1",
        });
        expect(res).toBeUndefined();
    });

    it("getConstraints: returns summary", async () => {
        mockFetch({ summary: "Do not delete files" });
        const client = new PolicyShieldClient();
        const res = await client.getConstraints();
        expect(res).toBe("Do not delete files");
    });

    it("getConstraints: server down", async () => {
        mockFetchError();
        const client = new PolicyShieldClient();
        const res = await client.getConstraints();
        expect(res).toBeUndefined();
    });

    it("healthCheck: ok", async () => {
        mockFetch({}, 200);
        const client = new PolicyShieldClient();
        const ok = await client.healthCheck();
        expect(ok).toBe(true);
    });

    it("healthCheck: down", async () => {
        mockFetchError();
        const client = new PolicyShieldClient();
        const ok = await client.healthCheck();
        expect(ok).toBe(false);
    });
});
