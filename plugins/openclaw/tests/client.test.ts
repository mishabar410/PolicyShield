import { describe, it, expect, vi, afterEach } from "vitest";
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

    it("check: mode=disabled skips fetch", async () => {
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

    it("check: no client-side audit override — BLOCK from server stays BLOCK", async () => {
        mockFetch({ verdict: "BLOCK", message: "would block" });
        const client = new PolicyShieldClient({ mode: "enforce" });
        const res = await client.check({
            tool_name: "test",
            args: {},
            session_id: "s1",
        });
        expect(res.verdict).toBe("BLOCK");
        // Audit mode is now server-side only — client must not override verdicts
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

    it("postCheck: returns PII types", async () => {
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

    it("postCheck: logs warning on HTTP 500", async () => {
        mockFetch({}, 500);
        const mockLogger = { info: vi.fn(), warn: vi.fn(), error: vi.fn() };
        const client = new PolicyShieldClient({}, mockLogger);
        const res = await client.postCheck({
            tool_name: "test",
            args: {},
            result: "done",
            session_id: "s1",
        });
        expect(res).toBeUndefined();
        expect(mockLogger.warn).toHaveBeenCalledWith(
            expect.stringContaining("post-check HTTP 500"),
        );
    });

    it("postCheck: logs warning on connection error", async () => {
        mockFetchError();
        const mockLogger = { info: vi.fn(), warn: vi.fn(), error: vi.fn() };
        const client = new PolicyShieldClient({}, mockLogger);
        const res = await client.postCheck({
            tool_name: "exec",
            args: {},
            result: "done",
            session_id: "s1",
        });
        expect(res).toBeUndefined();
        expect(mockLogger.warn).toHaveBeenCalledWith(
            expect.stringContaining("post-check failed for exec"),
        );
    });

    it("getConstraints: returns summary", async () => {
        mockFetch({ summary: "Do not delete files" });
        const client = new PolicyShieldClient();
        const res = await client.getConstraints();
        expect(res).toBe("Do not delete files");
    });

    it("getConstraints: logs debug on error", async () => {
        mockFetchError();
        const mockLogger = { info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn() };
        const client = new PolicyShieldClient({}, mockLogger);
        const res = await client.getConstraints();
        expect(res).toBeUndefined();
        expect(mockLogger.debug).toHaveBeenCalledWith(
            expect.stringContaining("constraints fetch failed"),
        );
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

    it("checkApproval: approved", async () => {
        mockFetch({ approval_id: "apr-1", status: "approved", responder: "admin" });
        const client = new PolicyShieldClient();
        const res = await client.checkApproval("apr-1");
        expect(res.status).toBe("approved");
        expect(res.responder).toBe("admin");
    });

    it("checkApproval: pending", async () => {
        mockFetch({ approval_id: "apr-2", status: "pending" });
        const client = new PolicyShieldClient();
        const res = await client.checkApproval("apr-2");
        expect(res.status).toBe("pending");
    });

    it("checkApproval: server down falls back to pending", async () => {
        mockFetchError();
        const client = new PolicyShieldClient();
        const res = await client.checkApproval("apr-3");
        expect(res.status).toBe("pending");
        expect(res.approval_id).toBe("apr-3");
    });
});
