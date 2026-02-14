import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { PolicyShieldClient } from "../src/client.js";
import { createServer, type Server } from "node:http";

let server: Server;
let serverUrl: string;

beforeAll(async () => {
    server = createServer((req, res) => {
        let body = "";
        req.on("data", (chunk) => (body += chunk));
        req.on("end", () => {
            const url = req.url ?? "";

            if (url === "/api/v1/health") {
                res.writeHead(200, { "Content-Type": "application/json" });
                res.end(JSON.stringify({ status: "ok" }));
                return;
            }

            if (url === "/api/v1/check" && req.method === "POST") {
                const parsed = JSON.parse(body);
                if (
                    parsed.tool_name === "exec" &&
                    typeof parsed.args?.command === "string" &&
                    parsed.args.command.includes("rm -rf")
                ) {
                    res.writeHead(200, { "Content-Type": "application/json" });
                    res.end(
                        JSON.stringify({
                            verdict: "BLOCK",
                            message: "Destructive command blocked",
                        }),
                    );
                    return;
                }
                res.writeHead(200, { "Content-Type": "application/json" });
                res.end(JSON.stringify({ verdict: "ALLOW", message: "" }));
                return;
            }

            if (url === "/api/v1/post-check" && req.method === "POST") {
                res.writeHead(200, { "Content-Type": "application/json" });
                res.end(JSON.stringify({ pii_types: [] }));
                return;
            }

            if (url === "/api/v1/constraints") {
                res.writeHead(200, { "Content-Type": "application/json" });
                res.end(JSON.stringify({ summary: "- No destructive commands" }));
                return;
            }

            res.writeHead(404);
            res.end();
        });
    });

    await new Promise<void>((resolve) => {
        server.listen(0, () => {
            const addr = server.address();
            if (addr && typeof addr !== "string") {
                serverUrl = `http://localhost:${addr.port}`;
            }
            resolve();
        });
    });
});

afterAll(() => {
    server?.close();
});

describe("e2e: plugin ↔ mock PolicyShield server", () => {
    it("health check succeeds", async () => {
        const client = new PolicyShieldClient({ url: serverUrl });
        expect(await client.healthCheck()).toBe(true);
    });

    it("blocks destructive commands", async () => {
        const client = new PolicyShieldClient({ url: serverUrl });
        const result = await client.check({
            tool_name: "exec",
            args: { command: "rm -rf /" },
            session_id: "test",
        });
        expect(result.verdict).toBe("BLOCK");
        expect(result.message).toContain("Destructive");
    });

    it("allows safe commands", async () => {
        const client = new PolicyShieldClient({ url: serverUrl });
        const result = await client.check({
            tool_name: "exec",
            args: { command: "ls" },
            session_id: "test",
        });
        expect(result.verdict).toBe("ALLOW");
    });

    it("post-check returns PII types", async () => {
        const client = new PolicyShieldClient({ url: serverUrl });
        const result = await client.postCheck({
            tool_name: "exec",
            args: {},
            result: "safe output",
            session_id: "test",
        });
        expect(result).toBeDefined();
        expect(result?.pii_types).toEqual([]);
    });

    it("constraints returns summary", async () => {
        const client = new PolicyShieldClient({ url: serverUrl });
        const result = await client.getConstraints();
        expect(result).toBe("- No destructive commands");
    });

    it("unreachable server with fail_open=true returns ALLOW", async () => {
        const client = new PolicyShieldClient({
            url: "http://localhost:1",
            fail_open: true,
            timeout_ms: 500,
        });
        const result = await client.check({
            tool_name: "test",
            args: {},
            session_id: "test",
        });
        expect(result.verdict).toBe("ALLOW");
    });
});
