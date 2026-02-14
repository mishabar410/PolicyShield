/**
 * E2E: Plugin → PolicyShield Server
 *
 * Requires POLICYSHIELD_URL env var pointing to a running PolicyShield server.
 * Skip all tests if the env var is not set.
 */
import { PolicyShieldClient } from "../src/client.js";
import { describe, it, expect } from "vitest";

const url = process.env.POLICYSHIELD_URL;

const describeE2E = url ? describe : describe.skip;

describeE2E("E2E: Plugin → Server", () => {
    const client = new PolicyShieldClient({ url: url! });

    it("blocks destructive exec", async () => {
        const result = await client.check({
            tool_name: "exec",
            args: { command: "rm -rf /" },
            session_id: "ts-e2e",
        });
        expect(result.verdict).toBe("BLOCK");
    });

    it("allows safe exec", async () => {
        const result = await client.check({
            tool_name: "exec",
            args: { command: "echo hello" },
            session_id: "ts-e2e",
        });
        expect(result.verdict).toBe("ALLOW");
    });

    it("health check returns ok", async () => {
        const ok = await client.healthCheck();
        expect(ok).toBe(true);
    });

    it("constraints returns summary", async () => {
        const result = await client.getConstraints();
        expect(result).toBeDefined();
        expect(typeof result).toBe("string");
    });
});
