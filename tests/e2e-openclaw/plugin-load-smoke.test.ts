/**
 * Tier 2: Plugin Load Smoke Test
 *
 * Verifies that our plugin can be discovered, loaded, and registered
 * using the same patterns as the OpenClaw plugin system — but from an
 * external test directory (simulating how a real OpenClaw instance
 * would load a third-party plugin).
 *
 * Runs entirely in-process — no Docker, no LLM, no network.
 * Complements the more detailed openclaw-compat.test.ts in plugins/openclaw/tests/.
 */

import { describe, it, expect, vi } from "vitest";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

// Import our plugin via relative path (simulating OpenClaw loading from extensions dir)
import pluginModule from "../../plugins/openclaw/src/index.js";

// ── OpenClaw Plugin Discovery Simulation ────────────────────────────────────

describe("Plugin Discovery (simulating OpenClaw discovery.ts)", () => {
    it("package.json declares openclaw.extensions field", () => {
        const pkgPath = resolve(__dirname, "../../plugins/openclaw/package.json");
        const pkg = JSON.parse(readFileSync(pkgPath, "utf-8"));

        // OpenClaw's discoverOpenClawPlugins looks for this field
        expect(pkg.openclaw).toBeDefined();
        expect(pkg.openclaw.extensions).toBeInstanceOf(Array);
        expect(pkg.openclaw.extensions.length).toBeGreaterThan(0);
        expect(pkg.openclaw.extensions[0]).toMatch(/index\.js$/);
    });

    it("package.json has required metadata", () => {
        const pkgPath = resolve(__dirname, "../../plugins/openclaw/package.json");
        const pkg = JSON.parse(readFileSync(pkgPath, "utf-8"));

        expect(pkg.name).toBe("@policyshield/openclaw-plugin");
        expect(pkg.type).toBe("module");
        expect(pkg.main).toBeDefined();
    });
});

// ── OpenClaw Module Resolution Simulation ───────────────────────────────────

describe("Module Resolution (simulating OpenClaw loader.ts)", () => {
    it("default export is an object (not a function)", () => {
        // OpenClaw's resolvePluginModuleExport checks: typeof resolved === "object"
        expect(pluginModule).toBeDefined();
        expect(typeof pluginModule).toBe("object");
        expect(pluginModule).not.toBeNull();
    });

    it("exports OpenClawPluginDefinition shape: id, name, version, register", () => {
        // These fields are used by OpenClaw's loader.ts
        expect(pluginModule).toHaveProperty("id");
        expect(pluginModule).toHaveProperty("name");
        expect(pluginModule).toHaveProperty("version");
        expect(pluginModule).toHaveProperty("register");

        expect(typeof pluginModule.id).toBe("string");
        expect(typeof pluginModule.name).toBe("string");
        expect(typeof pluginModule.version).toBe("string");
        expect(typeof pluginModule.register).toBe("function");
    });

    it("id is 'policyshield' (used as config key)", () => {
        expect(pluginModule.id).toBe("policyshield");
    });
});

// ── OpenClaw Plugin Registration Simulation ─────────────────────────────────

describe("Plugin Registration (simulating OpenClaw registry.ts createApi)", () => {
    it("register() completes without throwing", async () => {
        const hooks: Array<{ hookName: string; priority: number }> = [];
        const mockApi = {
            id: "policyshield",
            name: "PolicyShield",
            version: pluginModule.version,
            description: "test",
            source: "/test/policyshield",
            config: {},
            pluginConfig: {
                url: "http://127.0.0.1:1", // unreachable — that's fine for smoke test
                timeout_ms: 200,
            },
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
            on: (hookName: string, _handler: unknown, opts?: { priority?: number }) => {
                hooks.push({ hookName, priority: opts?.priority ?? 0 });
            },
        };

        // This should not throw even when server is unreachable
        await pluginModule.register(mockApi as any);

        // Wait for the non-blocking health check to settle
        await new Promise((r) => setTimeout(r, 300));

        // Validate hook registrations
        const hookNames = hooks.map((h) => h.hookName);
        expect(hookNames).toContain("before_tool_call");
        expect(hookNames).toContain("after_tool_call");
        expect(hookNames).toContain("before_agent_start");
        expect(hooks).toHaveLength(3);
    });

    it("before_tool_call hook has priority 100 (high)", () => {
        const hooks: Array<{ hookName: string; priority: number }> = [];
        const mockApi = {
            id: "policyshield",
            name: "PolicyShield",
            version: pluginModule.version,
            description: "test",
            source: "/test/policyshield",
            config: {},
            pluginConfig: { url: "http://127.0.0.1:1", timeout_ms: 200 },
            runtime: { version: "2026.2.14" },
            logger: { debug: vi.fn(), info: vi.fn(), warn: vi.fn(), error: vi.fn() },
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
            on: (hookName: string, _handler: unknown, opts?: { priority?: number }) => {
                hooks.push({ hookName, priority: opts?.priority ?? 0 });
            },
        };

        // fire-and-forget — we only care about hooks array, not async result
        pluginModule.register(mockApi as any);

        const btc = hooks.find((h) => h.hookName === "before_tool_call");
        expect(btc).toBeDefined();
        expect(btc!.priority).toBe(100);
    });
});
