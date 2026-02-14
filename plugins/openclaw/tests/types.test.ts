import { describe, it, expect } from "vitest";
import type {
    OpenClawPluginDefinition,
} from "../src/openclaw-plugin-sdk.js";
import plugin from "../src/index.js";

describe("SDK type compatibility", () => {
    it("plugin satisfies OpenClawPluginDefinition", () => {
        // Compile-time check — if types don't match, tsc will fail
        const def: OpenClawPluginDefinition = plugin;
        expect(def.id).toBe("policyshield");
        expect(def.register).toBeTypeOf("function");
    });

    it("plugin has required fields", () => {
        expect(plugin.id).toBe("policyshield");
        expect(plugin.name).toBe("PolicyShield");
        expect(plugin.version).toBeDefined();
        expect(plugin.description).toBeDefined();
    });
});
