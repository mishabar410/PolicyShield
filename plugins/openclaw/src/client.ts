import type { PluginLogger } from "./openclaw-plugin-sdk.js";
import type {
    PluginConfig,
    CheckRequest,
    CheckResponse,
    PostCheckRequest,
    PostCheckResponse,
    ConstraintsResponse,
    ApprovalStatusResponse,
} from "./types.js";

export class PolicyShieldClient {
    private readonly url: string;
    private readonly timeout: number;
    private readonly mode: string;
    private readonly failOpen: boolean;
    private readonly logger?: PluginLogger;

    constructor(config: PluginConfig = {}, logger?: PluginLogger) {
        this.url = (config.url ?? "http://localhost:8100").replace(/\/$/, "");
        this.timeout = config.timeout_ms ?? 5000;
        this.mode = config.mode ?? "enforce";
        this.failOpen = config.fail_open ?? true;
        this.logger = logger;
    }

    async check(req: CheckRequest): Promise<CheckResponse> {
        if (this.mode === "disabled") {
            return { verdict: "ALLOW", message: "" };
        }
        try {
            const res = await fetch(`${this.url}/api/v1/check`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(req),
                signal: AbortSignal.timeout(this.timeout),
            });
            if (!res.ok) {
                throw new Error(`HTTP ${res.status}: ${res.statusText}`);
            }
            const verdict = (await res.json()) as CheckResponse;
            if (this.mode === "audit") {
                this.logger?.info(
                    `[policyshield:audit] ${req.tool_name}: ${verdict.verdict} — ${verdict.message}`,
                );
                return { verdict: "ALLOW", message: "" };
            }
            return verdict;
        } catch (err) {
            if (this.failOpen) {
                this.logger?.warn(
                    `[policyshield] server unreachable, fail-open: ${String(err)}`,
                );
                return { verdict: "ALLOW", message: "" };
            }
            return {
                verdict: "BLOCK",
                message: "PolicyShield server unreachable (fail-closed)",
            };
        }
    }

    async postCheck(
        req: PostCheckRequest,
    ): Promise<PostCheckResponse | undefined> {
        try {
            const res = await fetch(`${this.url}/api/v1/post-check`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(req),
                signal: AbortSignal.timeout(this.timeout),
            });
            if (res.ok) {
                return (await res.json()) as PostCheckResponse;
            }
        } catch {
            /* fire and forget */
        }
        return undefined;
    }

    async getConstraints(): Promise<string | undefined> {
        try {
            const res = await fetch(`${this.url}/api/v1/constraints`, {
                signal: AbortSignal.timeout(2000),
            });
            if (res.ok) {
                const data = (await res.json()) as ConstraintsResponse;
                return data.summary;
            }
        } catch {
            /* optional */
        }
        return undefined;
    }

    async healthCheck(): Promise<boolean> {
        try {
            const res = await fetch(`${this.url}/api/v1/health`, {
                signal: AbortSignal.timeout(2000),
            });
            return res.ok;
        } catch {
            return false;
        }
    }

    async checkApproval(approvalId: string): Promise<ApprovalStatusResponse> {
        try {
            const res = await fetch(`${this.url}/api/v1/check-approval`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ approval_id: approvalId }),
                signal: AbortSignal.timeout(this.timeout),
            });
            if (res.ok) {
                return (await res.json()) as ApprovalStatusResponse;
            }
        } catch {
            /* polling failure — treat as pending */
        }
        return { approval_id: approvalId, status: "pending" };
    }
}
