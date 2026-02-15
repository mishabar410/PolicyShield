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
    private readonly enabled: boolean;
    private readonly failOpen: boolean;
    private readonly apiToken?: string;
    private readonly logger?: PluginLogger;

    constructor(config: PluginConfig = {}, logger?: PluginLogger) {
        this.url = (config.url ?? "http://localhost:8100").replace(/\/$/, "");
        this.timeout = config.timeout_ms ?? 5000;
        this.enabled = (config.mode ?? "enforce") !== "disabled";
        this.failOpen = config.fail_open ?? true;
        this.apiToken = config.api_token;
        this.logger = logger;
    }

    private getHeaders(): Record<string, string> {
        const headers: Record<string, string> = {
            "Content-Type": "application/json",
        };
        if (this.apiToken) {
            headers["Authorization"] = `Bearer ${this.apiToken}`;
        }
        return headers;
    }

    async check(req: CheckRequest): Promise<CheckResponse> {
        if (!this.enabled) {
            return { verdict: "ALLOW", message: "" };
        }
        try {
            const res = await fetch(`${this.url}/api/v1/check`, {
                method: "POST",
                headers: this.getHeaders(),
                body: JSON.stringify(req),
                signal: AbortSignal.timeout(this.timeout),
            });
            if (!res.ok) {
                throw new Error(`HTTP ${res.status}: ${res.statusText}`);
            }
            // Audit mode is configured server-side, not in the client.
            return (await res.json()) as CheckResponse;
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
                headers: this.getHeaders(),
                body: JSON.stringify(req),
                signal: AbortSignal.timeout(this.timeout),
            });
            if (res.ok) {
                return (await res.json()) as PostCheckResponse;
            }
            this.logger?.warn(
                `[policyshield] post-check HTTP ${res.status} for ${req.tool_name}`,
            );
        } catch (err) {
            this.logger?.warn(
                `[policyshield] post-check failed for ${req.tool_name}: ${String(err)}`,
            );
        }
        return undefined;
    }

    async getConstraints(): Promise<string | undefined> {
        try {
            const res = await fetch(`${this.url}/api/v1/constraints`, {
                headers: this.getHeaders(),
                signal: AbortSignal.timeout(2000),
            });
            if (res.ok) {
                const data = (await res.json()) as ConstraintsResponse;
                return data.summary;
            }
        } catch (err) {
            this.logger?.debug?.(
                `[policyshield] constraints fetch failed: ${String(err)}`,
            );
        }
        return undefined;
    }

    async healthCheck(): Promise<boolean> {
        try {
            const res = await fetch(`${this.url}/api/v1/health`, {
                headers: this.getHeaders(),
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
                headers: this.getHeaders(),
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
