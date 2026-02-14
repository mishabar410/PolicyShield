// HTTP client — will be implemented in prompt 47
import type {
    PluginConfig,
    CheckRequest,
    CheckResponse,
    PostCheckRequest,
    PostCheckResponse,
    ConstraintsResponse,
} from "./types.js";

export class PolicyShieldClient {
    private readonly url: string;
    private readonly timeoutMs: number;

    constructor(config: PluginConfig = {}) {
        this.url = (config.url ?? "http://localhost:8100").replace(/\/$/, "");
        this.timeoutMs = config.timeout_ms ?? 5000;
    }

    async check(req: CheckRequest): Promise<CheckResponse> {
        return this.post<CheckResponse>("/api/v1/check", req);
    }

    async postCheck(req: PostCheckRequest): Promise<PostCheckResponse> {
        return this.post<PostCheckResponse>("/api/v1/post-check", req);
    }

    async constraints(): Promise<ConstraintsResponse> {
        return this.get<ConstraintsResponse>("/api/v1/constraints");
    }

    private async post<T>(path: string, body: unknown): Promise<T> {
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), this.timeoutMs);
        try {
            const res = await fetch(`${this.url}${path}`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(body),
                signal: controller.signal,
            });
            if (!res.ok) throw new Error(`HTTP ${res.status}: ${res.statusText}`);
            return (await res.json()) as T;
        } finally {
            clearTimeout(timer);
        }
    }

    private async get<T>(path: string): Promise<T> {
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), this.timeoutMs);
        try {
            const res = await fetch(`${this.url}${path}`, {
                method: "GET",
                signal: controller.signal,
            });
            if (!res.ok) throw new Error(`HTTP ${res.status}: ${res.statusText}`);
            return (await res.json()) as T;
        } finally {
            clearTimeout(timer);
        }
    }
}
