export type PluginConfig = {
    url?: string;
    /** "enforce" (default) or "disabled". Audit mode is configured on the server. */
    mode?: "enforce" | "disabled";
    fail_open?: boolean;
    timeout_ms?: number;
    /** Max time to wait for human approval (ms). Default: 60000 */
    approve_timeout_ms?: number;
    /** Polling interval for approval status (ms). Default: 2000 */
    approve_poll_interval_ms?: number;
    /** Max bytes of tool result to send for post-check PII scan. Default: 10000 */
    max_result_bytes?: number;
};

export type CheckRequest = {
    tool_name: string;
    args: Record<string, unknown>;
    session_id: string;
    sender?: string;
};

export type CheckResponse = {
    verdict: "ALLOW" | "BLOCK" | "REDACT" | "APPROVE";
    message: string;
    rule_id?: string;
    modified_args?: Record<string, unknown>;
    pii_types?: string[];
    approval_id?: string;
};

export type PostCheckRequest = {
    tool_name: string;
    args: Record<string, unknown>;
    result: string;
    session_id: string;
};

export type PostCheckResponse = {
    pii_types: string[];
    redacted_output?: string;
};

export type ConstraintsResponse = {
    summary: string;
};

export type ApprovalStatusResponse = {
    approval_id: string;
    status: "pending" | "approved" | "denied";
    responder?: string;
};
