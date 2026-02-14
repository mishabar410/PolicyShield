export type PluginConfig = {
    url?: string;
    mode?: "enforce" | "audit" | "disabled";
    fail_open?: boolean;
    timeout_ms?: number;
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
