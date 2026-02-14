/**
 * Type stubs for the OpenClaw Plugin SDK.
 *
 * Manually synchronized with openclaw/src/plugins/types.ts
 * Source of truth: https://github.com/openclaw/openclaw → src/plugins/types.ts
 * Last sync: 2026-02-14 (verified via raw download — all hook types match exactly)
 *
 * Only types used by the PolicyShield plugin are included here.
 * To re-sync: compare this file with the real types.ts and update differences.
 */

// ---------------------------------------------------------------------------
// Logger
// ---------------------------------------------------------------------------
export type PluginLogger = {
    debug?: (message: string) => void;
    info: (message: string) => void;
    warn: (message: string) => void;
    error: (message: string) => void;
};

// ---------------------------------------------------------------------------
// Plugin Hook Types
// ---------------------------------------------------------------------------

export type PluginHookName =
    | "before_agent_start"
    | "agent_end"
    | "before_compaction"
    | "after_compaction"
    | "before_reset"
    | "message_received"
    | "message_sending"
    | "message_sent"
    | "before_tool_call"
    | "after_tool_call"
    | "tool_result_persist"
    | "session_start"
    | "session_end"
    | "gateway_start"
    | "gateway_stop";

// Agent context shared across agent hooks
export type PluginHookAgentContext = {
    agentId?: string;
    sessionKey?: string;
    sessionId?: string;
    workspaceDir?: string;
    messageProvider?: string;
};

// before_agent_start
export type PluginHookBeforeAgentStartEvent = {
    prompt: string;
    messages?: unknown[];
};

export type PluginHookBeforeAgentStartResult = {
    systemPrompt?: string;
    prependContext?: string;
};

// Tool context
export type PluginHookToolContext = {
    agentId?: string;
    sessionKey?: string;
    toolName: string;
};

// before_tool_call
export type PluginHookBeforeToolCallEvent = {
    toolName: string;
    params: Record<string, unknown>;
};

export type PluginHookBeforeToolCallResult = {
    params?: Record<string, unknown>;
    block?: boolean;
    blockReason?: string;
};

// after_tool_call
export type PluginHookAfterToolCallEvent = {
    toolName: string;
    params: Record<string, unknown>;
    result?: unknown;
    error?: string;
    durationMs?: number;
};

// Hook handler map (subset we use)
export type PluginHookHandlerMap = {
    before_agent_start: (
        event: PluginHookBeforeAgentStartEvent,
        ctx: PluginHookAgentContext,
    ) => Promise<PluginHookBeforeAgentStartResult | void> | PluginHookBeforeAgentStartResult | void;
    after_tool_call: (
        event: PluginHookAfterToolCallEvent,
        ctx: PluginHookToolContext,
    ) => Promise<void> | void;
    before_tool_call: (
        event: PluginHookBeforeToolCallEvent,
        ctx: PluginHookToolContext,
    ) => Promise<PluginHookBeforeToolCallResult | void> | PluginHookBeforeToolCallResult | void;
    // Stubs for other hooks — not used by this plugin
    [key: string]: ((...args: unknown[]) => unknown) | undefined;
};

// ---------------------------------------------------------------------------
// Plugin API
// ---------------------------------------------------------------------------
export type OpenClawPluginApi = {
    id: string;
    name: string;
    version?: string;
    description?: string;
    source: string;
    config: Record<string, unknown>;
    pluginConfig?: Record<string, unknown>;
    runtime: unknown;
    logger: PluginLogger;
    registerTool: (...args: unknown[]) => void;
    registerHook: (...args: unknown[]) => void;
    registerHttpHandler: (...args: unknown[]) => void;
    registerHttpRoute: (...args: unknown[]) => void;
    registerChannel: (...args: unknown[]) => void;
    registerGatewayMethod: (...args: unknown[]) => void;
    registerCli: (...args: unknown[]) => void;
    registerService: (...args: unknown[]) => void;
    registerProvider: (...args: unknown[]) => void;
    registerCommand: (...args: unknown[]) => void;
    resolvePath: (input: string) => string;
    on: <K extends PluginHookName>(
        hookName: K,
        handler: PluginHookHandlerMap[K],
        opts?: { priority?: number },
    ) => void;
};

// ---------------------------------------------------------------------------
// Plugin Definition
// ---------------------------------------------------------------------------
export type PluginKind = "memory";

export type PluginConfigUiHint = {
    label?: string;
    help?: string;
    advanced?: boolean;
    sensitive?: boolean;
    placeholder?: string;
};

export type PluginConfigValidation =
    | { ok: true; value?: unknown }
    | { ok: false; errors: string[] };

export type OpenClawPluginConfigSchema = {
    safeParse?: (value: unknown) => {
        success: boolean;
        data?: unknown;
        error?: {
            issues?: Array<{ path: Array<string | number>; message: string }>;
        };
    };
    parse?: (value: unknown) => unknown;
    validate?: (value: unknown) => PluginConfigValidation;
    uiHints?: Record<string, PluginConfigUiHint>;
    jsonSchema?: Record<string, unknown>;
};

export type OpenClawPluginDefinition = {
    id?: string;
    name?: string;
    description?: string;
    version?: string;
    kind?: PluginKind;
    configSchema?: OpenClawPluginConfigSchema;
    register?: (api: OpenClawPluginApi) => void | Promise<void>;
    activate?: (api: OpenClawPluginApi) => void | Promise<void>;
};
