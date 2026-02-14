/**
 * Type stubs for the OpenClaw Plugin SDK.
 *
 * Extracted from the real OpenClaw source (openclaw/src/plugins/types.ts)
 * to avoid a heavyweight workspace dependency. Only the types actually
 * used by the PolicyShield plugin are included here.
 *
 * Source of truth: https://github.com/nicepkg/openclaw → src/plugins/types.ts
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
export type OpenClawPluginDefinition = {
    id?: string;
    name?: string;
    description?: string;
    version?: string;
    register?: (api: OpenClawPluginApi) => void | Promise<void>;
    activate?: (api: OpenClawPluginApi) => void | Promise<void>;
};
