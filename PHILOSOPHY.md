# PolicyShield: Philosophy & Design Principles

> **PolicyShield is a runtime policy enforcement layer for AI agent tool calls.**
> It is a firewall, not an antivirus. It watches what the agent *does*, not what the agent *is*.

---

## The Problem

AI agents call tools. Tools have side effects. The agent decides which tool to call, with which arguments, based on an LLM's interpretation of natural language. This creates a category of risk that did not exist before:

1. **The LLM can hallucinate** — it may call `rm -rf /` because it "thought" that was the right cleanup step
2. **The LLM can be manipulated** — prompt injection in a document, email, or web page can coerce the agent into executing arbitrary tool calls
3. **The LLM has no concept of consequence** — it doesn't understand that `send_message(text="SSN: 123-45-6789")` leaks PII, or that `unlock_door()` has physical consequences
4. **Skills/tools are trusted code running in an untrusted context** — a perfectly benign skill can be weaponized through the agent's language interface

Traditional security models don't cover this:

| Traditional Layer | What It Catches | What It Misses |
|---|---|---|
| Code signing / VirusTotal | Malicious skill code | Benign skill called maliciously |
| Sandboxing | Unauthorized system access | Authorized tool calls with dangerous arguments |
| Permission prompts | First-time tool access | The 500th call to the same tool in a loop |
| System prompt instructions | Nothing (advisory only) | Everything (LLM can ignore them) |

**PolicyShield exists because there is no enforcement layer between the LLM's decision and the tool's execution.**

---

## What PolicyShield IS

### A runtime firewall for tool calls

PolicyShield intercepts every tool call *after* the LLM decides to make it but *before* the tool executes. It evaluates the call against declarative rules and returns a verdict:

```
LLM → "call exec(command='rm -rf /')" → PolicyShield → BLOCK → tool never runs
LLM → "call send_msg(text='email: john@corp.com')" → PolicyShield → REDACT → tool runs with masked PII
LLM → "call unlock_door()" → PolicyShield → APPROVE → waits for human confirmation
LLM → "call web_search(query='best restaurants')" → PolicyShield → ALLOW → tool runs normally
```

### A policy-as-code system

Rules are YAML, not code. Security policy is separated from application logic. A security team can write and audit rules without touching the agent's source code:

```yaml
rules:
  - name: block-destructive-shell
    tool: exec
    args_match:
      command: { regex: "rm\\s+-rf|sudo|mkfs|dd\\s+if=" }
    then: block
    message: "Destructive shell command blocked"
```

Rules are versionable, reviewable, diffable. They live in the repo alongside the code they protect.

### An observability layer

Every tool call produces a trace record: timestamp, tool name, arguments, verdict, matched rule, PII types detected, latency. This is not optional logging — it's a structured audit trail that answers:

- "What did the agent do in the last hour?"
- "Did any PII leave the system?"
- "Which rules fired most often?"
- "Are there tool calls that matched no rule at all?"

### A cross-cutting concern

PolicyShield is not tied to one tool. It applies the same policy engine across all tools uniformly. A rate limit applies to `web_search` the same way it applies to `exec`. A PII scan runs on `send_message` the same way it runs on `write_file`. This is fundamentally different from per-tool security logic scattered across individual tool implementations.

---

## What PolicyShield is NOT

### Not an antivirus

PolicyShield does not scan skill code for malware. It does not analyze binaries, check signatures, or detect trojans. That's what VirusTotal, code signing, and static analysis do. PolicyShield operates at a different layer — it doesn't care if the tool code is benign or malicious; it cares what arguments the LLM passes to it.

### Not a sandbox

PolicyShield does not restrict filesystem access, network connectivity, or process privileges. Sandboxing (containers, seccomp, AppArmor) controls *what a tool CAN do*. PolicyShield controls *what the agent ASKS a tool to do*. These are complementary:

```
Sandbox: "this process cannot write to /etc"
PolicyShield: "this agent cannot call write_file with path matching /etc/*"
```

Both are needed. Neither replaces the other.

### Not a prompt engineering solution

PolicyShield does not rely on system prompts to enforce rules. System prompts are advisory — the LLM can hallucinate past them, ignore them under pressure, or be overridden by prompt injection. PolicyShield operates at the execution layer, where compliance is binary: the tool either runs or it doesn't, regardless of what the LLM "believes" about the policy.

That said, PolicyShield *does* inject policy summaries into the system prompt. This is an optimization, not a security boundary — it helps the LLM avoid generating blocked calls in the first place, reducing latency and improving UX. The actual enforcement happens at the execution layer.

### Not a permission system

Traditional permission systems ask: "Does this user have access to this resource?" PolicyShield asks: "Should this tool call, with these specific arguments, in this session context, be allowed right now?" The difference:

- Permissions are static (user X can use tool Y)
- PolicyShield is contextual (user X can use tool Y, but not with argument Z, and not more than 10 times per minute, and not if the arguments contain PII)

### Not a replacement for code review

PolicyShield does not validate tool implementation correctness. A tool that has a SQL injection vulnerability will still have it with PolicyShield. PolicyShield ensures the *agent doesn't pass malicious input to the tool*, but the tool itself must still be properly written.

---

## Core Principles

### 1. Enforce at the execution layer, not the language layer

The only security boundary that matters is the one the LLM cannot bypass. System prompt instructions, few-shot examples, and "safety training" are all language-layer controls that can be circumvented through prompt injection, context window manipulation, or model-specific jailbreaks.

PolicyShield's enforcement is code, not text. When a rule says `then: block`, the tool function is never called. No amount of prompt engineering, clever phrasing, or injection payload can change this.

### 2. Declarative over imperative

Policy rules are data, not code. This has concrete consequences:

- **Auditability**: A YAML file can be read by a security auditor who doesn't know Python
- **Versioning**: Rules can be diff'd, reviewed in PRs, and rolled back
- **Composability**: Multiple rule files can be merged (environment-specific overrides, team-specific policies)
- **Hot-reloading**: Rules can be updated without restarting the agent

The alternative — writing `if tool_name == "exec" and "rm" in args["command"]: raise BlockedError()` scattered across tool implementations — is unmaintainable, unauditable, and guaranteed to have gaps.

### 3. Defense in depth, not silver bullet

PolicyShield is one layer. It is valuable precisely because it covers the gap that other layers don't:

```
Layer 0: Model alignment (the LLM tries to be helpful, not harmful)
Layer 1: System prompt (advisory constraints on behavior)
Layer 2: Skill/tool marketplace scanning (VirusTotal, code review)
Layer 3: → PolicyShield (runtime argument/behavior enforcement) ←
Layer 4: Sandbox (OS-level process isolation)
Layer 5: Network segmentation (firewall, egress filtering)
```

PolicyShield explicitly does not try to replace layers 0, 1, 2, 4, or 5. It fills the specific gap between "the LLM decided to make a tool call" and "the tool actually executes".

### 4. Fail-safe defaults

When PolicyShield cannot make a decision (rule parsing error, engine crash, timeout), the default behavior must be configurable:

- **`fail_open: true`** (default) — allow the call, log the failure. Suitable for development and audit mode.
- **`fail_open: false`** — block the call. Suitable for production with sensitive tools.

The mode is also explicit:
- **`ENFORCE`** — verdicts are applied (block/redact/approve)
- **`AUDIT`** — verdicts are logged but not applied (shadow mode for rule development)
- **`DISABLED`** — engine is off (passthrough)

### 5. Framework-agnostic core, framework-specific adapters

The PolicyShield engine is a pure function: `check(tool_name, args, session_id, sender) → ShieldResult`. It has no dependency on any agent framework.

Integration with specific frameworks (OpenClaw, LangChain, CrewAI) is done through thin adapters that:

1. Intercept tool calls in the framework's execution path
2. Call the engine
3. Apply the verdict (block, redact, approve, allow)
4. Return the result in the framework's expected format

This separation is critical: it means PolicyShield can be adopted incrementally, tested independently, and upgraded without affecting the agent framework.

### 6. Observable by default

Every tool call that passes through PolicyShield produces a structured trace record. There is no "quiet mode" where calls are silently allowed without logging. The audit trail is not a feature — it's an invariant.

This enables:

- **Compliance**: "We can prove that no PII left the system in Q3"
- **Debugging**: "The agent was blocked 47 times in this session — here's why"
- **Rule development**: "These 12 tool calls matched no rule — do we need new rules?"
- **Anomaly detection**: "This session made 300 `exec` calls in 2 minutes — is the agent in a loop?"

---

## Capabilities: What PolicyShield SHOULD Do

### Must Have (Core)

| Capability | Description | Status |
|---|---|---|
| **Rule matching** | Match tool calls against YAML rules by tool name, argument patterns (regex, contains, eq), session state, and sender identity | ✅ Implemented |
| **Verdict enforcement** | Four verdicts: ALLOW, BLOCK, REDACT, APPROVE | ✅ Implemented |
| **PII detection** | Detect common PII types (email, phone, credit card, SSN, passport, etc.) in tool arguments using regex patterns | ✅ Implemented (L0 regex) |
| **PII redaction** | Automatically mask PII in tool arguments before the tool executes | ✅ Implemented |
| **Rate limiting** | Per-tool, per-session sliding window rate limits | ✅ Implemented |
| **Session management** | Track call counts, tool usage, PII taints per session | ✅ Implemented |
| **Audit trail** | JSONL trace of every tool call with verdict, rule, timing, PII types | ✅ Implemented |
| **Human approval flow** | APPROVE verdict pauses execution until a human confirms (CLI, Telegram, Webhook) | ✅ Implemented |
| **Hot reload** | Rules can be updated without restarting the agent | ✅ Implemented |
| **System prompt enrichment** | Inject policy summaries into the LLM's context to reduce wasted blocked calls | ✅ Implemented |
| **Tool filtering** | Remove unconditionally blocked tools from LLM's view entirely | ✅ Implemented |

### Should Have (Roadmap)

| Capability | Description | Why |
|---|---|---|
| **Semantic PII detection (L1)** | NER-based PII detection using spaCy/transformers in addition to regex | Regex alone has too many false positives/negatives for production DLP |
| **Zero-trust mode** | Explicit allow-list mode where unmatcheded tool calls are blocked by default | Current default-allow behavior contradicts "zero-trust" claim |
| **Rule composition** | Include/extend rule files, environment-specific overrides (dev/staging/prod) | Large deployments need rule modularity |
| **Cross-session analytics** | Aggregate traces across sessions for organizational insights | Enterprise compliance needs |
| **Conditional chaining** | Rules that depend on the result of previous tool calls in the same session | "Block `send_email` if `read_file` was called on a sensitive path" |
| **Output scanning** | Full PII scan on tool return values (not just arguments) | Data can leak through tool outputs, not just inputs |
| **Cost tracking** | Track estimated API cost per tool call and enforce budgets | LLM tool calls cost money; rate limiting alone isn't enough |

### Could Have (Future)

| Capability | Description |
|---|---|
| **Anomaly detection** | ML-based detection of unusual tool call patterns |
| **Policy simulation** | "What would happen if I deployed these rules?" dry-run engine |
| **Multi-agent coordination** | Enforce policies across agent-to-agent tool calls |
| **Temporal rules** | "Block `deploy` outside business hours" |
| **Geo-aware rules** | Different policies based on user/data jurisdiction |

---

## Non-Goals: What PolicyShield Should NOT Do

PolicyShield's scope must be explicitly bounded. Feature creep into adjacent domains would dilute its value and create false confidence.

### 1. Static code analysis

PolicyShield does not analyze tool code, skill source files, or dependencies. That's the domain of SAST tools, VirusTotal, and code review processes. PolicyShield evaluates *calls*, not *implementations*.

**Why not?** Because a tool's code can be perfectly safe — the danger comes from *how the LLM calls it*. A `send_email(to, subject, body)` function is harmless code. An LLM calling it with `body="Here's the user's SSN: 123-45-6789"` is the problem PolicyShield solves.

### 2. Model alignment or safety training

PolicyShield does not modify the LLM's weights, training data, or RLHF objectives. It does not try to make the model "safer" — it assumes the model *will* make unsafe calls and provides a separate enforcement layer.

**Why not?** Because model alignment is a research problem that changes with every model version. PolicyShield provides invariant enforcement that works regardless of which model is used.

### 3. Network-level security

PolicyShield does not manage TLS certificates, firewall rules, egress filtering, or DNS policies. If a tool is allowed to make HTTP requests, PolicyShield does not inspect the network packets — it inspects the tool *arguments* (URL, headers, body) before the request is made.

**Why not?** Because network security is an infrastructure concern with mature tooling (iptables, Calico, Istio). PolicyShield operates at the application semantic layer, which is above the network layer.

### 4. Authentication or authorization

PolicyShield does not manage user accounts, API keys, OAuth tokens, or role-based access control. It can use the `sender` field to apply different rules to different users, but it does not verify identity.

**Why not?** Because identity management is a solved problem with established solutions (Auth0, Keycloak, IAM). PolicyShield consumes identity as an input to policy decisions, but does not manage it.

### 5. Tool implementation correctness

PolicyShield does not validate that a tool does what it claims. If a tool named `echo` actually deletes files, PolicyShield will apply the `echo` rules to it. Tool behavior verification is the responsibility of testing, code review, and sandboxing.

**Why not?** Because verifying arbitrary code behavior is undecidable in the general case (halting problem). PolicyShield focuses on what it can statically evaluate: the *interface* between the agent and the tool.

### 6. Comprehensive data loss prevention (DLP)

PolicyShield includes PII detection as a rule action, but it is **not** a full DLP solution. True DLP requires:

- Deep content inspection across all data channels (not just tool arguments)
- Integration with data classification systems
- Endpoint monitoring
- Encrypted traffic inspection

PolicyShield provides a pragmatic, targeted PII scan at the tool call boundary. For comprehensive DLP, use a dedicated DLP platform and treat PolicyShield as one signal input.

### 7. Replacing human judgment

The APPROVE verdict exists precisely because some decisions cannot be automated. PolicyShield should make it easy for humans to review critical actions, not try to automate the judgment itself.

---

## Design Constraints

### Performance budget

PolicyShield sits in the hot path of every tool call. Its overhead must be negligible compared to:
- LLM inference time (seconds)
- Tool execution time (milliseconds to seconds)

**Performance target:** < 5ms p99 per sync check, < 10ms p99 per async check
(async includes `asyncio.to_thread` overhead for CPU-bound regex matching).

### Memory footprint

Session state (call counts, PII taints) must be bounded. A session with 10,000 tool calls should not consume unbounded memory. Fixed-size sliding windows and periodic compaction are required.

### No external dependencies in the core

The core engine (`shield/`) must depend only on the Python standard library and Pydantic. No database, no network calls, no ML models in the critical path. Optional extensions (NER-based PII, OTel export, Telegram approval) may have additional dependencies, but the core must remain minimal and fast.

### Backward-compatible rule format

Rules written for version N must continue to work in version N+1. New features may add optional fields, but existing rules must never break. This is a strong API contract — security policy should never be invalidated by an upgrade.

---

## Integration Philosophy

### The adapter pattern

Every agent framework integration follows the same pattern:

```
┌────────────────────────────────────┐
│          Agent Framework           │
│  (OpenClaw, LangChain, CrewAI)     │
│                                    │
│   LLM → tool_call(name, args)      │
│              │                     │
│              ▼                     │
│   ┌──────────────────────┐         │
│   │   Framework Adapter  │         │
│   │   (thin wrapper)     │         │
│   └──────────┬───────────┘         │
│              │                     │
│              ▼                     │
│   ┌──────────────────────┐         │
│   │   PolicyShield Core  │         │
│   │   (pure function)    │         │
│   └──────────┬───────────┘         │
│              │                     │
│         verdict                    │
│              │                     │
│   ALLOW → execute tool             │
│   BLOCK → return error message     │
│   REDACT → modify args, execute    │
│   APPROVE → pause, wait for human  │
└────────────────────────────────────┘
```

### Integration requirements

An adapter for a new framework must:

1. **Intercept tool calls** before execution
2. **Extract** tool name, arguments, session ID, and sender
3. **Call** `engine.check(tool_name, args, session_id, sender)`
4. **Apply** the verdict (block, redact, approve, allow)
5. **Optionally** filter tool definitions shown to the LLM
6. **Optionally** enrich the system prompt with policy summaries

### What NOT to do in adapters

- **Don't duplicate engine logic** — the adapter should not implement its own rule matching
- **Don't modify the engine's behavior** — framework-specific quirks belong in the adapter, not in the core
- **Don't require framework changes** — adapters should work through monkey-patching, middleware, or wrapping, never by modifying the framework's source code
- **Don't break without the engine** — if PolicyShield is removed, the framework should work exactly as it did before

---

## Relationship to OpenClaw

OpenClaw has its own security mechanisms:

| OpenClaw Feature | What It Does | Gap PolicyShield Fills |
|---|---|---|
| `exec-approvals` system | Human approval for shell commands | Only covers `exec` tool, not other 60+ tools |
| `DANGEROUS_HOST_ENV_VARS` blocklist | Blocks dangerous env vars in exec | Static list, no argument-level inspection |
| `--dangerously-skip-permissions` | Skips all permission checks | No graduated policy (all-or-nothing) |
| VirusTotal / ClawHub scanning | Scans skill code for malware | Doesn't cover runtime tool call arguments |
| System prompt constraints | Tells LLM about restrictions | Advisory only, bypassable via prompt injection |
| Prompt injection: "Out of Scope" | Explicitly declared out of scope in SECURITY.md | PolicyShield provides enforcement-layer defense |

PolicyShield in OpenClaw would:

1. **Extend approval beyond exec** — apply APPROVE verdict to `send_message`, `discord_action`, `unlock_door`, `web_fetch`, etc.
2. **Scan tool arguments for PII** — before data reaches `send_message`, `web_search`, or any external API
3. **Rate-limit across all tools** — not just exec, and with per-session granularity
4. **Provide a unified audit trail** — one log for all tool calls, not just exec
5. **Enable declarative per-skill policies** — install a skill, drop a rule file, done
6. **Address prompt injection at the enforcement layer** — where it actually matters, since OpenClaw explicitly declares it out of scope at the security policy level

---

## Summary

PolicyShield is a **narrow, deep** tool. It does one thing — evaluate tool calls against rules — and does it at the one point in the stack where it matters most: between the LLM's decision and the tool's execution.

It does not try to replace sandboxes, antiviruses, permission systems, DLP platforms, or model alignment. It fills the specific gap that none of those tools cover: **runtime policy enforcement on AI agent tool calls**.

The measure of PolicyShield's success is not whether it can block every possible attack. It's whether:

1. Every tool call is evaluated against a policy
2. Every evaluation produces an audit record
3. Blocked calls never execute
4. PII is detected and masked before it leaves the system
5. Critical operations require human confirmation
6. All of the above happens in < 5ms, with YAML rules, without modifying the agent framework

Everything else is out of scope by design.
