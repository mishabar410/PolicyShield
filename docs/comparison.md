# PolicyShield vs Alternatives

How does PolicyShield compare to other AI safety and guardrails tools?

## Comparison Matrix

| Feature | PolicyShield | Guardrails AI | NeMo Guardrails | LlamaGuard |
|---------|:---:|:---:|:---:|:---:|
| **Focus** | Tool-call firewall | I/O validation | Conversation rails | Content safety |
| **What it guards** | Tool arguments & execution | LLM input/output text | Conversation flow | Prompts & responses |
| **Enforcement point** | Between LLM decision and tool execution | Before/after LLM call | Inside conversation pipeline | At inference time |
| **Rules format** | YAML (declarative) | Python (validators) | Colang (DSL) | Model-based (fine-tuned LLM) |
| **Latency overhead** | <5ms p99 | 10-100ms+ | 50-500ms+ (LLM call) | 100-1000ms+ (inference) |
| **PII detection** | ✅ Regex + custom patterns | ✅ Validators | ❌ Not built-in | ❌ Not built-in |
| **PII redaction** | ✅ In tool arguments | ✅ In text | ❌ | ❌ |
| **Tool call blocking** | ✅ Core feature | ❌ Not applicable | ⚠️ Via canonical forms | ❌ |
| **Human approval** | ✅ APPROVE verdict (Telegram, REST) | ❌ | ❌ | ❌ |
| **Rate limiting** | ✅ Per-tool, per-session | ❌ | ❌ | ❌ |
| **Audit trail** | ✅ JSONL + OTEL + Prometheus | ❌ | ⚠️ Basic logging | ❌ |
| **Hot reload** | ✅ File watcher | ❌ Requires restart | ❌ Requires restart | ❌ N/A |
| **Framework-agnostic** | ✅ Any framework via HTTP | ⚠️ Python only | ⚠️ Python only | ⚠️ Requires model serving |
| **OpenClaw integration** | ✅ Native plugin | ❌ | ❌ | ❌ |
| **Requires GPU** | ❌ Pure CPU | ❌ | ⚠️ For LLM-based rails | ✅ |

## When to Use PolicyShield

✅ **Use PolicyShield when:**

- Your AI agent calls tools with side effects (shell, file I/O, network, messaging)
- You need to enforce policies on **what the agent does**, not just what it says
- You want declarative YAML rules, not Python code for security policy
- You need human-in-the-loop approval for sensitive operations
- You need <5ms latency (no LLM in the policy loop)
- You use OpenClaw and want a native plugin

❌ **Use something else when:**

- You need to guard LLM **text output** quality (→ Guardrails AI)
- You need conversation flow control (→ NeMo Guardrails)
- You need content safety classification (→ LlamaGuard, OpenAI Moderation)
- You need prompt injection detection at the LLM input level (→ Rebuff, Prompt Guard)

## Complementary Tools

PolicyShield works **alongside** other safety tools, not instead of them:

```
User prompt → [Prompt Guard] → LLM → [NeMo Rails] → tool_call decision
                                                          │
                                                    [PolicyShield] ← enforcement layer
                                                          │
                                                     tool execution
                                                          │
                                                    [Guardrails AI] ← output validation
                                                          │
                                                     response to user
```

Each tool covers a different layer. PolicyShield covers the gap between "the LLM decided to call a tool" and "the tool actually executes."
