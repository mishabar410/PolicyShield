# 🛡️ PolicyShield — Project Vision

## One-liner

**Declarative, zero-code firewall that sits between any LLM/agent and the tools it calls.**

## Problem

LLM agents can call arbitrary tools — shell commands, APIs, file operations — with no built-in safety net.
Prompt injection, hallucinated actions, and accidental destructive commands are inevitable at scale.
Existing solutions require rewriting agent code or are tightly coupled to a single framework.

## Solution

PolicyShield is a **standalone policy engine** that:

1. **Intercepts** every tool call before execution
2. **Evaluates** it against declarative YAML rules
3. **Acts**: blocks, redacts PII, requires human approval, or allows
4. **Records** a full audit trail for compliance

No agent code changes required. Works with any Python agent framework.

## Core Principles

| Principle | What it means |
|-----------|--------------|
| **Declarative** | Security policies live in YAML, not in application code |
| **Zero-trust tools** | Every call is checked; nothing is implicitly allowed |
| **Framework-agnostic** | Standalone engine + adapters for OpenClaw, LangChain, CrewAI, and more |
| **Non-invasive** | Monkey-patch or wrap — never fork the agent framework |
| **Observable** | Every decision is traced, exported, and queryable |
| **Testable** | Policies have their own test suite (`policyshield test`) |

## Architecture

```
┌──────────────────────────────────────────────────┐
│  Agent Framework (OpenClaw / LangChain / custom)  │
└───────────────────────┬──────────────────────────┘
                        │ tool call
                        ▼
              ┌─────────────────────┐
              │   PolicyShield      │
              │                     │
              │  ┌───────────────┐  │
              │  │  Rule Matcher  │──── YAML rules
              │  ├───────────────┤  │
              │  │  PII Detector  │──── regex + custom patterns
              │  ├───────────────┤  │
              │  │  Rate Limiter  │──── per-tool / per-session
              │  ├───────────────┤  │
              │  │  Approval Flow │──── CLI / Telegram / Webhook
              │  ├───────────────┤  │
              │  │  Trace Logger  │──── JSONL + OTel
              │  └───────────────┘  │
              └─────────┬───────────┘
                        │ verdict
                        ▼
          ┌──────────────────────────────┐
          │ ALLOW → execute tool         │
          │ BLOCK → return error to LLM  │
          │ REDACT → mask PII, execute   │
          │ APPROVE → wait for human     │
          └──────────────────────────────┘
```

## Target Users

- **Solo developers** building AI agents who need safety guardrails
- **Teams** deploying agents in production who need audit trails and compliance
- **Enterprises** requiring human-in-the-loop approval for sensitive operations

## What PolicyShield is NOT

- Not a WAF or network firewall
- Not a prompt injection detector (it protects the *output* side — tool calls)
- Not a replacement for proper auth/authz on the tools themselves
- Not an LLM evaluation framework

## Status

PolicyShield is at **v1.0** (Stable). The core engine is production-ready with HTTP server, OpenClaw plugin, 700+ tests, and 85% coverage.

See [ROADMAP.md](ROADMAP.md) for future ideas.
