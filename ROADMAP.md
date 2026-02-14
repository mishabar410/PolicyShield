# 🗺️ PolicyShield Roadmap

## Completed

### v0.1 — Core Engine ✅
- YAML rule DSL (regex, glob, exact match)
- 4 verdicts: ALLOW, BLOCK, REDACT, APPROVE
- PII detector (EMAIL, PHONE, CREDIT_CARD, SSN, IBAN, IP, PASSPORT, DOB)
- ShieldEngine orchestrator
- Session manager with tool-call tracking
- Trace recorder (JSONL)
- CLI: `validate`, `trace show`, `trace violations`

### v0.2 — Production Hardening ✅
- Rule linter with 6 static checks (`policyshield lint`)
- Hot reload (file watcher auto-reloads rules on change)
- RU PII patterns: INN, SNILS, passport, phone (with checksums)
- Custom PII patterns from YAML
- Sliding-window rate limiter (per-tool, per-session)
- Human-in-the-loop approval with caching strategies
- Approval backends: InMemory, CLI, Telegram
- Trace stats aggregation
- LangChain `BaseTool` adapter

### v0.3 — Async & Ecosystem ✅
- `AsyncShieldEngine` with full async/await support
- CrewAI `BaseTool` adapter
- OpenTelemetry exporter (OTLP spans + metrics)
- Webhook approval backend with HMAC-SHA256
- YAML test framework (`policyshield test`)
- Policy diff tool (`policyshield diff`)
- Trace export: CSV and HTML reports
- Input sanitizer with prompt-injection protection
- Unified config file (`policyshield.yaml`) with JSON Schema

### v0.4 — Engine Refinements ✅
- Session ID propagation for per-session rate limiting
- Post-call PII scan on tool results
- LLM context enrichment (constraints in system prompt)
- Definition filtering (blocked tools hidden from LLM)

### v0.5 — Developer Experience ✅
- PyPI packaging: `pip install policyshield`
- MkDocs documentation site with Material theme
- GitHub Actions CI + Release workflow
- Reusable GitHub Action for linting rules in PRs
- `policyshield init` with presets (`minimal`, `security`, `compliance`)
- FastAPI example, Docker quickstart
- Contributing guide, Code of Conduct, PR/issue templates

### v0.6 — Observability & Dashboard ✅
- Trace search: full-text + structured search across JSONL traces
- Trace aggregation API: verdict breakdown, top tools, PII heatmap
- Cost estimator: token/dollar cost per tool call with multi-model pricing
- Alert engine: 5 condition types with Console, Webhook, Slack, Telegram backends
- Web dashboard: FastAPI REST API + WebSocket live verdict stream
- Dashboard frontend: dark-themed SPA
- Prometheus exporter + Grafana preset

### v1.0 — HTTP Server & OpenClaw ✅
- HTTP Server: `policyshield server` with FastAPI (check, post-check, health, constraints)
- OpenClaw Plugin: native TypeScript plugin with before/after hooks
- OpenClaw Preset: `policyshield init --preset openclaw` (11 rules)
- Zero-trust mode: `default_verdict: block`
- Engine hardening: fail_open/fail_closed, `get_policy_summary()` API
- Docker server: `Dockerfile.server` with health check
- Benchmarks: p99 < 10ms verified
- 700+ tests, 85% coverage

---

## Future Ideas

| Item | Description |
|------|-------------|
| **Conditional rules** | `when.context` conditions: time of day, user role, session state |
| **Chain rules** | "If tool A was called, then tool B is blocked for N seconds" |
| **Dynamic rules** | Fetch rules from remote (HTTP/S3) with signature verification |
| **Policy-as-Code SDK** | Python API to define rules programmatically alongside YAML |
| **Rego/OPA bridge** | Optional: evaluate rules via Open Policy Agent |
| **Multi-tenant** | Per-user / per-org policy sets with inheritance |
| **RBAC** | Role-based tool access: `admin` can delete, `viewer` cannot |
| **Compliance packs** | Pre-built rule sets: GDPR, HIPAA, SOX, PCI-DSS |
| **Agent sandbox** | OS-level isolation for tool execution (containers, seccomp) |
| **Multi-language SDKs** | TypeScript, Go, Rust wrappers |
| **Rule marketplace** | Community-contributed policy packs |
| **AI-assisted rule writing** | "Describe what you want to protect" → YAML rules |
| **Federated policies** | Central policy server for fleet of agents |
| **Replay & simulation** | Re-run historical traces against new rules |

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Feature proposals should open a GitHub issue with the `enhancement` label. Large changes should include a brief design doc.
