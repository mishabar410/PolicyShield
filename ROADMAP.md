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
- Nanobot `ShieldedToolRegistry`

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

### v0.4 — Nanobot Deep Integration ✅
- Session ID propagation from AgentLoop
- Post-call PII scan on tool results
- LLM context enrichment (constraints in system prompt)
- Definition filtering (blocked tools hidden from LLM)
- Subagent shield propagation
- `shield_agent_loop()` monkey-patch for vanilla nanobot
- `policyshield nanobot` CLI wrapper
- 471 tests, 92% coverage

---

## In Progress

### v0.5 — Developer Experience 🚧

**Goal:** Make PolicyShield trivial to adopt.

| Item | Description | Status |
|------|-------------|--------|
| PyPI publish | `pip install policyshield` from PyPI | 🔲 |
| Docs site | MkDocs / Docusaurus with search, guides, API reference | 🔲 |
| GitHub Actions | Pre-built CI action: `policyshield lint` + `policyshield test` in PR | 🔲 |
| `policyshield init` | Interactive scaffold: creates rules, config, test file, gitignore | 🔲 |
| VS Code extension | YAML syntax highlighting, autocomplete, inline linting for rules | 🔲 |
| Examples refresh | End-to-end demo: FastAPI + nanobot + dashboard | 🔲 |

---

## Planned

### v0.6 — Observability & Dashboard

| Item | Description |
|------|-------------|
| Web dashboard | Local web UI: live verdict stream, rule hit counts, PII heatmap |
| Grafana preset | Pre-built Grafana dashboard for OTel metrics |
| Alert rules | Configurable alerts on violation spikes or new PII types |
| Trace search | Full-text + structured search across JSONL traces |
| Cost tracking | Estimate token cost of blocked/replanned calls |

### v0.7 — Advanced Policies

| Item | Description |
|------|-------------|
| Conditional rules | `when.context` conditions: time of day, user role, session state |
| Chain rules | "If tool A was called, then tool B is blocked for N seconds" |
| Dynamic rules | Fetch rules from remote (HTTP/S3) with signature verification |
| Policy-as-Code SDK | Python API to define rules programmatically alongside YAML |
| Rego/OPA bridge | Optional: evaluate rules via Open Policy Agent |

### v0.8 — Enterprise

| Item | Description |
|------|-------------|
| Multi-tenant | Per-user / per-org policy sets with inheritance |
| RBAC | Role-based tool access: `admin` can delete, `viewer` cannot |
| SOC 2 audit log | Tamper-evident trace format with signature chains |
| SSO approval | Approve via Okta/Google Workspace identity |
| Compliance packs | Pre-built rule sets: GDPR, HIPAA, SOX, PCI-DSS |

### v1.0 — Stable Release

| Item | Description |
|------|-------------|
| Stable API | Freeze public API, semantic versioning guarantees |
| Backwards compat | Migration guide for breaking changes from 0.x |
| Upstream nanobot PR | Submit PolicyShield hooks to nanobot core |
| Performance benchmarks | < 1ms overhead per tool call (validated) |
| Security audit | Third-party review of PII detection and redaction |

---

## Future Ideas (Post v1.0)

- **Agent sandbox**: OS-level isolation for tool execution (containers, seccomp)
- **Multi-language SDKs**: TypeScript, Go, Rust wrappers
- **Rule marketplace**: Community-contributed policy packs
- **AI-assisted rule writing**: "Describe what you want to protect" → YAML rules
- **Federated policies**: Central policy server for fleet of agents
- **Replay & simulation**: Re-run historical traces against new rules

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Feature proposals should open a GitHub issue with the `enhancement` label. Large changes should include a brief design doc.
