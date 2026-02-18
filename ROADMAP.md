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

### v0.7 — Audit Fixes & Plugin Compliance ✅
- Async engine in HTTP server (no event loop blocking)
- Server hot-reload with `/api/v1/reload` endpoint
- OpenClaw Plugin rewritten for real `api.on()` API
- APPROVE flow with human-in-the-loop polling
- Benchmark CI gate (p99 < 5ms sync, < 10ms async)
- Repo cleanup (docker paths, vendored docs)
- 290+ tests, 85% coverage

### v0.8 — Docs & npm Publish ✅
- `@policyshield/openclaw-plugin` published to npm
- OpenClaw integration docs fully rewritten
- Documentation consistency pass across README, plugin README, integration guide
- 715+ tests

### v0.9 — OpenClaw 10/10 ✅
- SDK type auto-sync script + CI (weekly cron)
- E2E integration tests with real OpenClaw (Docker Compose, 5 scenarios)
- E2E CI job on every PR
- Server Bearer token authentication (`POLICYSHIELD_API_TOKEN`)
- PII taint chain: block outgoing calls after PII leak in output
- `policyshield openclaw setup` — one-command integration
- Compatibility matrix and migration guide
- Quickstart: Option A (1 cmd), Option B (Docker), Option C (step-by-step)
- Explicit limitations documentation (output blocking, PII detection)
- 720+ tests

### v0.10 — Tier 1 Features ✅
- **Replay & Simulation**: `policyshield replay` re-runs JSONL traces against new rules
- **Chain Rules**: `when.chain` temporal conditions with `EventRingBuffer`
- **AI-Assisted Rule Writer**: `policyshield generate` from natural language (OpenAI/Anthropic)
- Tool classifier with 4 danger levels
- Rule template library (5 templates for few-shot prompting)
- Chain linting check (7 lint checks total)
- 816 tests

### v0.11 — Tier 0: "Install and Protected" ✅
- **Built-in Security Patterns**: 5 detectors (path traversal, shell injection, SQL injection, SSRF, URL schemes)
- **Kill Switch**: `policyshield kill` / `POST /admin/kill` — instant emergency stop
- **Secure Preset**: `--preset secure` with `default_verdict: BLOCK`, fail-closed, all 5 detectors
- **Doctor**: `policyshield doctor` — 10-check health scanner with A-F grading
- **OpenClaw Tool Fetcher**: HTTP client for `/api/tools` endpoint
- **Auto-Rule Generator**: `policyshield generate-rules --from-openclaw` — zero-config rules
- **Honeypot Tools**: decoy tool detection, always blocks (even in AUDIT mode)
- 974 tests

### v0.12 — Tier 2: Medium Impact ✅ (current)
- **Circuit breaker** for approval backends with fallback
- **Backend health checks** and `/readyz` runtime endpoint
- **Rule simulation**: `policyshield simulate` what-if analysis
- **Trace log rotation** with max-size, daily rotation, TTL retention
- **TLS support** for HTTPS server
- **API rate limiting** middleware for `/check` endpoints
- **Approval flow Prometheus metrics**
- **Shadow mode**: dual-path evaluation for safe rule rollouts
- **Output/response policy pipeline** for post-call scanning
- **Plugin system**: extensible detector API
- **Multi-file rule validation** with conflict detection
- **Dead rule detection** via trace cross-reference
- **Dynamic rules** from HTTP/HTTPS with periodic refresh
- **Rule composition**: `include:` / `extends:` support
- **Budget caps**: per-session and per-hour USD limits
- **Global & adaptive rate limiting** with burst detection
- **Compliance reports**: HTML reports for auditors
- **Incident timeline** for post-mortem analysis
- **Canary deployments**: hash-based session bucketing
- **Config migration**: `policyshield migrate` between versions
- 1192 tests

## Next

### v1.0 — Production Release (planned)
- Bounded session storage (LRU eviction, TTL)
- Mypy type checking in CI
- Coverage gate raised to 90%
- Production deployment guide

---

## Future Ideas

| Item | Description |
|------|-------------|
| **Conditional rules** | `when.context` conditions: time of day, user role, session state |
| **Policy-as-Code SDK** | Python API to define rules programmatically alongside YAML |
| **Rego/OPA bridge** | Optional: evaluate rules via Open Policy Agent |
| **Multi-tenant** | Per-user / per-org policy sets with inheritance |
| **RBAC** | Role-based tool access: `admin` can delete, `viewer` cannot |
| **Agent sandbox** | OS-level isolation for tool execution (containers, seccomp) |
| **Multi-language SDKs** | TypeScript, Go, Rust wrappers |
| **Rule marketplace** | Community-contributed policy packs |
| **Federated policies** | Central policy server for fleet of agents |

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Feature proposals should open a GitHub issue with the `enhancement` label. Large changes should include a brief design doc.
