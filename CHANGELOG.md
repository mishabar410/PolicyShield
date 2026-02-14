# Changelog

## [1.0.0] - 2025-02-14

### Added
- **HTTP Server**: `policyshield server` — FastAPI HTTP API for framework-agnostic integration
  - POST `/api/v1/check` — pre-call policy check (ALLOW/BLOCK/REDACT/APPROVE)
  - POST `/api/v1/post-check` — post-call output PII scanning
  - GET `/api/v1/health` — health check with rules count and mode
  - GET `/api/v1/constraints` — human-readable policy summary for LLM context
- **OpenClaw Plugin**: `openclaw-plugin-policyshield` npm package
  - `before_tool_call` hook: block/redact/approve enforcement
  - `after_tool_call` hook: output PII audit trail
  - `before_agent_start` hook: policy constraint injection into system prompt
  - Configurable via `openclaw.yaml`: url, mode, fail_open, timeout_ms
  - Graceful degradation when server is unreachable
- **OpenClaw Preset**: `policyshield init --preset openclaw` — 11 ready-to-use rules
- **Zero-Trust Mode**: `default_verdict: block` in YAML rules
- **PostCheckResult**: Structured response with redacted output for post-call scanning
- **Engine Hardening**: fail_open/fail_closed error handling, `get_policy_summary()` API
- **Docker Server**: `Dockerfile.server` with health check for containerized deployment
- **Benchmarks**: p99 latency verification (< 10ms target)
- **E2E Tests**: 12 Python E2E tests + 4 TypeScript plugin E2E tests
- New optional dependency: `policyshield[server]` (FastAPI + uvicorn)
- 700+ tests, 85% coverage

### Changed
- Development Status classifier: Beta → Production/Stable

### Removed
- Nanobot integration (removed in v0.4, cleaned from all docs)

## [0.6.0] - 2025-02-13

### Added
- **Trace Search**: Full-text and structured search across JSONL traces (`policyshield trace search`)
- **Trace Aggregation API**: Verdict breakdown, top tools, PII heatmap, timeline analysis
- **Cost Estimator**: Token/dollar cost estimation per tool call with multi-model pricing (`policyshield trace cost`)
- **Alert Engine**: 5 condition types (block rate, block count, PII detected, tool blocked, error rate)
- **Alert Backends**: Console, Webhook, Slack, Telegram with severity filtering and cooldown
- **Web Dashboard**: FastAPI REST API + WebSocket live verdict stream (`policyshield trace dashboard`)
- **Dashboard Frontend**: Dark-themed SPA with verdict breakdown, block rate, tool stats, PII, cost view
- **Prometheus Exporter**: `/metrics` endpoint with per-tool and per-PII labels
- **Grafana Preset**: Pre-built dashboard JSON + datasource provisioning config
- New `policyshield trace stats` with directory-based aggregation
- New `policyshield trace cost` CLI command
- New `policyshield trace dashboard` CLI command
- Optional dependencies: `dashboard` (FastAPI + uvicorn), `prometheus` (prometheus-client)
- 100+ new tests (prompts 29–37), bringing total to 688+

## [0.5.0] - 2025-02-12

### Added
- **CLI `policyshield init`**: Scaffold new projects with presets (`minimal`, `security`, `compliance`), auto-generated test cases
- **PyPI packaging**: Updated metadata, Beta status, optional dependency groups (`langchain`, `crewai`, `otel`, `docs`, `dev`, `all`)
- **GitHub Actions CI**: Enhanced with format check, coverage XML artifact, build job with twine check
- **Release workflow**: Automated PyPI publishing on version tags
- **Reusable GitHub Action**: `.github/actions/lint-rules/` for validating and linting rules in CI
- **MkDocs documentation site**: Material theme, 14 pages covering getting started, guides, integrations, API reference
- **GitHub Pages deploy**: Automatic docs deployment workflow
- **FastAPI example**: Complete agent service with `/evaluate` and `/rules` endpoints
- **Docker quickstart**: Dockerfile and docker-compose.yml with validate/lint/test services
- **Contributing guide**: Updated with format checks, project structure, commit conventions
- **GitHub templates**: PR template, bug report and feature request issue templates
- **Code of Conduct**: Contributor Covenant v2.1
- 109 new tests (prompts 19–28), bringing total to 570

## [0.4.0] - 2025-02-12

### Added
- Session ID propagation from `AgentLoop` to `ShieldEngine` for per-session rate limiting
- Post-call PII scan: tool results are scanned and tainted PII types are recorded
- `get_definitions()` override: unconditionally blocked tools are hidden from LLM context
- Context enrichment: active policy constraints are injected into the LLM system prompt
- 26 new tests, bringing total to 461

## [0.3.1] - 2025-02-11

### Fixed
- Session increment no longer fires on BLOCK/APPROVE verdicts (both sync and async engines)
- `_parse_rule` now preserves `approval_strategy` field from YAML rules
- `AsyncShieldEngine.reload_rules` protected with `threading.Lock` to prevent race conditions
- ReDoS protection: regex patterns in rules capped at 500 characters
- `redact_dict` now recursively redacts PII in nested dicts and lists
- `TraceRecorder.record()` / `flush()` protected with `threading.Lock` for thread safety
- LangChain `_arun` uses `asyncio.to_thread` instead of blocking sync call
- IP address regex validates octet range (0–255), rejects `999.999.999.999`
- Passport regex narrowed from 6–9 to 7–9 digits to reduce false positives

### Added
- 23 audit regression tests (`test_audit_fixes.py`), bringing total to 437

## [0.3.0] - 2025-02-11

### Added
- AsyncShieldEngine with full async/await support
- CrewAI BaseTool adapter (CrewAIShieldTool, shield_all_crewai_tools)
- OpenTelemetry exporter (OTLP spans + metrics)
- Webhook approval backend with HMAC-SHA256 signing
- YAML-based rule testing framework (`policyshield test`)
- Policy diff tool (`policyshield diff`)
- Trace export: CSV and HTML report (`policyshield trace export`)
- Input sanitizer with prompt injection protection
- Unified config file (policyshield.yaml) with JSON Schema
- 14 new E2E test scenarios for v0.3 features

## [0.2.0] - 2025-02-11

### Added
- Rule linter with 6 static checks (`policyshield lint`)
- Hot reload of YAML rules (file watcher)
- RU PII patterns: INN, SNILS, passport, phone (with checksum validation)
- Custom PII patterns from YAML
- Sliding window rate limiter with YAML config
- Human-in-the-loop APPROVE verdict
- Approval backends: InMemory, CLI, Telegram
- Batch approve with caching strategies (once, per_session, per_rule, per_tool)
- Trace stats aggregation (`policyshield trace stats`)
- LangChain BaseTool adapter (`PolicyShieldTool`, `shield_all_tools`)
- 12 new E2E test scenarios for v0.2 features
- CHANGELOG

## [0.1.0] - 2025-02-11

### Added
- Core models (Verdict, RuleConfig, ShieldResult, etc.)
- YAML rule parser with includes and env vars
- PII detector (EMAIL, PHONE, CREDIT_CARD, SSN, IBAN, IP, PASSPORT, DOB)
- Rule matcher with regex, glob, and exact match
- ShieldEngine orchestrator
- Session manager with tool call tracking
- Trace recorder (JSONL)
- CLI: validate, trace show, trace violations
- 10 E2E test scenarios
