# Changelog

All notable changes to PolicyShield will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/).

## [0.14.0] - 2026-03-01

### Added — Tier 3A: v1.0 Essential Features (601–605)

- **Conditional Rules (601)**: `ContextEvaluator` for time-of-day, day-of-week, and arbitrary context conditions in rule matching
- **Bounded Session Storage (602)**: `SessionBackend` interface with `InMemorySessionBackend` (LRU + TTL eviction) and `RedisSessionBackend` stub
- **LLM Guard (603)**: async threat detection middleware with response caching and configurable fail-open/fail-closed behavior
- **NL Policy Compiler (604)**: LLM-powered natural language → YAML rule compiler with validation loop and `policyshield compile` CLI command
- **Deployment Guide (605)**: production `Dockerfile`, `docker-compose.yml`, Kubernetes manifests, and comprehensive deployment docs

### Fixed

- **80+ bug fixes** across engine, PII, session, trace, server, parser, async engine, decorators, and security modules (v17–v18 audits)
- **CI**: lint errors, SDK sync, ruff formatting across 9 files
- **Test coverage**: improved to 85% threshold with additional tests for async client, bugfix coverage, and Phase 10 features

### Changed

- **Release workflow**: added `skip-existing: true` to PyPI publish step to prevent duplicate upload failures on re-runs
- **npm plugin**: version synced to 0.14.0

## [0.13.0] - 2026-02-25

### Added — Tier 2: SDK, DX & Integrations (16 features)

**SDK & Integrations (501–504)**
- **Python SDK**: `PolicyShieldClient` + `AsyncPolicyShieldClient` with typed `CheckResult`, context manager support, and methods for check, post_check, health, kill, resume, reload
- **TypeScript SDK**: added `kill()`, `resume()`, `reload()`, `waitForApproval()` to `PolicyShieldClient` in `@policyshield/openclaw-plugin` — full parity with Python SDK
- **`@shield()` decorator**: sync and async function wrapping with policy enforcement. Configurable `on_block` behavior (`raise` / `return_none`). Backward-compatible `guard()` alias
- **MCP Proxy**: transparent MCP tool call proxy through PolicyShield (`policyshield/mcp_proxy.py`)

**CLI & DX (511–514)**
- **Quickstart wizard**: `policyshield quickstart` — interactive setup with framework selection, tool auto-discovery, and preset application
- **Dry-run CLI**: `policyshield check --tool <name> --rules <path>` — one-shot check without server (exit 0=ALLOW, 2=BLOCK)
- **Role presets**: `coding-agent`, `data-analyst`, `customer-support` — ready-made rule sets for common agent roles
- **Test coverage**: CI gate at 85% with coverage XML report

**Reliability (521–524)**
- **Idempotency**: `X-Idempotency-Key` header support (already existed, verified)
- **Retry/backoff**: generic `retry_with_backoff()` async utility with exponential backoff
- **K8s probes**: `/api/v1/livez` and `/api/v1/readyz` aliases for K8s probe consistency
- **Deep health**: `/healthz` and `/readyz` endpoints (already existed, verified)

**Operations & Observability (531–534)**
- **Full ENV config**: 31 `POLICYSHIELD_*` env vars — mode, rules_path, fail_open, trace_dir, trace_privacy, approval_timeout, telegram, slack, and more
- **OpenAPI expansion**: API tags (check, admin, observability) and description added to FastAPI app
- **Slack approval backend**: `SlackApprovalBackend` with Incoming Webhook notifications, delegates storage to `InMemoryBackend`
- **Integration examples**: standalone_check.py, fastapi_middleware.py, docker_compose/

### Fixed
- **mypy**: `dict[str, Any]` annotation in `_cmd_check` (was inferring incorrect type)
- **SDK client**: `/api/v1/kill-switch` → `/api/v1/kill` (matched server endpoint)
- **ruff format**: fixed formatting in `cli/main.py` and `test_tier2.py`
- **Coverage**: 83.65% → 85.26% with 16 additional tests for Slack, MCP proxy, quickstart, SDK, ENV config

## [0.12.0] - 2026-02-19

### Added — Tier 1.5 Features (20 modules)

**Resilience & Approval (401–407)**
- **Circuit breaker** for approval backends (Telegram/Webhook) with configurable failure threshold and fallback
- **Backend health checks** and `/readyz` runtime endpoint
- **Rule simulation** CLI: `policyshield simulate --rule rule.yaml --tool exec --args '{}'`
- **Trace log rotation** with max-size, daily rotation, and TTL retention
- **TLS support** via `--tls-cert`/`--tls-key` for HTTPS server
- **API rate limiting** middleware for `/check` and `/post-check` endpoints (configurable via env vars)
- **Approval flow Prometheus metrics** (pending count, response time, timeout rate)

**Rules Engine (408–414)**
- **Shadow mode**: dual-path rule evaluation (log only, no blocking) for safe rollouts
- **Output/response policy pipeline**: post-call response scanning with block patterns and size limits
- **Plugin system**: extensible detector API for custom security checks
- **Multi-file rule validation**: cross-file lint with conflict and shadow detection
- **Dead rule detection**: cross-reference rules with trace files to find unused rules
- **Dynamic rules**: fetch rules from HTTP/HTTPS with periodic refresh
- **Rule composition**: `include:` / `extends:` for rule inheritance and modularity

**Observability (415–418)**
- **Budget caps**: per-session and per-hour USD-based cost limits
- **Global & adaptive rate limiting**: cross-tool rate limiting with burst detection
- **Compliance reports**: `policyshield report` generates HTML reports for auditors
- **Incident timeline**: `policyshield incident <session_id>` for post-mortem analysis

**Operations (419–420)**
- **Canary deployments**: hash-based session bucketing, auto-promote after duration
- **Config migration**: `policyshield migrate` with sequential migration chain (0.11 → 0.12 → 1.0)

### Fixed
- **Benchmark CI**: `test_check_latency_p99` was failing with 429 due to API rate limiter; fixed by raising limit in benchmark fixture

## [0.11.1] - 2026-02-18

### Fixed
- **Rule parser**: support both `when/then` and legacy `tool/verdict` formats — previously `verdict:` at top level was silently ignored, defaulting to ALLOW
- **README**: endpoint paths corrected from `/admin/kill` → `/api/v1/kill`, added `/api/v1/reload` and `/api/v1/status`
- **Ruff**: formatting fix in `cli/main.py`

### Added
- **E2E test script** (`tests/e2e.sh`): 38 automated tests covering all Tier 0 features — verdicts, approval round-trip, honeypots, kill switch, sanitizer (5 detectors), post-check PII, and hot reload

## [0.11.0] - 2026-02-17

### Added
- **Built-in Security Patterns**: 5 detectors (path traversal, shell injection, SQL injection, SSRF, URL schemes) in sanitizer
- **Kill Switch**: engine-level emergency stop via `policyshield kill` CLI and `POST /admin/kill` REST endpoint
  - `ShieldEngine.kill(reason)` / `.resume()` methods with atomic `threading.Event`
  - Kill switch overrides AUDIT mode
- **Secure Preset**: `policyshield init --preset secure` with `default_verdict: BLOCK`, fail-closed, all 5 detectors
- **Doctor Command**: `policyshield doctor` — 10-check configuration health scanner with A-F security grading
  - JSON output mode (`--json`), configurable paths (`--config`, `--rules`)
- **OpenClaw Tool Fetcher**: `openclaw_client.py` HTTP client for `/api/tools` endpoint
- **Auto-Rule Generator**: `policyshield generate-rules` — pattern-based tool classification → YAML rules
  - `--from-openclaw` (fetch from running instance) or `--tools` (comma-separated names)
  - `--include-safe`, `--default-verdict`, `--force`, `-o` options
- **Honeypot Tools**: decoy tool detection — blocks always, even in AUDIT mode
  - `honeypots` field in `RuleSet` YAML config
  - Integrated into engine pipeline (after kill switch, before sanitizer)

### Changed
- `_apply_post_check`: honeypots and kill switch both bypass AUDIT mode override
- `RuleSet` model: added optional `honeypots: list[dict]` field

## [0.10.0] - 2026-02-16

### Added
- **Replay & Simulation**: `policyshield replay` CLI command to re-run recorded JSONL traces against new/modified rules
  - Trace loader (`policyshield.replay.loader`) for JSONL parsing
  - Replay engine (`policyshield.replay.engine`) with verdict comparison
  - CLI options: `--filter`, `--format`, `--changed-only`
- **Chain Rules**: temporal conditions (`when.chain`) for multi-step policy enforcement
  - `EventRingBuffer` for fixed-size tool event history
  - `ChainCondition` model with `tool`, `within_seconds`, `min_count`, `verdict` fields
  - Chain matcher integrated into `MatcherEngine`
  - Chain linting check added to `RuleLinter` (7 lint checks total)
  - Example file: `examples/chain_rules.yaml`
- **AI-Assisted Rule Writer**: generate YAML rules from natural language
  - Tool classifier (`policyshield.ai.templates`) with 4 danger levels and regex patterns
  - Rule template library with 5 templates for few-shot prompting
  - LLM rule generator (`policyshield.ai.generator`) with OpenAI/Anthropic support
  - YAML validation and retry logic
  - `policyshield generate` CLI command with `--template` (offline) and AI modes
  - `[ai]` optional dependency group in `pyproject.toml`

### Fixed
- `EventRingBuffer.find_recent()`: verdict filter used truthiness instead of `is not None`
- `ChainCondition`: silently accepted extra/typo'd keys; added `extra='forbid'`
- CLI `generate --template`: double indentation in generated YAML output

## [0.9.0] - 2026-02-15

### Added
- `policyshield openclaw setup/teardown/status` CLI commands
- Server Bearer token authentication via `POLICYSHIELD_API_TOKEN`
- PII taint chain: `taint_chain` config in rules YAML
- `/api/v1/clear-taint` endpoint
- `/api/v1/respond-approval` and `/api/v1/pending-approvals` endpoints for APPROVE flow
- Telegram approval backend via `POLICYSHIELD_TELEGRAM_TOKEN` / `POLICYSHIELD_TELEGRAM_CHAT_ID` env vars
- Non-blocking APPROVE verdict: `/check` returns `approval_id` immediately for async polling
- E2E test suite with real OpenClaw (Docker Compose)
- SDK type auto-sync script + CI job
- Compatibility matrix and migration guide
- `docker-compose.openclaw.yml` for one-file deployment

### Changed
- Plugin config: added `api_token` field
- OpenClaw preset rules: includes `taint_chain` (disabled by default)
- Quickstart: three options (one-command, Docker, step-by-step)

### Documentation
- Explicit limitations section (output blocking, PII detection)
- Migration guide: 0.7→0.8 and 0.8→0.9
- Version compatibility table

## [0.8.2] - 2026-02-15

### Fixed
- **SPEC.md**: deleted — code examples were outdated (old plugin pattern, wrong CLI commands, features marked TODO already implemented)
- **ROADMAP.md**: added v0.8 status, moved npm publish from v1.0 planned (already done), updated v1.0 goals

### Added
- **Troubleshooting**: added common issues table to main README (5 entries)

## [0.8.1] - 2026-02-14

### Fixed
- **APPROVE Polling**: replaced raw `while` loop with `AbortController`-based timeout for cleaner cancellation
- **Documentation Drift**: moved zero-trust mode and output scanning from roadmap to implemented in `PHILOSOPHY.md`
- **Version Sync**: unified Python (`0.7.0`) and npm plugin (`0.8.0`) versions to `0.8.1`

### Added
- **npm Publish**: `release.yml` now publishes `@policyshield/openclaw-plugin` to npm on tag push
- **Plugin CI Job**: `ci.yml` runs typecheck, build, and vitest for the OpenClaw plugin
- **Plugin README**: npm package page with quick start and configuration docs
- **OpenClaw Integration Guide**: comprehensive step-by-step guide with real CLI commands,
  troubleshooting, Docker deployment, and verified setup (OpenClaw 2026.2.13 tested)

### Changed
- **Benchmark Gate**: benchmark job now blocks the build pipeline (added to `needs`)

## [0.7.0] - 2026-02-14

### Fixed
- **Async Server Engine**: replaced sync `ShieldEngine` with `AsyncShieldEngine` in HTTP server
  to eliminate event loop blocking
- **OpenClaw Plugin API**: rewritten `index.ts` to use real `OpenClawPluginApi.on()` registration
  instead of non-existent `return { hooks }` pattern
- **APPROVE Flow**: implemented real human-in-the-loop polling instead of `block: true` stub
- **Version Consistency**: aligned all version references to 0.7.0

### Added
- **Server Hot Reload**: `/api/v1/reload` endpoint + file watcher lifespan
- **Approval Polling**: `/api/v1/check-approval` endpoint for approval status checks
- **Benchmark CI Gate**: p99 < 5ms (sync) / < 10ms (async) enforced in CI
- `CHANGELOG.md` (this file)

### Changed
- `docker-compose.yml`: unified volume mount paths to `./policies/`
- `PHILOSOPHY.md`: clarified performance targets (sync vs async)
- `ROADMAP.md`: updated to reflect actual v0.7 status

### Removed
- Legacy `.docx` file from repository root
- Dead `return { hooks }` plugin pattern

## [0.6.0] - 2026-02-12

### Added
- HTTP Server with FastAPI (`policyshield server`)
- OpenClaw Plugin scaffold (initial version)
- Server Docker configuration
- OpenClaw preset rules (`policyshield init --preset openclaw`)

## [0.5.0] - 2026-02-12

### Added
- Dashboard with WebSocket support
- Alert system
- Rule diff command
- CrewAI integration

## [0.4.0] - 2026-02-11

### Added
- Async engine (`AsyncShieldEngine`)
- OpenTelemetry integration
- Approval system with caching
- Input sanitizer

## [0.3.0] - 2026-02-11

### Added
- Session management
- Conditional rules (session state matching)
- Rate limiting
- Rule hot-reload (file watcher)

## [0.2.0] - 2026-02-11

### Added
- LangChain integration
- Trace recording with JSONL export
- Trace statistics and search
- Rule linting

## [0.1.0] - 2026-02-10

### Added
- Core engine: YAML rules, matcher, PII detection, verdict builder
- CLI: validate, lint, test, check
- Basic trace recording
