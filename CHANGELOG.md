# Changelog

All notable changes to PolicyShield will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/).

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
