# Changelog

All notable changes to PolicyShield will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/).

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
