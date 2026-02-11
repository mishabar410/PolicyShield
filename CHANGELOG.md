# Changelog

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
- Nanobot integration: `ShieldedToolRegistry` extends nanobot's `ToolRegistry` with async support
- `install_shield()` helper to wrap existing nanobot registries
- `AgentLoop.shield_config` parameter for optional PolicyShield enablement
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
- Nanobot integration
- 10 E2E test scenarios
