# Changelog

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
