# 🛡️ PolicyShield v0.1 — Цепочка промптов

13 атомарных промптов. Каждый: описание → код → тесты → lint → коммит.

## Порядок выполнения

| # | Файл | Что создаётся | Зависит от |
|---|------|--------------|-----------|
| 01 | `01_project_setup.md` | pyproject.toml, структура, ruff | — |
| 02 | `02_core_models.md` | Enums, Rule, PII, Session, Trace models | 01 |
| 03 | `03_yaml_parser.md` | YAML loader, validator, exceptions | 02 |
| 04 | `04_pii_detector.md` | L0 PII regex (9 типов, Luhn) | 02 |
| 05 | `05_matcher_engine.md` | Rule matching (tool, args, session) | 02, 03 |
| 06 | `06_verdict_builder.md` | Counterexample generation | 02 |
| 07 | `07_session_manager.md` | Session TTL, taints, thread-safety | 02 |
| 08 | `08_trace_recorder.md` | JSONL writer, batching, privacy | 02 |
| 09 | `09_shield_engine.md` | Оркестратор всех компонентов | 04-08 |
| 10 | `10_nanobot_integration.md` | ShieldedToolRegistry, install_shield | 09 |
| 11 | `11_cli.md` | `policyshield validate/trace` | 03, 08 |
| 12 | `12_e2e_tests.md` | 10 интеграционных сценариев | 01-11 |
| 13 | `13_finalize.md` | Examples, docs, README, v0.1.0 tag | 01-12 |

## Правила

1. Выполняй строго по порядку
2. Переходи к следующему промпту **только** если все тесты текущего и предыдущих зелёные
3. Каждый промпт завершается git commit
4. Если что-то сломалось — чини в текущем промпте, не иди дальше
