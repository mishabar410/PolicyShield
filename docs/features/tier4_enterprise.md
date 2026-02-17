# 🔵 Tier 4 — Enterprise/Scale (после product-market fit)

| Фича | Описание |
|------|----------|
| Conditional Rules (time/role) | `time_of_day: "09:00-18:00"`, `user_role: admin` |
| RBAC | Per-role policy sets |
| Agent Identity & Attribution | Различение агентов в multi-agent: per-agent привилегии, identity propagation, аудит per-agent |
| Multi-Agent Orchestration | Cross-agent policy, session isolation/sharing |
| Federated Policies | Центральный policy server с push-updates |
| Multi-Tenant | Per-org policy sets с наследованием |
| Rule Versioning & Rollback | Git-подобное `rules history`, `rules rollback v3` |
| HA / Stateless Mode | Redis-backed sessions + approvals для multi-instance |
| Signed Rule Bundles | Подписанные пакеты правил для air-gapped окружений |
| Offline / Airgapped Mode | Гарантия работы без сети: явная документация, отключение всех external calls |
| Config Encryption / Secrets Management | Интеграция с Vault / AWS Secrets Manager / SOPS для чувствительных данных в конфиге |
| API Versioning & Deprecation | Формальная политика v1 → v2 миграции |
| Config Schema Migration | Auto-migrate старого формата конфига при обновлении |
| Chaos Testing | Рандомный блок/задержка для стресс-тестов |
| Data Watermarking | Невидимые маркеры в данных для tracking утечек |
| Cost Attribution | Разбивка стоимости по агенту/сессии/пользователю |

---

## ❄️ Отложить

| Фича | Причина |
|------|---------|
| Rego/OPA bridge | Тяжёлая зависимость, путает пользователей |
| Multi-language SDKs (Go, Rust) | Преждевременно без product-market fit |
| Agent sandbox | Другой домен, другой проект |
| Rule marketplace | Нет сообщества |

---

## Интеграции к рассмотрению

| Фреймворк | Приоритет | Примечание |
|-----------|-----------|------------|
| **MCP (Model Context Protocol)** | 🔥🔥🔥 | Де-факто стандарт tool calling, proxy = охват всей экосистемы |
| OpenAI Agents SDK | 🔥🔥 | Новый SDK, заменяет Assistants API |
| Anthropic tool use | 🔥🔥 | Прямая интеграция |
| AutoGen | 🔥🔥 | Быстро растёт, multi-agent |
| Dify | 🔥🔥 | Огромная OSS база, workflow agents |
| n8n | 🔥 | AI agents в workflow automation |
| LlamaIndex Agents | 🔥 | Agents mode набирает обороты |
| Semantic Kernel | 🔥 | Microsoft ecosystem |
| Haystack | 🔥 | Pipeline-based agents от deepset |
