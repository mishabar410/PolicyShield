# 🛡️ PolicyShield

**Декларативный firewall для tool calls AI-агентов.**

Пишешь правила в YAML → PolicyShield исполняет их на каждом tool call → получаешь аудитный лог.

```yaml
rules:
  - id: no-pii-external
    description: "Запрет отправки PII на внешние сервисы"
    when:
      tool: [web_fetch, web_search]
      args_match:
        any_field: { contains_pattern: "pii" }
    then: block
    message: "PII detected. Redact before sending externally."
```

---

## Зачем

AI-агенты взаимодействуют с миром через **tool calls**: shell-команды, файлы, HTTP, сообщения. Контроль над ними сегодня — либо промпты ("пожалуйста, не удаляй"), либо ad-hoc regex-проверки. Оба подхода ненадёжны, не покрывают все tools и не оставляют аудитного следа.

PolicyShield решает это:
- **Декларативные правила** (YAML) вместо хардкода
- **Runtime enforcement** на каждом tool call
- **Repair loop** — при блокировке агент получает объяснение и может исправиться
- **Audit trail** (JSONL) — доказательство compliance

## Чем отличается

| Решение | Уровень работы | Repair loop | Audit |
|---------|---------------|-------------|-------|
| Guardrails AI | LLM output | ✗ | ✗ |
| NeMo Guardrails | Conversational flow | ✗ | ✗ |
| LlamaGuard | Safety classifier | ✗ | ✗ |
| **PolicyShield** | **Tool calls** | **✓** | **✓** |

---

## Как работает

```
LLM хочет вызвать web_fetch(url="...?email=john@corp.com")
      │
      ▼
  PolicyShield pre-call check
      │
      ├── PII обнаружен (email) → правило no-pii-external → BLOCK
      │
      ▼
  Агенту возвращается counterexample:
  "🛡️ BLOCKED: PII detected. Redact email before external request."
      │
      ▼
  LLM перепланирует: web_fetch(url="...?email=[REDACTED]")
      │
      ▼
  PolicyShield: OK → ALLOW → tool выполняется
```

## Три столпа

### 1. Rules — YAML DSL

Человекочитаемые правила в знакомом формате (like GitHub Actions / K8s policies):

```yaml
shield: security-v1
version: 1

rules:
  - id: no-destructive-shell
    when:
      tool: exec
      args_match:
        command: { regex: "rm\\s+-rf|mkfs|dd\\s+if=" }
    then: block
    severity: critical

  - id: approve-curl
    when:
      tool: exec
      args_match:
        command: { regex: "curl|wget" }
    then: approve
    
  - id: rate-limit-web
    when:
      tool: [web_fetch, web_search]
      session:
        tool_count.web_fetch: { gt: 20 }
    then: block
```

### 2. Shield — Runtime enforcement

Middleware между LLM и tools. Вердикты:
- **ALLOW** — tool call проходит
- **BLOCK** — tool call блокируется, агент получает counterexample для исправления
- **APPROVE** — human-in-the-loop (через Telegram/Discord/CLI)
- **REDACT** — PII маскируется в аргументах или результатах

### 3. Trace — Audit log

Каждое решение в JSONL:

```jsonl
{"ts":"2026-02-11T00:30:15Z","tool":"web_fetch","verdict":"BLOCK","rule":"no-pii-external","pii":["email"],"session":"tg:123"}
{"ts":"2026-02-11T00:30:16Z","tool":"web_fetch","verdict":"ALLOW","session":"tg:123"}
```

CLI для просмотра:
```bash
policyshield trace show --session tg:123
policyshield trace violations --last 7d
```

---

## Интеграция с nanobot

PolicyShield работает с [nanobot](https://github.com/cjohndesign/nanobot) из коробки.

### Установка

```bash
pip install policyshield
```

### Настройка

Добавить секцию `shield` в `~/.nanobot/config.json`:

```json
{
  "shield": {
    "enabled": true,
    "mode": "enforce",
    "rules_path": "~/.nanobot/policies/"
  }
}
```

Создать правила в `~/.nanobot/policies/security.yaml` — и всё.

---

## Документация

| Документ | Описание |
|----------|----------|
| [CLAUDE.md](CLAUDE.md) | Видение проекта, позиционирование, стратегия |
| [TECHNICAL_SPEC.md](TECHNICAL_SPEC.md) | Техническая спецификация: YAML DSL, matcher, вердикты, PII, trace |
| [INTEGRATION_SPEC.md](INTEGRATION_SPEC.md) | Интеграция с nanobot: архитектура, ShieldedToolRegistry, approval flow |

## Roadmap

| Версия | Что включает |
|--------|-------------|
| **v0.1** | YAML DSL + BLOCK/ALLOW + L0 PII + Repair loop + JSONL trace |
| **v0.2** | APPROVE (human-in-the-loop) + REDACT + Batch approve |
| **v0.3** | Trace CLI + Rule linter + Rate limiting |
| **v0.4** | LangChain / CrewAI адаптеры |
| **v1.0** | Stable API + PyPI publish |

---

## Лицензия

MIT