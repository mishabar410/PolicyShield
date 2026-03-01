# PolicyShield v1.0 — Brainstorm

> Текущее состояние: **v0.14.0** released. 1350 тестов, 85% coverage.
> Дата: 2026-03-01

---

## 🏗️ Архитектурный долг

### Покрытие тестами (текущее: 85%)
| Файл | Coverage | Что нужно |
|------|----------|-----------|
| `mcp_proxy.py` | ~0% | Unit-тесты forward/block/modify path |
| `mcp_server.py` | ~16% | Тесты start/stop/tool_list/check |
| `cli/quickstart.py` | ~0% | Mock stdin для интерактивного потока |
| `cli/openclaw.py` | ~28% | Тесты fetch tools, error handling |
| `sdk/async_client.py` | ~40% | Тесты timeout, retry, error scenarios |
| `trace/search.py` | ~81% | Edge-cases фильтрации |
| **Цель** | **90%** | Поднять coverage gate в CI |

### Код качество
- [ ] 2 mypy ошибки в `cli/main.py` (строки ~1428, 1430)
- [ ] `test_packaging.py` — уже пофикшен (динамические версии)
- [ ] Убрать `# type: ignore` там где можно

---

## ✅ Tier 3A — Must-Have для v1.0 (реализовано в v0.14.0)

### 1. LLM Guard (optional middleware) ✅

Архитектура: LLM как **опциональный** шаг в pipeline. Без LLM — 0ms. С LLM — +200-500ms.

```
Tool Call → Sanitizer → Regex Rules → [LLM Guard] → Verdict
```

| Компонент | Описание | Latency | Сложность |
|-----------|----------|---------|-----------|
| **Prompt Injection Guard** | LLM-классификатор для prompt injection в аргументах | +300ms | 🟡 |
| **Semantic PII Detection** | LLM-based PII как второй проход после regex | +300ms | 🟡 |
| **Intent Classification** | read_database → send_http = exfiltration | +500ms | 🔴 |
| **Explainable Verdicts** | LLM объясняет почему заблокировано + risk score | +200ms | 🟡 |
| **Anomaly Detection** | Статистика: "агент обычно делает read_file 5-10 раз, 200 delete — аномалия" | 0ms | 🔴 |
| **Multi-Step Plan Analysis** | Оценка плана агента целиком до выполнения | +500ms | 🔴 |

**Ключевые решения:**
- Model: `gpt-4o-mini` для скорости vs `gpt-4o` для качества?
- Кеширование: хешировать аргументы → кешировать вердикт на N минут?
- Fallback: если LLM недоступен → regex-only?
- Конфиг: `llm_guard: { enabled: true, model: gpt-4o-mini, timeout: 2s, cache_ttl: 300 }`

### 2. Natural Language → Policy Compiler ✅

LLM компилирует человеческие описания «что нельзя» в структурированные YAML-правила.

**Пользовательский ввод** (plain text или markdown):
```
Никогда не удалять production базы данных.
Файлы .env запрещены для чтения вне CI.
Деплой только в рабочее время, только для admin.
Email с PII — блокировать и логировать.
```

**Результат** (сгенерированный YAML):
```yaml
rules:
  - id: block-prod-db-delete
    when:
      tool: delete_database
      args_match:
        database: "*prod*"
    then: BLOCK
    severity: critical
    message: "Production database deletion is prohibited"

  - id: block-dotenv-read
    when:
      tool: read_file
      args_match:
        path: "*.env"
      context:
        environment: "!ci"
    then: BLOCK
    message: ".env files can only be read in CI"

  - id: deploy-office-hours-admin
    when:
      tool: deploy
      context:
        time_of_day: "!09:00-18:00"
        user_role: "!admin"
    then: BLOCK
    message: "Deploy allowed only Mon-Fri 9-18 by admins"

  - id: block-pii-email
    when:
      tool: send_email
    then: REDACT
    pii_action: block_and_log
    message: "PII detected in email — blocked"
```

**Реализация:**
- [x] CLI: `policyshield compile "описание на человеческом языке" -o rules.yaml`
- [x] CLI: `policyshield compile --file restrictions.md -o rules.yaml`
- [x] Двухстадийный pipeline: LLM генерирует → `policyshield validate` проверяет
- [ ] Diff mode: `policyshield compile --diff` — показать что изменится vs текущие правила
- [x] Iterative refinement: если validate fails → LLM исправляет автоматически
- [x] Model: `gpt-4o` для точности, `gpt-4o-mini` для скорости
- [x] Prompt template с примерами existing rules для consistency
- [x] Support conditional rules (time/role) в output

**Ключевое преимущество:**
Не надо знать YAML-формат PolicyShield — пишешь на человеческом языке, получаешь production-ready правила.

### 3. Conditional Rules ✅

```yaml
rules:
  - id: block-after-hours
    when:
      tool: deploy
      context:
        time_of_day: "!09:00-18:00"  # Вне рабочих часов
        day_of_week: "!Mon-Fri"      # Только будни
    then: BLOCK
    message: "Deploy allowed only Mon-Fri 9-18"

  - id: admin-only-delete
    when:
      tool: delete_*
      context:
        user_role: "!admin"  # Если НЕ admin
    then: BLOCK
```

**Что нужно:**
- [x] Расширить `when` matcher для context conditions
- [x] Передавать `context` dict в `engine.check()`
- [x] Time parsing (timezone-aware)
- [x] Wildcard tool matching (`delete_*`)

### 4. Bounded Session Storage ✅

Сейчас: `InMemorySessionManager` растёт бесконечно.

- [x] LRU eviction (max N sessions)
- [x] TTL per session (default 1h)
- [x] Redis backend как альтернатива
- [ ] Метрики: active_sessions, evicted_sessions_total

### 5. Production Deployment Guide ✅

- [x] `docs/deployment.md`
- [x] Docker production Dockerfile (multi-stage, non-root)
- [x] Kubernetes manifests (Deployment, Service)
- [ ] Helm chart
- [x] docker-compose production config
- [x] ENV checklist
- [ ] Monitoring/alerting рекомендации
- [ ] Backup/restore для traces

---

## 🟡 Tier 3B — High Value, Post-v1.0

### 5. Web UI Dashboard

```
┌──────────────────────────────────────────────┐
│ PolicyShield Dashboard                  🟢 v1│
├──────────────────────────────────────────────┤
│                                              │
│  📊 Live Verdicts    🟢 2,340 ALLOW          │
│                      🔴 12 BLOCK             │
│                      🟡 3 APPROVE pending    │
│                                              │
│  📈 Timeline ─────────────────────────────── │
│  ████████████████▓▓░░░░░░░░░░░░░░░░░░░░░░░  │
│                                              │
│  🔍 Recent                                   │
│  14:23 exec rm -rf /     BLOCK  block-exec   │
│  14:22 read_file app.py  ALLOW  default      │
│  14:21 deploy prod       APPROVE pending     │
│                                              │
│  ⚙️ Rules: 11  │ Sessions: 45 │ Uptime: 3d  │
└──────────────────────────────────────────────┘
```

**Stack options:**
- A) **HTMX + Jinja2** — zero JS deps, server-rendered, FastAPI native
- B) **React + Vite** — отдельный SPA, WebSocket для live stream
- C) **Embedded static** — single HTML file bundled in package

**Рекомендация:** вариант A (HTMX) — минимальная сложность, 0 внешних зависимостей.

**Фичи:**
- [ ] Live verdict stream (WebSocket / SSE)
- [ ] Rule editor (YAML + validation)
- [ ] Trace viewer + search
- [ ] Session inspector
- [ ] Kill switch button 🔴
- [ ] Health dashboard
- [ ] API token management

### 6. RBAC (Role-Based Access Control)

```yaml
roles:
  admin:
    allowed: ["*"]
  developer:
    allowed: ["read_file", "write_file", "exec"]
    denied: ["delete_*", "deploy"]
  viewer:
    allowed: ["read_*"]
```

- [ ] Role definitions в YAML
- [ ] Role → tool permission mapping
- [ ] API: `engine.check(tool, args, role='developer')`
- [ ] CLI: `policyshield check --tool deploy --role viewer`

### 7. Agent Identity & Attribution

```python
# Каждый агент имеет identity
result = engine.check("exec", {"cmd": "ls"}, 
    agent_id="coding-agent-1",
    parent_agent_id="orchestrator",
    session_id="s1"
)
```

- [ ] `agent_id` в traces
- [ ] Per-agent rate limits
- [ ] Per-agent policy overrides
- [ ] Agent reputation score (based on historical behavior)

---

## 🔵 Tier 4 — Enterprise / Scale

### 8. Federated Policies
- Центральный PolicyShield Server с push-updates
- Агенты подгружают policy через HTTP
- Event bus: policy changed → all agents reload
- Conflict resolution при multi-source rules

### 9. Multi-Tenant
- Per-org / per-user policy sets
- Policy inheritance (base → org → user)
- Tenant isolation
- SaaS model readiness

### 10. Signed Rule Bundles
- Подписанные пакеты правил для air-gapped окружений
- GPG / cosign для верификации
- `policyshield verify-bundle rules.tar.gz.sig`

### 11. Redis/External State Backend
- Sessions → Redis
- Approvals → Redis with pub/sub
- Traces → ClickHouse / Loki
- Zero local state

### 12. Rule Versioning & Rollback
```bash
policyshield rules history           # показать историю изменений
policyshield rules diff v3 v4        # diff между версиями
policyshield rules rollback v3       # откатить к версии
```

---

## 🧩 Интеграции

| Фреймворк | Приоритет | Тип | Статус |
|-----------|-----------|-----|--------|
| **OpenClaw / MCP** | 🔥🔥🔥 | Plugin + Proxy | ✅ Есть |
| **OpenAI Agents SDK** | 🔥🔥🔥 | Hook wrapper | ❌ Нужно |
| **Anthropic tool_use** | 🔥🔥🔥 | Middleware | ❌ Нужно |
| **LangChain** | 🔥🔥 | ToolGuard callback | ⚠️ Пример есть |
| **CrewAI** | 🔥🔥 | Agent wrapper | ⚠️ Пример есть |
| **AutoGen** | 🔥🔥 | FunctionAdapter | ❌ Нужно |
| **Dify** | 🔥🔥 | Plugin | ❌ Нужно |
| **n8n** | 🔥 | Node | ❌ Нужно |
| **LlamaIndex** | 🔥 | ToolSpec wrapper | ❌ Нужно |
| **Semantic Kernel** | 🔥 | Filter | ❌ Нужно |
| **Haystack** | 🔥 | Component | ❌ Нужно |
| **Vercel AI SDK** | 🔥🔥 | Middleware | ❌ Нужно |

### Формат интеграции

Каждая интеграция = 3 файла:
```
policyshield/integrations/<framework>/
├── __init__.py      # adapter code
├── README.md        # usage guide
└── examples/        # working examples
```

---

## 🚀 DX & Community

### 13. VS Code Extension
- Подсветка синтаксиса для `rules.yaml`
- Inline validation (как ESLint для правил)
- Code actions: "Add BLOCK rule for this tool"
- Snippets для common patterns

### 14. GitHub Action
```yaml
- uses: policyshield/action@v1
  with:
    rules: policies/rules.yaml
    fail-on: warning
```

### 15. Rule Marketplace / Community Packs
```bash
policyshield install-pack owasp-top10
policyshield install-pack gdpr-compliance
policyshield install-pack coding-agent-security
```

### 16. Interactive Playground
- Web-based: paste rules YAML → test tool calls → see verdicts
- Zero install
- Shareable links

---

## ❄️ Отложить

| Фича | Причина |
|------|---------|
| Rego/OPA bridge | Тяжёлая зависимость, мало юзеров |
| Multi-language SDKs (Go, Rust) | Преждевременно, нет спроса |
| Agent sandbox (containers, seccomp) | Другой домен, другой продукт |
| Data watermarking | Нишевая фича |
| Chaos testing | Можно заменить unit-тестами |

---

## 📋 Приоритизированный план

### Phase 1: v1.0-rc (1-2 недели)
1. ~~Покрытие → 90%~~ Тесты для mcp_proxy, quickstart, async_client
2. ~~Conditional rules (time/role)~~ ✅ v0.14.0
3. ~~Bounded session storage (LRU + TTL)~~ ✅ v0.14.0
4. ~~Production deployment guide~~ ✅ v0.14.0
5. Fix mypy errors

### Phase 2: v1.0 (2-3 недели)
6. ~~LLM Guard: prompt injection + semantic PII~~ ✅ v0.14.0
7. ~~NL → Policy Compiler~~ ✅ v0.14.0
8. Web UI dashboard (HTMX)
9. OpenAI Agents SDK integration
10. Anthropic tool_use integration

### Phase 3: v1.1+ (ongoing)
10. RBAC
11. Agent identity
12. Remaining integrations
13. VS Code extension
14. GitHub Action

---

## 💡 Дикие идеи

- **PolicyShield Cloud** — hosted SaaS version, `pip install policyshield && policyshield login`
- **"PolicyShield Certified" badge** — для агентов прошедших audit
- **AI rule advisor** — "your rules have a gap: tool X is unprotected"
- **Compliance-as-a-Service** — SOC2/GDPR/HIPAA rule packs с автоматическим audit trail
- **Agent Firewall** — network-level interception (eBPF?) для полного контроля
- **Policy language DSL** — не YAML, а `BLOCK exec WHERE args.command CONTAINS "rm -rf"`
