# v1.0+ Feature Ideas

Приоритизированный список **нереализованных** фич для PolicyShield.

**Главный принцип приоритизации:** что заставит человека _поставить_ PolicyShield, а не что сделает его лучше для тех, кто уже поставил.

> Реализованные фичи (Tier 0, Tier 1) см. в [ROADMAP.md](../ROADMAP.md) и [CHANGELOG.md](../CHANGELOG.md).

---

## 🔥 Tier 1.5 — DX & Быстрое внедрение

Всё что нужно чтобы пользователь за 5 минут интегрировал PolicyShield без чтения документации.

### Python SDK-клиент для HTTP API 🔴

Сейчас пользователь пишет raw HTTP запросы. Должно быть:

```python
from policyshield.client import PolicyShieldClient

ps = PolicyShieldClient("http://localhost:8100")
result = ps.check("write_file", {"path": "/tmp/x"})
if result.verdict == "APPROVE":
    ps.wait_for_approval(result.approval_id, timeout=300)
```

- **Усилия**: Средние (~200 строк, обёртка над httpx)
- **Ценность**: 🔥🔥🔥 — убирает 80% трения при интеграции

### Готовые пресеты по ролям 🔴

`policyshield init --preset coding-agent`, `--preset data-analyst`, `--preset customer-support`. 90% пользователей хотят «включил и забыл», а не писать YAML.

- **Усилия**: Маленькие (YAML шаблоны)
- **Ценность**: 🔥🔥🔥 — zero-config для конкретного use case

### `policyshield quickstart` — интерактивный мастер 🔴

Спрашивает «какие инструменты использует ваш агент?», генерирует правила, запускает сервер, выводит код для интеграции. Одна команда от нуля до работающей защиты.

- **Усилия**: Средние (wizard CLI + template engine)
- **Ценность**: 🔥🔥🔥 — самый короткий путь к value

### Dry-run CLI (`policyshield check`) 🔴

Проверить один вызов без поднятия сервера:

```bash
policyshield check --tool exec --args '{"cmd":"rm -rf /"}' --rules rules.yaml
```

- **Усилия**: Маленькие (~30 строк)
- **Ценность**: 🔥🔥 — отладка правил без запуска сервера

### Approval Timeout & Escalation 🔴

Когда вердикт APPROVE, а человек не ответил — что происходит?

```yaml
approval:
  timeout: 300s
  on_timeout: BLOCK         # или AUTO_APPROVE
  escalation:
    after: 600s
    notify: [admin@corp.com]
```

- **Усилия**: Средние (таймеры, escalation chain)
- **Ценность**: 🔥🔥🔥 — для production это критично

### Decorator/middleware API 🟡

Inline интеграция без отдельного сервера:

```python
from policyshield import shield

@shield(engine)
def my_tool(args):
    ...
```

- **Усилия**: Маленькие (~50 строк)
- **Ценность**: 🔥🔥 — для тех кто не хочет отдельный сервер

### JS/TS SDK 🟡

Python SDK — начало, но большинство агентов на Node.js. Без JS клиента теряем огромную аудиторию.

```typescript
import { PolicyShield } from '@policyshield/client';
const ps = new PolicyShield('http://localhost:8100');
const result = await ps.check('write_file', { path: '/tmp/x' });
```

- **Усилия**: Средние (~300 строк TypeScript)
- **Ценность**: 🔥🔥 — открывает Node.js аудиторию

### Slack/Webhook уведомления о нарушениях 🟡

Telegram есть, но Slack в корпоративном мире важнее. Webhook для кастомных интеграций.

```yaml
alerts:
  on_block: slack
  slack_webhook: ${SLACK_WEBHOOK_URL}
```

- **Усилия**: Маленькие (адаптер поверх alert engine)
- **Ценность**: 🔥🔥 — enterprise adoption

### Рабочие примеры интеграций 🟡

Не документация, а `git clone && python run.py`:

```
examples/
  langchain_agent/     # полный агент с PolicyShield
  crewai_workflow/     # CrewAI pipeline
  autogen_agent/       # AutoGen multi-agent
  fastapi_service/     # микросервис с check/approve
  docker_compose/      # сервер + агент + monitoring
```

- **Усилия**: Средние (5-6 рабочих примеров)
- **Ценность**: 🔥🔥 — proof of concept за 2 минуты

### `policyshield test --coverage` 🟢

Показывает какие инструменты агента покрыты правилами:

```
$ policyshield test --coverage --tools exec,read_file,write_file,send_email
Coverage: 3/4 tools (75%)
  ✅ exec → block-exec
  ✅ read_file → allow-read-file
  ✅ send_email → redact-pii
  ❌ write_file → no matching rule (default: BLOCK)
```

- **Усилия**: Маленькие
- **Ценность**: 🔥 — уверенность что ничего не пропущено

### Web UI дашборд 🟢

Посмотреть что заблочено, одобрить/отклонить, статистика PII — прямо в браузере.

- **Усилия**: Большие (SPA + WebSocket)
- **Ценность**: 🔥 — визуализация для менеджеров

---

## 🟡 Tier 2 — Medium Impact (после v1.0)

### Shadow Mode

Новые правила работают параллельно, но не блокируют — только логируют:

```
policyshield shadow rules_v2.yaml --duration 1h
```

- **Усилия**: Средние (dual-path в engine)
- **Ценность**: Высокая — безопасный деплой правил

### Output/Response Policy

Проверка не только аргументов, но и **ответов** тулов:

```yaml
output_policy:
  max_size: 10MB
  block_patterns: [base64_blob, executable_content]
  rules:
    - when: { tool: read_database, output_contains: "password" }
      then: REDACT
```

- **Усилия**: Средние (вторая pipeline для output)
- **Ценность**: Высокая — сейчас output проверяется только на PII

### Plugin System (extensible detectors)

Generic API для подключения кастомных детекторов и хуков:

```python
from policyshield.plugins import detector

@detector("credit_score_leak")
def check_credit_score(args: dict) -> bool:
    return "credit_score" in str(args)
```

- **Усилия**: Средние (plugin registry + hooks)
- **Ценность**: Высокая — расширяемость без форков

### Dead Rule Detection

Правила, которые никогда не сработали:

```
policyshield lint --check unused --traces traces/
```

- **Усилия**: Маленькие (cross-ref traces × rules)
- **Ценность**: Средняя — гигиена правил

### Dynamic Rules — загрузка по HTTP/S3

Центральный сервер правил для флота агентов:

```yaml
rules:
  source: https://policies.internal/rules.yaml
  signature_key: ${POLICY_SIGN_KEY}
  refresh: 30s
```

- **Усилия**: Средние
- **Ценность**: Высокая для production multi-agent

### Rule Composition

`include:`, `extends:`, `priority:` — переиспользование и наследование правил.

```yaml
include:
  - ./base_rules.yaml
  - ./team_overrides.yaml
```

- **Усилия**: Средние
- **Ценность**: Средняя — нужно для больших конфигов

### Budget Caps

Не «10 вызовов в минуту», а «не больше $5 за сессию»:

```yaml
budget:
  max_per_session: 5.00
  max_per_hour: 20.00
  currency: USD
```

- **Усилия**: Средние (интеграция с cost estimator)
- **Ценность**: Средняя — для платных API

### Global & Adaptive Rate Limiting

Текущий rate limiter — per-tool sliding window. Не хватает:
- **Global rate limit** (все тулы в сумме)
- **Adaptive**: при аномальном поведении автоматически ужесточить
- **Per-user/role** (связано с RBAC)

- **Усилия**: Средние
- **Ценность**: Средняя — production hardening

### Compliance Reports

PDF/HTML отчёт для аудиторов:

```
policyshield report --period 30d --format pdf
```

- **Усилия**: Средние (aggregator + jinja2 шаблоны)
- **Ценность**: Высокая для enterprise

### Incident Timeline

Авто-генерация таймлайна сессии при инциденте:

```
policyshield incident session_abc123 --format html
```

- **Усилия**: Средние (trace reader + HTML renderer)
- **Ценность**: Высокая — post-mortem

### Canary Deployments для правил

Новые правила на 5% сессий → мониторинг → 100%:

```yaml
rules:
  - id: new-strict-rule
    canary: 5%
    promote_after: 24h
```

- **Усилия**: Средние (session hash routing)
- **Ценность**: Высокая для production

---

## 🧠 Tier 3 — LLM Guard (отдельный milestone)

Архитектура: **LLM Guard как опциональный middleware** в pipeline. Без LLM — всё работает как сейчас (0ms). С LLM — +200-500ms, но ловит то, что regex не может. Включается per-rule.

```
Tool Call → Sanitizer → Regex Rules → [LLM Guard] → Verdict
```

**Почему отдельный tier:** меняет value proposition с «бесплатный 0ms фаервол» на «платный медленный фаервол». Мощно, но не для первого знакомства.

### Prompt Injection Guard

LLM-классификатор проверяет аргументы тулов на prompt injection:

```yaml
sanitizer:
  prompt_injection_guard:
    enabled: true
    model: gpt-4o-mini
    action: BLOCK
```

- **Усилия**: Средние | **Latency**: +300ms

### Semantic PII Detection

LLM-based PII как второй проход после regex:

```yaml
pii:
  llm_scan: true
  llm_model: gpt-4o-mini
```

- **Усилия**: Средние | **Latency**: +300ms

### Intent Classification

LLM видит **намерение**: агент прочитал БД → вызывает `send_http` с теми же данными → exfiltration.

```yaml
llm_guard:
  checks:
    - intent_classification
    - exfiltration_detection
  on_suspicious: APPROVE
  on_malicious: BLOCK
```

- **Усилия**: Большие | **Latency**: +500ms

### Explainable Verdicts

LLM генерирует объяснение при блокировке:

```json
{
  "verdict": "BLOCK",
  "explanation": "Agent attempted to send database contents via HTTP.",
  "risk_score": 0.92,
  "recommendation": "If intended, add rule 'allow-export-reports'"
}
```

- **Усилия**: Маленькие | **Latency**: +200ms

### Anomaly Detection

Статистический baseline: «агент обычно делает read_file 5-10 раз», 200 вызовов delete — аномалия.

- **Усилия**: Большие | **Latency**: +5ms (статистика) или +500ms (LLM)

### Multi-Step Plan Analysis

Оценка плана агента целиком до выполнения:

```
Plan: 1) read_database → 2) format_csv → 3) send_email
Risk: HIGH — data from step 1 leaves system at step 3
```

- **Усилия**: Большие (нужен доступ к плану агента) | **Latency**: +500ms

---

## 🔵 Tier 4 — Enterprise/Scale (после product-market fit)

| Фича | Описание |
|------|----------|
| Conditional Rules (time/role) | `time_of_day: "09:00-18:00"`, `user_role: admin` |
| RBAC | Per-role policy sets |
| Multi-Agent Orchestration | Cross-agent policy, session isolation/sharing |
| Federated Policies | Центральный policy server с push-updates |
| Multi-Tenant | Per-org policy sets с наследованием |
| Rule Versioning & Rollback | Git-подобное `rules history`, `rules rollback v3` |
| Chaos Testing | Рандомный блок/задержка для стресс-тестов |
| Data Watermarking | Невидимые маркеры в данных для tracking утечек |
| Cost Attribution | Разбивка стоимости по агенту/сессии/пользователю |
| Signed Rule Bundles | Подписанные пакеты правил для air-gapped окружений |
| API Versioning & Deprecation | Формальная политика v1 → v2 миграции |
| Config Schema Migration | Auto-migrate старого формата конфига при обновлении |

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
| AutoGen | 🔥🔥 | Быстро растёт, multi-agent |
| LlamaIndex Agents | 🔥 | Agents mode набирает обороты |
| Semantic Kernel | 🔥 | Microsoft ecosystem |
| OpenAI Assistants API | 🔥🔥 | Прямая интеграция без прокси |
| Anthropic tool use | 🔥🔥 | Прямая интеграция |
