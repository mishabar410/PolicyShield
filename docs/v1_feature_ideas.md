# v1.0 Feature Ideas

Приоритизированный список фич для следующей версии PolicyShield.

---

## 🔥 Tier 1 — High Impact

### 1. Replay & Simulation

Перепрогонка исторических трейсов через новые правила **до** деплоя. Всё готово: JSONL трейсы, матчер, CLI.

```
policyshield replay traces/ --rules new_rules.yaml --diff
```

- **Усилия**: Средние
- **Ценность**: Огромная — убирает страх менять правила
- **Зависимости**: trace reader (есть), matcher (есть), diff formatter (есть)

### 2. Chain Rules — временные зависимости

«Если вызвали `read_file`, то `send_email` блокируется 60 секунд.» Stateful temporal policy — то, чего ни у кого нет.

```yaml
- id: no-exfil
  when:
    chain:
      - tool: read_database
      - tool: send_email
        within: 60s
  then: BLOCK
  message: "Data exfiltration: read → send blocked for 60s"
```

- **Усилия**: Большие (новый тип matching, ring buffer событий в сессии)
- **Ценность**: Огромная — основной кейс утечки данных
- **Зависимости**: session manager (есть), matcher (расширить)

### 3. AI-Assisted Rule Writing

Генерация YAML-правил по текстовому описанию через LLM.

```
policyshield generate "block file deletion and email sending with PII"
```

- **Усилия**: Средние (structured output, few-shot prompting)
- **Ценность**: Высокая — снижает порог входа в 10 раз
- **Зависимости**: OpenAI/Anthropic API (опционально)

---

## 🟡 Tier 2 — Medium Impact

### 4. Compliance Packs

Готовые наборы правил: GDPR, HIPAA, SOC2, PCI-DSS. Ставятся одной командой.

```
policyshield init --preset gdpr
policyshield init --preset hipaa
```

- **Усилия**: Небольшие (YAML + документация)
- **Ценность**: Высокая для enterprise
- **Зависимости**: init_scaffold (есть, расширить пресеты)

### 5. Dynamic Rules — загрузка по HTTP/S3

Центральный сервер правил для флота агентов. Фетч с подписью.

```yaml
rules:
  source: https://policies.internal/rules.yaml
  signature_key: ${POLICY_SIGN_KEY}
  refresh: 30s
```

- **Усилия**: Средние
- **Ценность**: Высокая для production multi-agent
- **Зависимости**: watcher (адаптировать под HTTP polling)

### 6. Rule Composition

`include:`, `extends:`, `priority:` — переиспользование и наследование правил.

```yaml
include:
  - ./base_rules.yaml
  - ./team_overrides.yaml

rules:
  - id: override-example
    extends: base-block-delete
    priority: 100
```

- **Усилия**: Средние
- **Ценность**: Средняя — нужно для больших конфигов

---

## 🔵 Tier 3 — Nice to Have

### 7. Conditional Rules (time/role/context)

```yaml
when:
  context:
    time_of_day: "09:00-18:00"
    user_role: admin
```

### 8. RBAC — Role-Based Tool Access

Per-role policy sets: `admin` может удалять, `viewer` — нет.

### 9. Federated Policies

Центральный policy server для fleet of agents с push-updates.

### 10. Multi-Tenant

Per-org policy sets с наследованием.

---

## 🛡️ «Поставил и спокоен» — фичи для OpenClaw-пользователей

Сценарий: человек ставит OpenClaw → хочет безопасности → ставит PolicyShield → настраивает за 5 минут → уверен, что ничего страшного не случится.

### 11. Built-in Security Patterns (самое важное!)

Встроенные детекторы опасных аргументов, работают **без единого правила в YAML**:

```yaml
sanitizer:
  enabled: true
  builtin_detectors:
    - path_traversal    # ../../../etc/passwd
    - shell_injection   # ; rm -rf / , | curl, `cmd`
    - sql_injection     # ' OR 1=1 --, UNION SELECT
    - ssrf              # file://, http://169.254.169.254
    - url_schemes       # javascript:, data:, ftp://
```

Сейчас `blocked_patterns` есть, но пользователь должен **сам** знать паттерны. 99% не знают.

- **Усилия**: Средние (каталог regex + validators)
- **Ценность**: Огромная — защита из коробки без знаний security
- **Зависимости**: sanitizer (есть, расширить)

### 12. Kill Switch — аварийная остановка

Один endpoint или CLI-команда, которая мгновенно блокирует ВСЕ вызовы:

```
policyshield kill                    # CLI
POST /api/v1/kill                    # REST
policyshield resume                  # снять блокировку
```

Как `docker stop` для AI-агента. Без этого нельзя чувствовать себя безопасно.

- **Усилия**: Небольшие (глобальный флаг в engine)
- **Ценность**: Огромная — паника-кнопка
- **Зависимости**: engine (добавить `_killed` атомарный флаг)

### 13. Secure-by-Default Preset

`policyshield init --preset secure` ставит **default BLOCK** + whitelist:

```yaml
default_verdict: BLOCK
sanitizer:
  enabled: true
  builtin_detectors: [path_traversal, shell_injection, sql_injection, ssrf]
rules:
  - id: allow-safe-tools
    when:
      tool: [search, read_file, list_dir]
    then: ALLOW
  - id: approve-dangerous
    when:
      tool: [write_file, execute, send_email]
    then: APPROVE
```

- **Усилия**: Небольшие (YAML шаблон + init_scaffold)
- **Ценность**: Высокая — zero-config security
- **Зависимости**: init_scaffold (есть)

### 14. Auto-Rules from OpenClaw Tool List

Автогенерация правил из инвентаря инструментов OpenClaw:

```
policyshield generate-rules --from-openclaw http://localhost:3000
```

Смотрит какие тулы зарегистрированы → классифицирует (safe/dangerous/critical) → генерирует YAML. Не нужен LLM — маппинг по именам (`delete_*` → BLOCK, `read_*` → ALLOW, `send_*` → APPROVE).

- **Усилия**: Средние (HTTP client + classifier + YAML writer)
- **Ценность**: Высокая — правила за 0 секунд
- **Зависимости**: OpenClaw API (список тулов)

### 15. Budget Caps

Не «10 вызовов в минуту», а «не больше $5 за сессию»:

```yaml
budget:
  max_per_session: 5.00
  max_per_hour: 20.00
  currency: USD
```

- **Усилия**: Средние (интеграция с cost estimator)
- **Ценность**: Средняя — для платных API
- **Зависимости**: cost estimator (есть)

### 16. Zero-Config Block Alerts

Когда что-то заблокировано — сразу нотификация, одна строка конфига:

```yaml
alerts:
  on_block: telegram  # или slack, webhook
```

- **Усилия**: Небольшие (sugar поверх alert engine)
- **Ценность**: Средняя — awareness

---

## 🧠 LLM-Powered фичи

Архитектура: **LLM Guard как опциональный middleware** в pipeline. Без LLM — всё работает как сейчас (0ms). С LLM — +200-500ms, но ловит то, что regex не может. Включается per-rule.

```
Tool Call → Sanitizer → Regex Rules → [LLM Guard] → Verdict
```

### 17. Prompt Injection Guard

LLM-классификатор проверяет аргументы тулов на prompt injection:

```yaml
sanitizer:
  prompt_injection_guard:
    enabled: true
    model: gpt-4o-mini
    action: BLOCK
```

Ловит: `"Ignore all previous instructions..."`, перефразированные атаки, закодированные payload'ы.

- **Усилия**: Средние
- **Ценность**: Огромная — самая актуальная угроза
- **Latency**: +300ms

### 18. Semantic PII Detection

LLM-based PII как второй проход после regex. Ловит то, что regex не может:
- «мой номер паспорта пять пять ноль три…»
- «Иванов Пётр, ул. Ленина 42, кв. 15»

```yaml
pii:
  enabled: true
  llm_scan: true
  llm_scan_threshold: 0.7
  llm_model: gpt-4o-mini
```

- **Усилия**: Средние
- **Ценность**: Высокая
- **Latency**: +300ms

### 19. Intent Classification

LLM видит **намерение**: агент прочитал БД → вызывает `send_http` с теми же данными → exfiltration, даже если аргументы чистые.

```yaml
llm_guard:
  enabled: true
  model: gpt-4o-mini
  checks:
    - intent_classification
    - exfiltration_detection
  on_suspicious: APPROVE
  on_malicious: BLOCK
```

- **Усилия**: Большие (контекст сессии в prompt)
- **Ценность**: Огромная
- **Latency**: +500ms

### 20. Explainable Verdicts

Когда PolicyShield блокирует — LLM генерирует объяснение:

```json
{
  "verdict": "BLOCK",
  "explanation": "Agent attempted to send database contents via HTTP. This matches data exfiltration pattern.",
  "risk_score": 0.92,
  "recommendation": "If intended, add rule 'allow-export-reports'"
}
```

- **Усилия**: Небольшие
- **Ценность**: Высокая — DX и доверие
- **Latency**: +200ms

### 21. Anomaly Detection

Выучивает baseline: «агент обычно делает read_file 5-10 раз, потом summarize». 200 вызовов delete — аномалия.

```yaml
anomaly:
  enabled: true
  learning_period: 100
  sensitivity: medium
  on_anomaly: APPROVE
```

- **Усилия**: Большие (можно статистически, без LLM)
- **Ценность**: Средняя
- **Latency**: +5ms (статистика) или +500ms (LLM)

### 22. Multi-Step Plan Analysis

Оценка плана агента целиком до выполнения:

```
Plan: 1) read_database → 2) format_csv → 3) send_email
Risk: HIGH — data from step 1 leaves system at step 3
```

- **Усилия**: Большие (нужен доступ к плану агента)
- **Ценность**: Высокая
- **Latency**: +500ms

### LLM Guard — топ-3 для v1.0

**Prompt Injection Guard + Semantic PII + Explainable Verdicts** — реально продаются и реально защищают.

---

## 🕶️ DevOps для правил + Forensics

### 23. Shadow Mode

Новые правила работают параллельно, но не блокируют — только логируют. «Что бы произошло» без риска.

```yaml
mode: shadow  # log-only, no enforcement
```

```
policyshield shadow rules_v2.yaml --duration 1h
```

- **Усилия**: Средние (dual-path в engine)
- **Ценность**: Огромная — безопасный деплой правил

### 24. Honeypot Tools

Фейковые тулы-ловушки. Если агент пытается вызвать `admin_panel` или `get_credentials` — мгновенный BLOCK + алерт.

```yaml
honeypots:
  - tool: admin_panel
  - tool: get_credentials
  - tool: delete_all_data
  alert: telegram
```

- **Усилия**: Небольшие (специальное правило + алерт)
- **Ценность**: Высокая — ранний индикатор компрометации

### 25. Compliance Reports

PDF/HTML отчёт для аудиторов: X вызовов, Y заблокировано, Z PII, breakdown по тулам.

```
policyshield report --period 30d --format pdf
```

- **Усилия**: Средние (aggregator + jinja2 шаблоны)
- **Ценность**: Высокая для enterprise

### 26. Rule Versioning & Rollback

Git-подобное версионирование правил с мгновенным откатом:

```
policyshield rules history
policyshield rules rollback v3
policyshield rules diff v3 v5
```

- **Усилия**: Средние (снапшоты + diff уже есть)
- **Ценность**: Средняя

### 27. Chaos / Stress Testing

Рандомный блок/задержка тулов для проверки устойчивости агента:

```
policyshield chaos --block-rate 10% --delay 500ms --duration 5m
```

- **Усилия**: Небольшие (random verdict override)
- **Ценность**: Средняя — для зрелых команд

### 28. Dead Rule Detection

Правила, которые никогда не сработали (мёртвый код в policies):

```
policyshield lint --check unused --traces traces/
```

- **Усилия**: Небольшие (cross-ref traces × rules)
- **Ценность**: Средняя — гигиена правил

### 29. Data Watermarking

Невидимые маркеры в данных, проходящих через тулы. Если утекут — можно отследить источник.

- **Усилия**: Большие (Unicode zero-width, стеганография)
- **Ценность**: Средняя — niche но впечатляет

### 30. Canary Deployments для правил

Новые правила на 5% сессий → мониторинг → 100%:

```yaml
rules:
  - id: new-strict-rule
    canary: 5%
    promote_after: 24h
```

- **Усилия**: Средние (session hash routing)
- **Ценность**: Высокая для production

### 31. Cost Attribution

Разбивка стоимости по агенту, сессии, пользователю, тулу:

```
policyshield cost breakdown --by agent --period 7d
```

- **Усилия**: Небольшие (расширение cost estimator)
- **Ценность**: Средняя

### 32. Incident Timeline

Авто-генерация таймлайна сессии при инциденте:

```
policyshield incident session_abc123 --format html
```

- **Усилия**: Средние (trace reader + HTML renderer)
- **Ценность**: Высокая — post-mortem

---

## ❄️ Отложить

| Фича | Причина |
|------|---------|
| Rego/OPA bridge | Тяжёлая зависимость, путает пользователей |
| Multi-language SDKs | Преждевременно без product-market fit |
| Agent sandbox | Другой домен, другой проект |
| Rule marketplace | Нет сообщества |

---

## Рекомендованная комбинация для v1.0

**Built-in Security Patterns + Kill Switch + Secure Preset + Auto-Rules** — четыре фичи, которые превращают PolicyShield из «мощного конструктора правил» в «поставил — защищён».

Дополнительно: **Replay + Chain Rules** — для тех, кто хочет полный контроль.
