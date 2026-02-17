# v1.0 Feature Ideas

Приоритизированный список фич для PolicyShield v1.0.

**Главный принцип приоритизации:** что заставит человека _поставить_ PolicyShield, а не что сделает его лучше для тех, кто уже поставил.

**Главный барьер adoption:** слишком сложно начать. 99% пользователей OpenClaw не security-инженеры. Им нужно «поставил → защищён», а не «напиши 50 строк YAML».

---

## 🔥 Tier 0 — «Поставил и защищён» (must-have для v1.0)

Цель: путь пользователя за 30 секунд:
```
pip install policyshield
policyshield init --preset secure
policyshield doctor
# Готово. Защищён.
```

### 1. Built-in Security Patterns ⭐

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

Сейчас `blocked_patterns` есть, но пользователь должен **сам** знать паттерны. Бессмысленно — если он их знает, он уже и без PolicyShield в безопасности.

- **Усилия**: Средние (каталог regex + validators)
- **Ценность**: 🔥🔥🔥 — защита из коробки без знаний security
- **Зависимости**: sanitizer (есть, расширить)
- **Почему #1**: Это единственная фича, которая превращает PolicyShield из конструктора в продукт

### 2. Kill Switch — аварийная остановка ⭐

Один endpoint или CLI-команда, которая мгновенно блокирует ВСЕ вызовы:

```
policyshield kill                    # CLI
POST /api/v1/kill                    # REST
policyshield resume                  # снять блокировку
```

Как `docker stop` для AI-агента. Без этого нельзя чувствовать себя безопасно.

- **Усилия**: Маленькие (~50 строк, атомарный `_killed` флаг в engine)
- **Ценность**: 🔥🔥🔥 — паника-кнопка, огромный психологический эффект
- **Зависимости**: engine (добавить атомарный флаг)

### 3. Secure-by-Default Preset ⭐

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

Пресет `openclaw` уже есть, но он `default_verdict: allow`. Нужен именно `secure` с BLOCK.

- **Усилия**: Маленькие (YAML шаблон + init_scaffold)
- **Ценность**: 🔥🔥 — zero-config security
- **Зависимости**: init_scaffold (есть), зависит от #1

### 4. `policyshield doctor` — диагностика ⭐

Проверяет текущую конфигурацию и выдаёт score:

```
$ policyshield doctor

PolicyShield Health Check
═════════════════════════
✅ Rules loaded: 12 rules from rules.yaml
✅ Default verdict: BLOCK (secure)
✅ Sanitizer: enabled (5 detectors)
✅ PII scanner: enabled
⚠️  Rate limiting: not configured
⚠️  Approval backend: none (APPROVE verdicts will fail)
❌ No chain rules — data exfiltration not covered

Score: 7/10
Recommendations:
  1. Add rate limiting: rate_limit: {max_calls: 100, window: 60}
  2. Configure approval: approval_backend: telegram
  3. Add chain rule for read→send pattern
```

Как `brew doctor` или `next lint` — помогает понять, что не так.

- **Усилия**: Маленькие (проверки конфига + вывод)
- **Ценность**: 🔥🔥 — onboarding, уменьшает ошибки конфигурации
- **Зависимости**: нет

### 5. Auto-Rules from OpenClaw

Автогенерация правил из инвентаря инструментов OpenClaw:

```
policyshield generate-rules --from-openclaw http://localhost:3000
```

Смотрит какие тулы зарегистрированы → классифицирует (safe/dangerous/critical) → генерирует YAML. Не нужен LLM — маппинг по именам (`delete_*` → BLOCK, `read_*` → ALLOW, `send_*` → APPROVE). Классификатор уже есть в `ai/templates.py`.

- **Усилия**: Средние (HTTP client + classifier + YAML writer)
- **Ценность**: 🔥🔥 — правила за 0 секунд
- **Зависимости**: OpenClaw API (список тулов), classifier (есть)

### 6. Honeypot Tools

Фейковые тулы-ловушки. Если агент пытается вызвать `admin_panel` или `get_credentials` — мгновенный BLOCK + алерт.

```yaml
honeypots:
  - tool: admin_panel
  - tool: get_credentials
  - tool: delete_all_data
  alert: telegram
```

Ловит prompt injection и confused deputy. Ни у кого такого нет.

- **Усилия**: Маленькие (~30 строк, специальное правило + алерт)
- **Ценность**: 🔥 — ранний индикатор компрометации

---

## ✅ Tier 1 — Реализовано (v0.10)

| Фича | Статус |
|------|--------|
| Replay & Simulation | ✅ `policyshield replay` |
| Chain Rules | ✅ `EventRingBuffer` + `ChainCondition` |
| AI-Assisted Rule Writing | ✅ `policyshield generate` (templates + LLM) |

---

## 🟡 Tier 2 — Medium Impact (после v1.0)

### 7. Shadow Mode

Новые правила работают параллельно, но не блокируют — только логируют:

```
policyshield shadow rules_v2.yaml --duration 1h
```

- **Усилия**: Средние (dual-path в engine)
- **Ценность**: Высокая — безопасный деплой правил
- **Примечание**: `AUDIT` mode уже есть, но per-file shadow — отдельная фича

### 8. Dead Rule Detection

Правила, которые никогда не сработали:

```
policyshield lint --check unused --traces traces/
```

- **Усилия**: Маленькие (cross-ref traces × rules)
- **Ценность**: Средняя — гигиена правил

### 9. Dynamic Rules — загрузка по HTTP/S3

Центральный сервер правил для флота агентов:

```yaml
rules:
  source: https://policies.internal/rules.yaml
  signature_key: ${POLICY_SIGN_KEY}
  refresh: 30s
```

- **Усилия**: Средние
- **Ценность**: Высокая для production multi-agent
- **Зависимости**: watcher (адаптировать под HTTP polling)

### 10. Rule Composition

`include:`, `extends:`, `priority:` — переиспользование и наследование правил.

```yaml
include:
  - ./base_rules.yaml
  - ./team_overrides.yaml
```

- **Усилия**: Средние
- **Ценность**: Средняя — нужно для больших конфигов

### 11. Budget Caps

Не «10 вызовов в минуту», а «не больше $5 за сессию»:

```yaml
budget:
  max_per_session: 5.00
  max_per_hour: 20.00
  currency: USD
```

- **Усилия**: Средние (интеграция с cost estimator)
- **Ценность**: Средняя — для платных API

### 12. Zero-Config Block Alerts

Когда что-то заблокировано — нотификация, одна строка:

```yaml
alerts:
  on_block: telegram  # или slack, webhook
```

- **Усилия**: Маленькие (sugar поверх alert engine)
- **Ценность**: Средняя

### 13. Compliance Reports

PDF/HTML отчёт для аудиторов:

```
policyshield report --period 30d --format pdf
```

- **Усилия**: Средние (aggregator + jinja2 шаблоны)
- **Ценность**: Высокая для enterprise

### 14. Incident Timeline

Авто-генерация таймлайна сессии при инциденте:

```
policyshield incident session_abc123 --format html
```

- **Усилия**: Средние (trace reader + HTML renderer)
- **Ценность**: Высокая — post-mortem

### 15. Canary Deployments для правил

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

**Почему отдельный tier:** меняет value proposition с «бесплатный 0ms фаервол» на «платный медленный фаервол». Мощно, но не для первого знакомства. Делать после того, как adoption state прошёл.

### 16. Prompt Injection Guard

LLM-классификатор проверяет аргументы тулов на prompt injection:

```yaml
sanitizer:
  prompt_injection_guard:
    enabled: true
    model: gpt-4o-mini
    action: BLOCK
```

- **Усилия**: Средние
- **Ценность**: Огромная — самая актуальная угроза
- **Latency**: +300ms

### 17. Semantic PII Detection

LLM-based PII как второй проход после regex:

```yaml
pii:
  llm_scan: true
  llm_model: gpt-4o-mini
```

- **Усилия**: Средние
- **Latency**: +300ms

### 18. Intent Classification

LLM видит **намерение**: агент прочитал БД → вызывает `send_http` с теми же данными → exfiltration.

```yaml
llm_guard:
  checks:
    - intent_classification
    - exfiltration_detection
  on_suspicious: APPROVE
  on_malicious: BLOCK
```

- **Усилия**: Большие (контекст сессии в prompt)
- **Latency**: +500ms

### 19. Explainable Verdicts

LLM генерирует объяснение при блокировке:

```json
{
  "verdict": "BLOCK",
  "explanation": "Agent attempted to send database contents via HTTP.",
  "risk_score": 0.92,
  "recommendation": "If intended, add rule 'allow-export-reports'"
}
```

- **Усилия**: Маленькие
- **Latency**: +200ms

### 20. Anomaly Detection

Статистический baseline: «агент обычно делает read_file 5-10 раз», 200 вызовов delete — аномалия.

- **Усилия**: Большие
- **Latency**: +5ms (статистика) или +500ms (LLM)

### 21. Multi-Step Plan Analysis

Оценка плана агента целиком до выполнения:

```
Plan: 1) read_database → 2) format_csv → 3) send_email
Risk: HIGH — data from step 1 leaves system at step 3
```

- **Усилия**: Большие (нужен доступ к плану агента)
- **Latency**: +500ms

---

## 🔵 Tier 4 — Enterprise/Scale (после product-market fit)

| Фича | Описание |
|------|----------|
| Conditional Rules (time/role) | `time_of_day: "09:00-18:00"`, `user_role: admin` |
| RBAC | Per-role policy sets |
| Federated Policies | Центральный policy server с push-updates |
| Multi-Tenant | Per-org policy sets с наследованием |
| Rule Versioning & Rollback | Git-подобное `rules history`, `rules rollback v3` |
| Chaos Testing | Рандомный блок/задержка для стресс-тестов |
| Data Watermarking | Невидимые маркеры в данных для tracking утечек |
| Cost Attribution | Разбивка стоимости по агенту/сессии/пользователю |

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

**6 фич, ~5-7 дней работы:**

| # | Фича | Усилия | Эффект |
|---|------|--------|--------|
| 1 | Built-in Security Patterns | Средние | 🔥🔥🔥 |
| 2 | Kill Switch | Маленькие | 🔥🔥🔥 |
| 3 | Secure-by-Default Preset | Маленькие | 🔥🔥 |
| 4 | `policyshield doctor` | Маленькие | 🔥🔥 |
| 5 | Auto-Rules from OpenClaw | Средние | 🔥🔥 |
| 6 | Honeypot Tools | Маленькие | 🔥 |

**Критерий успеха:** пользователь ставит PolicyShield, запускает 2 команды, и защищён. Без чтения документации, без написания YAML, без знания security.
