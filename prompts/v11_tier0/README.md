# PolicyShield v1.1 — Prompt Chain: Tier 0 «Поставил и защищён»

Цепочка из 12 атомарных промптов: Built-in Detectors → Kill Switch → Secure Preset → Doctor → Auto-Rules → Honeypots.

## Главная цель

Превратить PolicyShield из «мощного конструктора правил» в «поставил — защищён». Путь пользователя:

```
pip install policyshield
policyshield init --preset secure
policyshield doctor
# Готово. Защищён.
```

## Фазы

### Фаза 1: Built-in Security Detectors (промпты 201–203)

| # | Промпт | Основная задача |
|---|--------|-----------------|
| 201 | Detector Registry | Каталог встроенных детекторов (path_traversal, shell_injection, ssrf, sql_injection, url_schemes) |
| 202 | Sanitizer Integration | Интеграция детекторов в `InputSanitizer` — работают без YAML правил |
| 203 | Detector Tests & YAML Config | YAML-конфиг `builtin_detectors:`, unit тесты на каждый детектор |

### Фаза 2: Kill Switch (промпты 204–205)

| # | Промпт | Основная задача |
|---|--------|-----------------|
| 204 | Kill Switch Engine | Атомарный `_killed` флаг в `BaseShieldEngine`, `kill()` / `resume()` методы |
| 205 | Kill Switch CLI & API | CLI `policyshield kill/resume`, REST `POST /api/v1/kill`, `POST /api/v1/resume` |

### Фаза 3: Secure Preset + Doctor (промпты 206–208)

| # | Промпт | Основная задача |
|---|--------|-----------------|
| 206 | Secure Preset | Пресет `--preset secure`: default BLOCK + whitelist + builtin detectors |
| 207 | Doctor Command | CLI `policyshield doctor` — проверка конфига, score, рекомендации |
| 208 | Doctor Tests | Полное покрытие doctor: разные конфиги, scoring, edge cases |

### Фаза 4: Auto-Rules + Honeypots (промпты 209–212)

| # | Промпт | Основная задача |
|---|--------|-----------------|
| 209 | OpenClaw Tool Fetcher | HTTP-клиент для получения списка тулов из OpenClaw API |
| 210 | Auto-Rule Generator | Классификация тулов → генерация YAML правил (без LLM) |
| 211 | CLI `generate-rules` | CLI `policyshield generate-rules --from-openclaw` + вывод |
| 212 | Honeypot Tools | Конфиг `honeypots:` в YAML, matching в engine, алерт при срабатывании |

## Зависимости между промптами

```
201 (Detector Registry)     ← ни от кого
202 (Sanitizer Integration) ← после 201
203 (Detector Tests)        ← после 202

204 (Kill Switch Engine)    ← ни от кого (параллельно с 201–203)
205 (Kill Switch CLI/API)   ← после 204

206 (Secure Preset)         ← после 203 (использует builtin detectors)
207 (Doctor Command)        ← после 206 (проверяет secure preset)
208 (Doctor Tests)          ← после 207

209 (Tool Fetcher)          ← ни от кого (параллельно с 204–208)
210 (Auto-Rule Generator)   ← после 209
211 (CLI generate-rules)    ← после 210
212 (Honeypot Tools)        ← ни от кого (параллельно)
```

> Фазы 1, 2, 4 **независимы** друг от друга. Фаза 3 зависит от Фазы 1 (secure preset использует builtin detectors).

## Правила

1. **Атомарность:** каждый промпт = код + тесты + коммит
2. **Регрессий нет:** перед коммитом — `pytest tests/ -q` (все тесты проходят)
3. **Последовательность:** промпты внутри фазы выполняются строго по порядку
4. **Обратная совместимость:** все новые фичи опциональны, ничего не ломают
5. **Версия бампится один раз:** после last prompt → bump до v1.1.0
