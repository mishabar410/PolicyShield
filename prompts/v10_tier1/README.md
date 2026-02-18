# PolicyShield v1.0 — Prompt Chain: Tier 1 Features

Цепочка из 10 атомарных промптов: Replay & Simulation → Chain Rules → AI-Assisted Rule Writing.

## Контекст

Три фичи, которые делают PolicyShield уникальным:

1. **Replay** — перепрогнать исторические трейсы через новые правила до деплоя
2. **Chain Rules** — временные зависимости между вызовами (anti-exfiltration)
3. **AI Rule Writer** — генерация YAML-правил по текстовому описанию

## Фазы

### Фаза 1: Replay & Simulation (промпты 101–103)

| # | Промпт | Основная задача |
|---|--------|-----------------| 
| 101 | Trace Loader | Загрузчик JSONL-трейсов для replay: парсинг, фильтрация, итерация |
| 102 | Replay Engine | Прогон трейсов через матчер, сравнение old vs new verdict, diff |
| 103 | CLI `replay` | CLI-команда `policyshield replay` + форматирование결 результатов |

### Фаза 2: Chain Rules (промпты 104–107)

| # | Промпт | Основная задача |
|---|--------|-----------------|
| 104 | Event Ring Buffer | Кольцевой буфер событий в SessionState для temporal matching |
| 105 | Chain Rule Parser | Парсинг `when.chain` из YAML, валидация, модель `ChainCondition` |
| 106 | Chain Matcher | Матчинг chain rules: проверка временных зависимостей в буфере |
| 107 | Chain Integration | Интеграция chain matching в engine pipeline + CLI lint check |

### Фаза 3: AI-Assisted Rule Writing (промпты 108–110)

| # | Промпт | Основная задача |
|---|--------|-----------------|
| 108 | Rule Templates | Шаблоны правил + классификатор имён тулов (safe/dangerous/critical) |
| 109 | LLM Rule Generator | Генерация YAML через LLM API (OpenAI/Anthropic) с few-shot |
| 110 | CLI `generate` | CLI-команда `policyshield generate` + валидация + запись файла |

## Зависимости между промптами

```
101 (Trace Loader)       ← ни от кого
102 (Replay Engine)      ← после 101
103 (CLI replay)         ← после 102

104 (Event Ring Buffer)  ← ни от кого (параллельно с 101–103)
105 (Chain Rule Parser)  ← после 104
106 (Chain Matcher)      ← после 105
107 (Chain Integration)  ← после 106

108 (Rule Templates)     ← ни от кого (параллельно с 104–107)
109 (LLM Rule Generator) ← после 108
110 (CLI generate)       ← после 109
```

> Фазы 1, 2 и 3 **независимы** друг от друга и могут выполняться параллельно.

## Правила

1. **Атомарность:** каждый промпт = код + тесты + коммит
2. **Регрессий нет:** перед коммитом — `pytest tests/ -q` (все тесты проходят)
3. **Последовательность:** промпты внутри фазы выполняются строго по порядку
4. **Обратная совместимость:** все новые фичи опциональны, ничего не ломают
5. **Версия бампится один раз:** после last prompt → bump до v1.0.0
