# PolicyShield × nanobot — Спецификация интеграции

> **Version:** 0.2-refined  
> **Date:** 2026-02-11  
> **Status:** RFC / pre-implementation

---

## 1. Цель документа

Описать, как PolicyShield встраивается в архитектуру nanobot (~3500 LOC, 16k ★), сохраняя его минимализм и обратную совместимость. Общая техническая спецификация PolicyShield — в TECHNICAL_SPEC.md. Этот документ фокусируется исключительно на нanobot-специфичных деталях.

---

## 2. Архитектура nanobot (as-is)

### 2.1 Ключевые компоненты

```
InboundMessage
      │
      ▼
 ┌──────────┐    ┌─────────────┐    ┌───────────────┐
 │ AgentLoop │───▶│ LLMProvider │───▶│ Tool Registry │
 │ (loop.py) │◀──│ (litellm)   │    │  .execute()   │
 └──────────┘    └─────────────┘    └───────┬───────┘
      │                                     │
      ▼                                     ▼
 OutboundMessage                  Tool (base.py)
                                  ├── ExecTool     (shell)
                                  ├── ReadFileTool
                                  ├── WriteFileTool
                                  ├── EditFileTool
                                  ├── ListDirTool
                                  ├── WebSearchTool
                                  ├── WebFetchTool
                                  ├── MessageTool
                                  ├── SpawnTool
                                  └── CronTool
```

### 2.2 Ключевые файлы

| Файл | Компонент | Роль |
|------|-----------|------|
| `agent/loop.py` | `AgentLoop` | Главный цикл: сообщение → контекст → LLM → tool calls → ответ |
| `agent/tools/registry.py` | `ToolRegistry` | Реестр tools. Метод `execute(name, params)` — единая точка вызова |
| `agent/tools/base.py` | `Tool` | Абстрактный класс: `execute()`, `validate_params()`, `to_schema()` |
| `agent/context.py` | `ContextBuilder` | Построение prompt (history + memory + skills) |
| `config/schema.py` | `Config` | Pydantic-конфигурация из `~/.nanobot/config.json` |
| `bus/events.py` | `InboundMessage` / `OutboundMessage` | Структуры сообщений |
| `agent/tools/shell.py` | `ExecTool` | Shell с deny-patterns и `restrict_to_workspace` |

### 2.3 Текущие механизмы безопасности nanobot

| Механизм | Где | Что делает | Ограничения |
|----------|-----|------------|-------------|
| `ExecTool._guard_command()` | `shell.py` | Regex-блокировка опасных команд | Только ExecTool, только regex, нет аудита |
| `restrict_to_workspace` | `loop.py`, filesystem tools, `shell.py` | Ограничение file/shell операций рабочей директорией | Binary: вкл/выкл, нет гранулярности |
| `allowFrom` | Каждый канал | Белый список пользователей | Per-channel, нет per-tool контроля |
| `validate_params()` | `base.py` | JSON Schema валидация аргументов | Проверяет формат, не семантику |

**Что не покрыто:** корпоративные политики, data-flow контроль, PII-детекция, rate limiting, audit trail, human-in-the-loop, repair loop при блокировке.

---

## 3. Архитектура с PolicyShield (to-be)

### 3.1 Принцип: обёртка, а не форк

PolicyShield интегрируется **без изменения исходного кода nanobot**:

```
InboundMessage
      │
      ▼
 ┌──────────┐    ┌─────────────┐    ┌─────────────────────────┐
 │ AgentLoop │───▶│ LLMProvider │───▶│ ShieldedToolRegistry    │
 │ (loop.py) │◀──│ (litellm)   │    │                         │
 └──────────┘    └─────────────┘    │  ┌───────────────────┐  │
      │                             │  │   ShieldEngine     │  │
      ▼                             │  │                   │  │
 OutboundMessage                    │  │   Pre-call check  │  │
                                    │  │   Post-call check │  │
                                    │  │   PII detection   │  │
                                    │  │   Session mgmt    │  │
                                    │  │   Trace recorder  │  │
                                    │  └───────────────────┘  │
                                    │                         │
                                    │  original ToolRegistry  │
                                    │   .execute()            │
                                    └─────────────────────────┘
```

`ShieldedToolRegistry` наследуется от `ToolRegistry`, переопределяя метод `execute()`. Все остальные методы (`register()`, `get_definitions()`, `get()`) работают как в оригинале.

### 3.2 Что не меняется

- Все существующие tools работают без модификаций
- Все каналы (Telegram, Discord, WhatsApp, Slack, CLI) работают
- Конфигурация обратно совместима (shield-секция опциональна)
- CLI (`nanobot agent`, `nanobot gateway`) не меняется
- Формат tool definitions для LLM не меняется

---

## 4. Точки интеграции (детально)

### 4.1 Точка А: `ToolRegistry.execute()` — главная точка

Это **центральная и единственная обязательная** точка интеграции. Каждый tool call проходит через `ToolRegistry.execute(name, params)`, что делает её идеальной для middleware.

**Текущий flow nanobot:**

```
AgentLoop._process_message():
  ...
  for tool_call in response.tool_calls:
      result = await self.tools.execute(tool_call.name, tool_call.arguments)
      messages = self.context.add_tool_result(messages, tool_call.id, tool_call.name, result)
  ...
```

**Flow с ShieldedToolRegistry:**

```
ShieldedToolRegistry.execute(name, params):
  
  1. Session lookup
     → Получить или создать SessionState для текущего session_key
  
  2. Pre-call check
     → PII scan аргументов
     → Rule matching: (tool_name, args, session_context) → matched_rules
     → Выбор вердикта: ALLOW | BLOCK | APPROVE | REDACT
     → Approval cache check (если APPROVE)
  
  3. Обработка вердикта:
     ALLOW:
       → Продолжить к шагу 4
     
     BLOCK:
       → Сформировать counterexample
       → Записать в trace
       → Вернуть counterexample как result (НЕ вызывая оригинальный execute)
       → AgentLoop увидит это как tool result → LLM перепланирует
     
     APPROVE:
       → Отправить approval request через канал nanobot (см. 4.3)
       → Ждать ответа (с таймаутом)
       → Если approved — продолжить к шагу 4
       → Если denied/timeout — как BLOCK
     
     REDACT:
       → Замаскировать PII в args
       → Продолжить к шагу 4

  4. Вызов оригинального execute
     → result = await super().execute(name, params)
  
  5. Post-call check
     → PII scan результата
     → Если PII найден — маскировка (если post_call_scan: true)
  
  6. Trace record
     → Записать событие (tool, verdict, rule, PII, latency)
  
  7. Session update
     → Инкрементировать счётчики
     → Обновить taints
  
  8. Вернуть result
```

**Ключевое свойство:** для `AgentLoop` ничего не меняется. Он по-прежнему вызывает `self.tools.execute(name, params)` и получает строковый результат. Разница только в том, что при BLOCK результат — это counterexample, а не ошибка инструмента.

### 4.2 Точка Б: `AgentLoop._process_message()` — context enrichment

Опциональная точка. Позволяет:

1. **Фильтрация tool definitions.** PolicyShield может убрать из `tools=self.tools.get_definitions()` tools, которые полностью заблокированы текущей политикой. Это предотвращает ситуацию, когда LLM "знает" про tool, но каждый его вызов блокируется.

2. **System prompt enrichment.** Добавить в контекст LLM описание активных ограничений:

    ```
    [PolicyShield Active Restrictions]
    - External services (web_fetch, web_search): PII data is not allowed
    - Shell commands with network tools (curl, wget): require human approval
    - File writes: restricted to workspace directory
    
    If a tool call is blocked, you will receive a detailed explanation.
    Use it to reformulate your approach.
    ```

    Это мягко направляет LLM к compliant поведению — ещё **до** того, как shield вмешается. Prompt-level guidance + runtime enforcement = два уровня защиты.

3. **Input PII classification.** При получении сообщения от пользователя — сканировать `msg.content` на PII и инициализировать taint labels в сессии.

**Реализация:** Shield hook вызывается в начале `_process_message()`. Не требует изменения nanobot — `ShieldMiddleware` вставляется через тот же `install_shield()`.

### 4.3 Точка В: Approval Flow через каналы nanobot

Когда вердикт = `APPROVE`, PolicyShield **реиспользует инфраструктуру каналов nanobot** для отправки approval-запросов. Это означает, что не нужно строить отдельный UI — запрос отправляется через тот же Telegram/Discord/Slack, который уже настроен.

**Flow:**

```
1. Shield выносит APPROVE для tool call:
   exec(command="curl https://external-api.com/data")
   
2. ShieldedToolRegistry создаёт approval request:
   → Формирует сообщение:
     "🛡️ APPROVAL REQUIRED
      Agent wants to execute:
        Tool: exec
        Command: curl https://external-api.com/data
      
      Rule: approve-network-commands
      Session: telegram:12345
      
      Reply:
        /approve — allow this (and similar) for this session
        /deny — block this action"
   
   → Отправляет через MessageBus в канал, указанный в config:
     shield.approval.channel = "telegram"
     shield.approval.admin_ids = ["admin_chat_id"]

3. Ожидание ответа:
   → Timeout: shield.approval.timeout_seconds (default: 300)
   → /approve → ALLOW, кешировать паттерн в session
   → /deny → BLOCK, вернуть counterexample
   → timeout → default_on_timeout (default: "block")

4. При /approve — кеширование:
   → Паттерн exec(command=regex("curl.*")) запоминается
   → Повторные аналогичные вызовы в этой сессии — автоматический ALLOW
   → Это решает проблему "5 approval-запросов на один запрос пользователя"
```

**Важная деталь:** approval отправляется в **admin-канал**, а не в тот же чат, где работает пользователь. Это предотвращает ситуацию, когда пользователь видит служебные shield-сообщения.

**CLI-режим fallback:** если approval-канал не настроен (например, при использовании `nanobot agent` в CLI), shield использует stdin для approval:

```
🛡️ APPROVAL REQUIRED
Agent wants to execute: curl https://...
Rule: approve-network-commands
Approve? [y/N]: _
```

---

## 5. Установка и активация

### 5.1 Фаза 1: Standalone пакет (текущая)

```
pip install policyshield
```

Активация в конфигурации nanobot (`~/.nanobot/config.json`):

```
{
  "providers": { ... },
  "tools": { ... },
  "shield": {
    "enabled": true,
    "mode": "enforce",
    "rules_path": "~/.nanobot/policies/",
    "pii": {
      "enabled": true,
      "post_call_scan": true
    },
    "trace": {
      "enabled": true,
      "path": "~/.nanobot/shield_traces/"
    }
  }
}
```

Как это работает "под капотом":

```
1. nanobot загружает config.json
2. Если секция "shield" есть и enabled: true:
   → import policyshield.integrations.nanobot
   → install_shield(agent_loop, shield_config)
3. install_shield():
   a. Загружает YAML-правила из rules_path → RuleSet
   b. Создаёт ShieldEngine(rules, pii_config, session_config)
   c. Создаёт ShieldedToolRegistry, передаёт ему ShieldEngine 
      и оригинальный ToolRegistry из AgentLoop
   d. Подменяет agent_loop.tools на ShieldedToolRegistry
   e. Если approval.enabled — настраивает ApprovalManager
   f. Если context enrichment включён — регистрирует pre-process hook
```

**Требования к nanobot:** единственное, что нужно от nanobot — чтобы `install_shield` мог подменить `agent_loop.tools`. Это работает, потому что `tools` — публичный атрибут `AgentLoop`, а `ShieldedToolRegistry` полностью совместим по апи (наследование от `ToolRegistry`).

### 5.2 Фаза 2: PR в nanobot (middleware hooks)

Предложение маленького PR в nanobot — добавление middleware API в `ToolRegistry`:

```
Что добавляется:
1. Поле _middleware: list в ToolRegistry
2. Метод add_middleware(fn): добавить middleware
3. Метод remove_middleware(fn): удалить middleware
4. Изменение execute(): прогон через middleware chain
```

**Аргумент для maintainer-ов:**

Middleware API полезен **не только** для PolicyShield. Любой плагин может использовать его:
- Логирование tool calls (уже запрашивается в issues)
- Rate limiting
- Метрики / мониторинг
- A/B тестирование tools
- Caching результатов

Это ~20-30 строк кода, zero breaking changes, полностью опциональный (если нет middleware — поведение идентично).

**После мержа** PolicyShield переключается:

```
# Фаза 1 (subclass):
agent.tools = ShieldedToolRegistry(original_registry, engine)

# Фаза 2 (middleware):
agent.tools.add_middleware(shield_engine.middleware)
```

Subclass сохраняется как fallback для старых версий nanobot (до middleware PR).

---

## 6. ShieldedToolRegistry — детали реализации (архитектурные)

### 6.1 Наследование vs Обёртка

**Выбран subclass (наследование)**, а не wrapper, по следующим причинам:

| Подход | Плюсы | Минусы |
|--------|-------|--------|
| Subclass (`ShieldedToolRegistry(ToolRegistry)`) | Полная совместимость с типами. `isinstance(x, ToolRegistry)` = True. Доступ к внутренним методам | При изменении ToolRegistry может потребоваться обновление |
| Wrapper (composition) | Изоляция от изменений ToolRegistry | `isinstance` ломается. Нужно проксировать все методы |
| Monkey-patch | Проще всего | Хрупкий, трудно отлаживать, "magic" |

### 6.2 Переопределяемые методы

```
ShieldedToolRegistry(ToolRegistry):

  Конструктор:
    __init__(original_registry, shield_engine, config):
      → Копирует зарегистрированные tools из original_registry
      → Сохраняет ссылку на ShieldEngine

  Переопределённые методы:
    execute(name, params) → str:
      → Основная логика: pre-check → verdict → original execute → post-check → trace
      (описано в разделе 4.1)

    get_definitions() → list[dict]:
      → Опционально: фильтрация tool schemas по политикам
      → Убирает tools, которые на 100% заблокированы текущей политикой
      → Если фильтрация выключена — делегирует в super()

  Новые методы:
    get_shield_status() → dict:
      → Возвращает текущий статус shield: mode, число правил,
        активные сессии, статистика вердиктов

    reload_rules() → None:
      → Перезагрузка YAML-правил без перезапуска агента
```

### 6.3 Session key propagation

Проблема: `ToolRegistry.execute(name, params)` не принимает `session_id`. Но PolicyShield нужен session context для rate limiting и taint tracking.

Решение: **context variable** (Python `contextvars`).

```
Контекст session_id устанавливается в AgentLoop._process_message()
через ShieldMiddleware:
  → shield_session_var.set(msg.session_key)

ShieldedToolRegistry.execute() читает:
  → session_id = shield_session_var.get()

Это не требует изменения сигнатуры execute() и совместимо с asyncio.
```

---

## 7. Взаимодействие с существующей безопасностью nanobot

PolicyShield **не заменяет**, а **дополняет** текущие механизмы. Порядок проверок:

```
Tool call: exec(command="rm -rf /tmp/data")
      │
      ▼
┌─ 1. validate_params() ──────────────────────┐
│ JSON Schema: обязательные поля, типы         │
│ Result: OK (формат валиден)                  │
└──────────────────────────────────────────────┘
      │
      ▼
┌─ 2. PolicyShield pre-call ──────────────────┐
│ PII scan: нет PII                            │
│ Rule matching: no-destructive-shell → MATCH  │
│ Verdict: BLOCK                               │
│ → Counterexample возвращается агенту         │
│ → Tool call НЕ исполняется                   │
│ → _guard_command() НЕ вызывается            │
└──────────────────────────────────────────────┘

Tool call: exec(command="git status")
      │
      ▼
┌─ 1. validate_params() ─ OK ─────────────────┐
┌─ 2. PolicyShield pre-call ──────────────────┐
│ No rules matched → Verdict: ALLOW            │
└──────────────────────────────────────────────┘
      │
      ▼
┌─ 3. ExecTool._guard_command() ──────────────┐
│ deny_patterns check: OK                      │
│ restrict_to_workspace: OK                    │
└──────────────────────────────────────────────┘
      │
      ▼
┌─ 4. ExecTool.execute() ────────────────────┐
│ Исполнение команды                          │
└──────────────────────────────────────────────┘
      │
      ▼
┌─ 5. PolicyShield post-call ─────────────────┐
│ PII scan результата: нет PII                 │
│ Verdict: ALLOW                               │
│ Trace record                                 │
└──────────────────────────────────────────────┘
```

**Почему shield проверяет до `_guard_command()`:**

Shield блокирует **до** исполнения tool, а `_guard_command()` — внутри `ExecTool.execute()`. Поскольку при BLOCK shield **не вызывает** оригинальный `execute()`, до `_guard_command()` дело не доходит. Это правильно: если PolicyShield уже заблокировал — незачем проверять regex-ами.

Если PolicyShield решил ALLOW — `_guard_command()` срабатывает как обычно. Два уровня защиты работают каскадно.

### 7.1 Матрица ответственности

| Что проверяет | PolicyShield | nanobot native |
|---------------|-------------|----------------|
| Формат аргументов (JSON Schema) | ✗ | `validate_params()` |
| Семантика tool call (политики) | ✓ | ✗ |
| Regex deny-list для shell | ✗ (не дублирует) | `_guard_command()` |
| PII в аргументах | ✓ | ✗ |
| PII в результатах | ✓ | ✗ |
| Rate limiting | ✓ | ✗ |
| Workspace restriction | Может расширить | `restrict_to_workspace` |
| User access control | Per-tool, per-rule RBAC | Per-channel `allowFrom` |
| Audit trail | ✓ (JSONL trace) | ✗ |
| Repair loop (counterexample) | ✓ | ✗ |
| Human-in-the-loop (approval) | ✓ | ✗ |

---

## 8. SpawnTool и субагенты

### 8.1 Проблема

`SpawnTool` в nanobot создаёт **дочерний AgentLoop** с собственным `ToolRegistry`. Если основной агент защищён shield, но субагент — нет, это создаёт обход.

### 8.2 Решение: shield propagation

При вызове `SpawnTool`:

```
1. ShieldedToolRegistry обнаруживает tool call "spawn"
2. Verdict: ALLOW (или APPROVE, если настроено правило)
3. SpawnTool создаёт дочерний AgentLoop
4. Shield hook перехватывает создание субагента
5. install_shield() применяется к дочернему AgentLoop:
   → Те же правила
   → Тот же ShieldEngine
   → Новый SessionState (дочерняя сессия)
   → Taints наследуются от родительской сессии
```

**Наследование taints:** субагент получает копию taint labels родительской сессии на момент spawn. Это консервативно — если родитель получил PII, субагент тоже считается "загрязнённым".

### 8.3 Альтернатива: policy delegation

В правилах можно указать, что субагенты работают под другой политикой:

```
- id: spawn-restricted
  description: "Субагенты ограничены read-only tools"
  when:
    tool: spawn
  then: allow
  spawn_policy:
    rules_path: "~/.nanobot/policies/subagent/"
```

Это позволяет создать более жёсткие правила для субагентов (например, только `read_file` и `list_dir`, без `exec` или `web_fetch`).

---

## 9. End-to-end сценарий

```
Пользователь (Telegram): "Переведи мой тикет на англ.,
                           вот email: john@corp.com
                           и номер карты 4111 1111 1111 1111"
      │
      ▼
┌─ ShieldMiddleware (input processing) ────────────────────────┐
│ PII Detection на msg.content:                                │
│   → Обнаружен email: john@corp.com → PII_DIRECT             │
│   → Обнаружена карта: 4111... → PII_FINANCIAL               │
│ Session taint init: {PII_DIRECT, PII_FINANCIAL}              │
│                                                              │
│ Context enrichment:                                          │
│   → Добавить в system prompt:                                │
│     "[PolicyShield] PII detected in user message.            │
│      Do not send PII to external services."                  │
└──────────────────────────────────────────────────────────────┘
      │
      ▼
┌─ LLM Response ───────────────────────────────────────────────┐
│ LLM решает вызвать:                                          │
│   web_fetch(url="https://translate.api/...",                 │
│             text="email john@corp.com card 4111...")          │
└──────────────────────────────────────────────────────────────┘
      │
      ▼
┌─ ShieldedToolRegistry.execute("web_fetch", {...}) ───────────┐
│                                                              │
│ PRE-CALL CHECK:                                              │
│   PII scan: PII_DIRECT (email) в поле "text"                │
│   Rule match: no-pii-external → MATCH                        │
│   Verdict: BLOCK                                             │
│                                                              │
│ COUNTEREXAMPLE (возвращается как tool result):               │
│   🛡️ BLOCKED by PolicyShield                                │
│   Rule: no-pii-external                                      │
│   Tool: web_fetch                                            │
│   Detected: email, credit card in field "text"               │
│   Suggestion: Redact PII before making external requests.    │
│               Use [EMAIL] and [CC] placeholders.              │
│                                                              │
│ TRACE: {verdict: BLOCK, rule: no-pii-external, pii: [...]}   │
└──────────────────────────────────────────────────────────────┘
      │
      ▼
┌─ Repair Loop (LLM перепланирует) ───────────────────────────┐
│ LLM видит counterexample как tool result                     │
│ LLM понимает: нужно убрать PII                               │
│ LLM вызывает:                                                │
│   web_fetch(url="https://translate.api/...",                 │
│             text="Translate the user ticket to English.       │
│                   Contact: [EMAIL], Payment: [CC]")          │
└──────────────────────────────────────────────────────────────┘
      │
      ▼
┌─ ShieldedToolRegistry.execute("web_fetch", {...}) ───────────┐
│ PRE-CALL: PII scan → no PII detected → ALLOW                │
│ Execute: web_fetch → получает перевод                        │
│ POST-CALL: PII scan result → OK                              │
│ TRACE: {verdict: ALLOW, ...}                                 │
└──────────────────────────────────────────────────────────────┘
      │
      ▼
┌─ OutboundMessage ────────────────────────────────────────────┐
│ Ответ пользователю: перевод тикета (без PII в запросе)       │
│                                                              │
│ Session trace (3 записи):                                    │
│   1. BLOCK  web_fetch  no-pii-external  PII: email, CC      │
│   2. ALLOW  web_fetch  -                                     │
│   3. Session end                                             │
└──────────────────────────────────────────────────────────────┘
```

---

## 10. Нagрузочные соображения

### 10.1 Overhead

В типичном nanobot запросе:
- 1 LLM call: 500-5000 мс
- 1-5 tool calls: 50-2000 мс каждый

PolicyShield добавляет:
- Pre-call check: < 3 мс (PII regex + rule matching + session lookup)
- Post-call check: < 1 мс (PII regex on result)
- Trace write: < 0.5 мс (async file append)

**Итого overhead: < 5 мс на tool call** — менее 0.5% от типичного запроса.

### 10.2 Memory

- RuleSet: ~1 KB на правило (скомпилированные regex + предикаты). 100 правил ≈ 100 KB
- Session: ~2 KB на сессию. 100 активных сессий ≈ 200 KB
- Trace buffer: ~100 bytes на запись, flush каждые N записей

**Итого: < 1 MB** для типичного deployment. Несущественно на фоне LLM context.

---

## 11. Ограничения и известные проблемы

| # | Ограничение | Почему | Mitigation |
|---|-------------|--------|-----------|
| 1 | Taint через LLM теряется | LLM перефразирует PII, regex не найдёт | Session-level taints (консервативно), whitelist taint-safe tools |
| 2 | PII только L0 (regex) | L1/L2 добавляют latency и dependencies | L0 ловит 80%+ случаев, L1 как опциональный плагин |
| 3 | Subclass может сломаться при обновлении nanobot | Нет stable API contract | Middleware PR (фаза 2) устраняет |
| 4 | Approval в CLI режиме — blocking stdin | Нет async input в CLI | Workaround: таймаут + default action |
| 5 | Нет Web UI для trace | Только CLI | CLI достаточен для 0→1, dashboard — v2.0 |

---

## 12. Checklist для реализации v0.1

| # | Что | Приоритет |
|---|-----|-----------|
| 1 | `ShieldedToolRegistry` с pre-call check | P0 |
| 2 | YAML DSL parser + RuleSet loader | P0 |
| 3 | Matcher engine (tool + args_match) | P0 |
| 4 | Verdict + Counterexample builder | P0 |
| 5 | PIIDetector (L0 regex: email, phone, CC) | P0 |
| 6 | TraceRecorder (JSONL) | P0 |
| 7 | `install_shield()` для nanobot | P0 |
| 8 | SessionManager (счётчики, taints) | P1 |
| 9 | Post-call PII scan | P1 |
| 10 | Context enrichment (system prompt injection) | P1 |
| 11 | CLI: `policyshield validate` | P1 |
| 12 | CLI: `policyshield trace show` | P1 |
| 13 | Approval flow через nanobot channels | P2 |
| 14 | Batch approve (session cache) | P2 |
| 15 | Tool definition filtering (get_definitions override) | P2 |
| 16 | SpawnTool shield propagation | P2 |
