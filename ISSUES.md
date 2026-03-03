# 🔍 PolicyShield — Системный анализ

Анализ ~8000+ строк кода по всем ключевым подсистемам.  
Всего: **160 issues** по 4 категориям критичности.

---

## Файлы по категориям

| Категория | Файл | Количество |
|-----------|------|------------|
| 🔴 Critical | [issues/critical.md](issues/critical.md) | 35 |
| 🟠 High | [issues/high.md](issues/high.md) | 47 |
| 🟡 Medium | [issues/medium.md](issues/medium.md) | 50 |
| 🔵 Low | [issues/low.md](issues/low.md) | 28 |

---

## 📊 Сводная таблица

| # | Тип | Компонент | Проблема | Severity |
|---|-----|-----------|----------|----------|
| 1 | Feature gap | Engine | LLM Guard только в async | 🔴 Critical |
| 2 | Architecture | SDK/Client | 3 несовместимых клиента + мёртвые endpoints | 🔴 Critical |
| 3 | Duplication | Engine | Sync/async дупликация с расхождениями | 🔴 Critical |
| 14 | Feature gap | SDK Client | `context` не передаётся в payload | 🔴 Critical |
| 15 | Logic bug | Parser | Shallow merge в `_resolve_extends` ломает `when` | 🔴 Critical |
| 16 | Architecture | Approval | Webhook `submit()` блокирует до 300s | 🔴 Critical |
| 27 | Logic bug | Engine | Shadow eval не передаёт `context` | 🔴 Critical |
| 28 | Feature gap | Decorator | `@shield` не передаёт `sender`/`context` | 🔴 Critical |
| 29 | Data loss | Server | `compile-and-apply` удаляет все правила для tool | 🔴 Critical |
| 40 | Security | SDK | Async SDK `/kill-switch` → несуществующий endpoint | 🔴 Critical |
| 41 | Feature gap | SDK | AsyncClient отсутствуют `post_check`, `reload`, `wait_for_approval` | 🔴 Critical |
| 42 | Runtime error | Decorator | `guard()` создаёт sync engine для async функций → crash | 🔴 Critical |
| 43 | Performance | Approval | Webhook — новый `httpx.Client` на каждый poll tick | 🔴 Critical |
| 44 | Data race | Engine | LLM Guard cache мутирует shared объект | 🔴 Critical |
| 62 | Security | Telegram Bot | Нулевая аутентификация — любой может `/kill` | 🔴 Critical |
| 63 | Security | Server | Payload size bypass через подмену Content-Length | 🔴 Critical |
| 75 | Architecture | MCP Proxy | Fake forwarding — proxy возвращает "forwarded" без вызова upstream | 🔴 Critical |
| 76 | Concurrency | MCP Server | `kill`/`reload` через `to_thread` вместо native async — deadlock risk | 🔴 Critical |
| 77 | Logic bug | Server | `compile-and-apply` idempotency key не проверяет description | 🔴 Critical |
| 78 | Architecture | Session | SessionManager + SessionBackend — два хранилища с рассинхронизацией | 🔴 Critical |
| 79 | Logic bug | Matcher | `eq`/`contains` используют `pattern.pattern` — некорректное сравнение | 🔴 Critical |
| 4 | Concurrency | Session | threading.Lock в async context | 🟠 High |
| 5 | Hot-reload | Engine | taint_chain не обновляется при reload | 🟠 High |
| 6 | Data race | Server | compile-and-apply без file lock | 🟠 High |
| 17 | Security | Server | Payload size bypass через spoofed Content-Length | 🟠 High |
| 18 | Security | Engine | Sanitizer перед detectors скрывает контент | 🟠 High |
| 19 | Architecture | Integration | LangChain wrapper не поддерживает async engine | 🟠 High |
| 20 | Memory leak | Approval | Webhook backend без cleanup | 🟠 High |
| 21 | Feature gap | SDK Client | AsyncClient — неполный API | 🟠 High |
| 30 | Dead API | Plugins | `pre_check_hook`/`post_check_hook` не вызываются | 🟠 High |
| 31 | Performance | Approval | Webhook — новый httpx.Client на каждый запрос | 🟠 High |
| 32 | Data race | Session/Engine | SessionState мутируется вне lock | 🟠 High |
| 33 | Reliability | Engine | Sync engine не имеет timeout | 🟠 High |
| 34 | Security | Sanitizer | Size check формула не считает полный размер | 🟠 High |
| 45 | Feature gap | Decorator | `@shield` не поддерживает approval workflow | 🟠 High |
| 46 | Architecture | Integration | LangChain wrapper hard-code sync engine | 🟠 High |
| 47 | Security | Integration | CrewAI wrapper пропускает `APPROVE` verdict | 🟠 High |
| 48 | Dead code | Session | `SessionBackend` подключён но не используется | 🟠 High |
| 49 | Security | Context | Fail-open на malformed spec → правило всегда match | 🟠 High |
| 50 | Logic bug | Config | `build_engine_from_config` игнорирует `watch` и `approval_backend` | 🟠 High |
| 64 | Logic bug | CrewAI | Игнорирует APPROVE вердикт — обход approval | 🟠 High |
| 65 | Logic bug | LangChain | Игнорирует APPROVE вердикт — обход approval | 🟠 High |
| 66 | Thread safety | LLM Guard | Cache dict без lock — race condition | 🟠 High |
| 80 | Architecture | MCP Proxy | `list_tools` генерирует из правил, а не из upstream | 🟠 High |
| 81 | Logic bug | Integration | CrewAI wrapper `_run` теряет positional args | 🟠 High |
| 82 | Runtime error | Integration | LangChain `_arun` падает с `AsyncShieldEngine` → `AttributeError` | 🟠 High |
| 83 | Logic bug | Config | `build_async_engine_from_config` игнорирует `watch`/`approval` | 🟠 High |
| 84 | Performance | Approval | Webhook poll-mode — 300s блокировка + new client на каждый tick | 🟠 High |
| 85 | Security | AI Compiler | Prompt injection через user description без санитизации | 🟠 High |
| 86 | Reliability | Trace | `_atexit_flush` может упасть при shutdown Python | 🟠 High |
| 87 | Data corruption | PII | `redact_dict` не merge'ит overlapping spans → порча данных | 🟠 High |
| 7 | Parser | Config | `context` нет в valid when keys | 🟡 Medium |
| 8 | Feature | MCP Proxy | Stub вместо реального proxy | 🟡 Medium |
| 9 | DX | Config | Priority — обратная семантика | 🟡 Medium |
| 22 | DX | Parser | `extends` наследует `enabled: false` без предупреждения | 🟡 Medium |
| 23 | Runtime error | Approval | `InMemoryBackend.health()` отсутствует → /readyz крашится | 🟡 Medium |
| 24 | Performance | Matcher | ChainCondition не pre-компилируется | 🟡 Medium |
| 25 | Reliability | Watcher | TOCTOU + aggressive failure counting | 🟡 Medium |
| 35 | Feature gap | Parser | Cross-file `extends` не работает в directory mode | 🟡 Medium |
| 36 | DX | Parser | `priority` непредсказуем при extends + compile-and-apply | 🟡 Medium |
| 37 | Performance | Approval | Webhook health() — новый TCP на каждый health check | 🟡 Medium |
| 38 | Logic bug | Server | `_rules_hash` не включает when/priority/enabled | 🟡 Medium |
| 39 | Logic bug | Engine | Rate limiter считает заблокированные вызовы | 🟡 Medium |
| 51 | Dead code | Plugins | `pre_check_hook`/`post_check_hook` — dead code | 🟡 Medium |
| 52 | Logic bug | PII | Overlapping patterns → двойные matches и redact corruption | 🟡 Medium |
| 53 | Security | Sanitizer | `_flatten_to_string` size guard проверяет только последние 10 частей | 🟡 Medium |
| 54 | Reliability | Watcher | Circuit breaker сбрасывается при любом успешном poll | 🟡 Medium |
| 55 | Reliability | Approval | Webhook poll loop без circuit breaker | 🟡 Medium |
| 56 | Data race | Approval | `Telegram.stop()` закрывает httpx.Client пока thread его использует | 🟡 Medium |
| 57 | Logic bug | Config | Env-var expansion однопроходный | 🟡 Medium |
| 67 | Config | Docker | Разные версии Python (3.12 vs 3.13) | 🟡 Medium |
| 68 | Logic bug | Approval Cache | Коллизия ключей при `:` в session_id | 🟡 Medium |
| 69 | Performance | Sanitizer | Квадратичная проверка размера в `_flatten` | 🟡 Medium |
| 70 | Performance | PII Detector | Unbounded matches в `scan_dict` | 🟡 Medium |
| 88 | Logic bug | MCP Server | `constraints` вызывает sync метод без `to_thread` | 🟡 Medium |
| 89 | Logic bug | Config | Env-var expansion не поддерживает nested `${}` | 🟡 Medium |
| 90 | API design | Rate Limiter | `check()` + `record()` TOCTOU при наличии `check_and_record()` | 🟡 Medium |
| 91 | Logic bug | Session | Eviction по `total_calls` вместо LRU — неверное название метода | 🟡 Medium |
| 92 | False positive | Detectors | Shell injection regex ложно срабатывает на backtick-текст | 🟡 Medium |
| 93 | Logic bug | Sanitizer | `_flatten_to_string` пропускает числовые dict-ключи | 🟡 Medium |
| 94 | Locale bug | Context | `strftime("%a")` зависит от locale → `day_of_week` ломается | 🟡 Medium |
| 95 | Performance | Ring Buffer | `find_recent()` O(n) scan без early-exit | 🟡 Medium |
| 10 | Dead code | Session | SessionBackend не используется | 🔵 Low |
| 11 | Security | Sanitizer | Size check обходится | 🔵 Low |
| 12 | Logic | Engine | str(result) vs JSON для output rules | 🔵 Low |
| 13 | Code quality | Server | Logger scope | 🔵 Low |
| 26 | Architecture | Matcher | `re.compile` для non-regex предикатов | 🔵 Low |
| 58 | DX | Decorator | `_rebuild_args` не работает с variadic сигнатурами | 🔵 Low |
| 59 | Logic bug | Approval | Slack `health()` всегда True без проверки | 🔵 Low |
| 60 | DX | SDK | `CheckResult.verdict` — `str` вместо `Verdict` enum | 🔵 Low |
| 61 | Performance | Engine | LLM Guard cache FIFO eviction без TTL-check | 🔵 Low |
| 71 | DX | CLI Doctor | Парсит rules файл дважды | 🔵 Low |
| 72 | DX | Auto-Rules | `default_verdict` параметр не используется | 🔵 Low |
| 73 | Reliability | Trace Recorder | Тихая потеря аудит-записей при сбоях диска | 🔵 Low |
| 74 | Architecture | LangChain | `_arun` — sync-через-thread вместо native async | 🔵 Low |
| 96 | Security | Approval | `ApprovalRequest` не маскирует PII/секреты в args | 🔵 Low |
| 97 | Reliability | Config | `load_schema()` без graceful fallback при отсутствии файла | 🔵 Low |
| 98 | Reliability | Trace | `cleanup_old_traces()` никогда не вызывается автоматически | 🔵 Low |
| 99 | Performance | Session Backend | Redis `count()` выполняет full SCAN — O(N) | 🔵 Low |
| 100 | Security | Telegram Bot | Markdown injection через YAML preview | 🔴 Critical |
| 101 | Data loss | Telegram Bot | `_deploy` перезаписывает все правила | 🔴 Critical |
| 102 | Data race | Session | Мутация `total_calls/tool_counts` вне lock | 🔴 Critical |
| 103 | Security | Sanitizer | OOM DoS через 100K+ мелких ключей | 🔴 Critical |
| 104 | Security | Engine | Rate limiter TOCTOU: `check()`+`record()` вместо `check_and_record()` | 🔴 Critical |
| 105 | Performance | Approval | Webhook poll-mode: 300s blocking + httpx.Client leak | 🟠 High |
| 106 | Logic bug | Config | `build_engine_from_config` игнорирует `watch_interval` | 🟠 High |
| 107 | Security | Matcher | ReDoS через regex tool patterns | 🟠 High |
| 108 | Data corruption | PII | `redact_dict` mask длина меняется → corrupt nested | 🟠 High |
| 109 | Data race | Engine | `_swap_rules` stale `_pii_detector` во время `to_thread` | 🟠 High |
| 110 | Reliability | Approval | InMemoryBackend timeout без внешнего polling | 🟠 High |
| 111 | Logic bug | Decorator | APPROVE и BLOCK обрабатываются идентично | 🟠 High |
| 112 | Security | PII | `_scan_list` CPU DoS через unbounded ширину | 🟠 High |
| 113 | Logic bug | Integration | CrewAI `post_check` результат игнорируется | 🟡 Medium |
| 114 | Feature gap | Integration | LangChain `post_check` отсутствует | 🟡 Medium |
| 115 | Logic bug | Honeypot | Case-insensitivity несоответствие с matcher | 🟡 Medium |
| 116 | DX | Config | 6 из 8 секций не валидируются | 🟡 Medium |
| 117 | Logic bug | Watcher | Удаление YAML-файлов не обрабатывается | 🟡 Medium |
| 118 | Performance | Ring Buffer | `find_recent()` O(n) без backward traversal | 🟡 Medium |
| 119 | DX | Client | Sync/Async несовместимые retry параметры | 🟡 Medium |
| 120 | Resource leak | Telegram Bot | `run_bot()` не вызывает `bot.stop()` при KeyboardInterrupt | 🔵 Low |
| 121 | API gap | Approval | ABC `get_status()` отсутствует → `AttributeError` | 🔵 Low |
| 122 | Data loss | Config | `render_config()` пропускает `rate_limits` | 🔵 Low |
| 123 | DX | Integration | CrewAI `run()` alias конфликт с `BaseTool.run()` | 🔵 Low |
| 124 | Logic bug | Decorator | `_bind_args` fallback теряет positional args | 🔵 Low |
| 125 | Lifecycle | Decorator | `_default_engine` singleton без cleanup/reset | 🔴 Critical |
| 126 | Security | MCP Proxy | `check_and_forward` — APPROVE bypass (как ALLOW) | 🔴 Critical |
| 127 | Data loss | Telegram Bot | `_pending` dict — кросс-chat state collision | 🔴 Critical |
| 128 | Security | Server | `verify_token` — timing side-channel attack | 🔴 Critical |
| 129 | Dead code | Rate Limiter | `GlobalRateLimiter`/`AdaptiveRateLimiter` нигде не используются | 🟠 High |
| 130 | Data race | Approval | `InMemoryBackend.stop()` — responses очищены до signal events | 🟠 High |
| 131 | Performance | LLM Guard | `_call_llm` — новый `httpx.AsyncClient` на каждый вызов | 🟠 High |
| 132 | Security | MCP Server | `kill`/`resume`/`reload` без авторизации | 🟠 High |
| 133 | Reliability | Trace | `record()` не проверяет `_closed` flag — потеря записей | 🟠 High |
| 134 | Feature gap | Config | Env-var override только для `mode`/`fail_open` | 🟡 Medium |
| 135 | DX | Client | Async/Sync несовместимые имена retry параметров | 🟡 Medium |
| 136 | Dead code | MCP Proxy | `subprocess` import + `_upstream_proc` unused | 🟡 Medium |
| 137 | Data loss | Config | `render_config()` пропускает `watch_interval` | 🟡 Medium |
| 138 | Security | LLM Guard | `api_key` — plain string в памяти | 🟡 Medium |
| 139 | Logic bug | Trace | `compute_args_hash` — нестабильный хэш из-за `default=str` | 🟡 Medium |
| 140 | Performance | Approval | `InMemoryBackend._start_gc()` — daemon Timer churn | 🔵 Low |
| 141 | Resource | Telegram Bot | Shared `httpx.AsyncClient` для 2 API с разными timeout | 🔵 Low |
| 142 | DX | MCP Proxy | `upstream_command` always empty list | 🔵 Low |
| 143 | Code quality | Rate Limiter | `count_in_window` — side effect в read-only метод | 🔵 Low |
| 144 | Concurrency | Approval | Webhook `submit()` exhausts `to_thread` pool при concurrent approvals | 🔴 Critical |
| 145 | Security | PII | `_scan_list` + `scan_dict` — memory DoS через unbounded matches | 🔴 Critical |
| 146 | Data race | Engine/Watcher | `_reload` callback races с `check()` — stale MatcherEngine | 🔴 Critical |
| 147 | Logic bug | Decorator | `guard()` hardcodes `session_id="default"` — ломает per-session rate limiting | 🟠 High |
| 148 | Data race | Telegram Bot | `_deploy` write_text races с RuleWatcher — частично записанный файл | 🟠 High |
| 149 | Logic bug | Context | `_check_time` — лексикографическое сравнение time strings без валидации формата | 🟡 Medium |
| 150 | Reliability | Rate Limiter | `from_yaml_dict` — no validation, `KeyError` на malformed YAML | 🟡 Medium |
| 151 | Reliability | Trace | `_generate_file_path` — infinite loop при permission denied | 🟡 Medium |
| 152 | Data race | Approval | `InMemoryBackend.get_status()` timeout race с `respond()` | 🟡 Medium |
| 153 | Memory leak | Telegram Bot | `_pending` dict без TTL — unbounded memory growth | 🔵 Low |
| 154 | Data integrity | Server | `compile-and-apply` — non-atomic YAML write, watcher видит partial file | 🔴 Critical |
| 155 | Memory leak | Budget | `BudgetTracker._session_spend` — unbounded dict, нет eviction | 🔴 Critical |
| 156 | Data race | Remote Loader | `RemoteRuleLoader` callback races с `check()` — аналог #146 | 🟠 High |
| 157 | Security | Reporting | `render_html` — XSS через tool_name/rule_id без escaping | 🟠 High |
| 158 | Security | Approval | `sanitize_args` — shallow, secrets в nested args утекают | 🟡 Medium |
| 159 | Concurrency | Alerts | `WebhookBackend`/`SlackBackend`/`TelegramBackend` — blocking urllib в async | 🟡 Medium |
| 160 | Thread safety | LLM Guard | `_cache` dict без lock — concurrent mutation из to_thread | 🔵 Low |
