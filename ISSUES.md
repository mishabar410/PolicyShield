# 🔍 PolicyShield — Системный анализ

Анализ ~8500+ строк кода по всем ключевым подсистемам.  
Всего: **38** issues (из 160 оригинальных, 142 исправлены + 66 новых, 8 critical + 17 high + 29 medium fixes).

---

## Файлы по категориям

| Категория | Файл | Количество |
|-----------|------|------------|
| 🔴 Critical | [issues/critical.md](issues/critical.md) | 0 ✅ |
| 🟠 High | [issues/high.md](issues/high.md) | 0 ✅ |
| 🟡 Medium | [issues/medium.md](issues/medium.md) | 0 ✅ |
| 🔵 Low | [issues/low.md](issues/low.md) | 38 |

---

## 📊 Сводная таблица

| # | Тип | Компонент | Проблема | Severity |
|---|-----|-----------|----------|----------|
| 12 | Logic | Engine | str(result) vs JSON для output rules | 🔵 Low |
| 13 | Code quality | Server | Logger scope | 🔵 Low |
| 26 | Architecture | Matcher | `re.compile` для non-regex предикатов | 🔵 Low |
| 58 | DX | Decorator | `_rebuild_args` не работает с variadic сигнатурами | 🔵 Low |
| 59 | Logic bug | Approval | Slack `health()` всегда True без проверки | 🔵 Low |
| 60 | DX | SDK | `CheckResult.verdict` — `str` вместо `Verdict` enum | 🔵 Low |
| 61 | Performance | Engine | LLM Guard cache FIFO eviction без TTL-check | 🔵 Low |
| ~~67~~ | ~~Config~~ | ~~Docker~~ | ~~Разные версии Python (3.12 vs 3.13)~~ | ✅ Fixed |
| 71 | DX | CLI Doctor | Парсит rules файл дважды | 🔵 Low |
| 72 | DX | Auto-Rules | `default_verdict` параметр не используется | 🔵 Low |
| 73 | Reliability | Trace Recorder | Тихая потеря аудит-записей при сбоях диска | 🔵 Low |
| ~~92~~ | ~~False positive~~ | ~~Detectors~~ | ~~Shell injection regex ложно срабатывает на backtick-текст~~ | ✅ Fixed |
| 97 | Reliability | Config | `load_schema()` без graceful fallback при отсутствии файла | 🔵 Low |
| 98 | Reliability | Trace | `cleanup_old_traces()` никогда не вызывается автоматически | 🔵 Low |
| 99 | Performance | Session Backend | Redis `count()` выполняет full SCAN — O(N) | 🔵 Low |
| ~~114~~ | ~~Feature gap~~ | ~~Integration~~ | ~~LangChain `post_check` отсутствует~~ | ✅ Fixed |
| ~~117~~ | ~~Logic bug~~ | ~~Watcher~~ | ~~Удаление YAML-файлов не обрабатывается~~ | ✅ Fixed |
| 120 | Resource leak | Telegram Bot | `run_bot()` не вызывает `bot.stop()` при KeyboardInterrupt | 🔵 Low |
| 122 | Data loss | Config | `render_config()` пропускает `rate_limits` | 🔵 Low |
| 123 | DX | Integration | CrewAI `run()` alias конфликт с `BaseTool.run()` | 🔵 Low |
| 124 | Logic bug | Decorator | `_bind_args` fallback теряет positional args | 🔵 Low |
| 140 | Performance | Approval | `InMemoryBackend._start_gc()` — daemon Timer churn | 🔵 Low |
| 141 | Resource | Telegram Bot | Shared `httpx.AsyncClient` для 2 API с разными timeout | 🔵 Low |
| 142 | DX | MCP Proxy | `upstream_command` always empty list | 🔵 Low |
| 143 | Code quality | Rate Limiter | `count_in_window` — side effect в read-only метод | 🔵 Low |
| ~~152~~ | ~~Race condition~~ | ~~Approval~~ | ~~InMemoryBackend `get_status()` timeout race с `respond()`~~ | ✅ Fixed |
| 153 | Memory leak | Telegram Bot | `_pending` dict без TTL — unbounded memory growth | 🔵 Low |
| ~~154~~ | ~~Concurrency~~ | ~~Engine~~ | ~~`asyncio.run()` в sync path — deadlock в async contexts~~ | ✅ Fixed |
| ~~155~~ | ~~Architecture~~ | ~~SDK~~ | ~~Три дублирующих клиента с несовместимыми API~~ | ✅ Fixed |
| ~~156~~ | ~~API bug~~ | ~~SDK~~ | ~~`wait_for_approval` — несуществующий endpoint (404)~~ | ✅ Fixed |
| 157 | Performance | Engine | ThreadPool per-call + leak при таймаутах | 🟠 High |
| 158 | Architecture | Engine/Config | Sync/async code duplication → расхождение поведения | 🟠 High |
| 159 | Logic bug | LangChain | `_arun()` вызывает sync `_run()` вместо async `_arun()` | 🟠 High |
| 160 | Dead code | Server | `new_tools` мёртвый код в compile-and-apply | 🟠 High |
| ~~161~~ | ~~Logic bug~~ | ~~Server~~ | ~~`compile-and-apply` — rules_path может быть директорией~~ | ✅ Fixed |
| ~~162~~ | ~~Concurrency~~ | ~~Engine~~ | ~~Вложенные thread pool + event loop при LLM Guard~~ | ✅ Fixed |
| ~~163~~ | ~~Data integrity~~ | ~~Session~~ | ~~`_evict_oldest` не синхронизирует backend~~ | ✅ Fixed |
| ~~164~~ | ~~Thread safety~~ | ~~Rate Limiter~~ | ~~`_SlidingWindow` не thread-safe~~ | ✅ Fixed |
| ~~165~~ | ~~Security~~ | ~~Server~~ | ~~Content-Type middleware пропускает пустой header~~ | ✅ Fixed |
| 166 | DX | Client | Разный default `backoff_factor` sync vs async | 🔵 Low |
| 167 | Code quality | Engine | `get_policy_summary()` lock inconsistency | 🔵 Low |
| 168 | Feature gap | LangChain | `_arun()` native async path без `post_check` | 🔵 Low |
| 169 | Logic bug | MCP Proxy | Regex tool patterns как literal MCP tool names | 🔵 Low |
| 170 | Race condition | Engine | Sync path не snapshot'ит PII-детектор под lock | 🟠 High |
| 171 | Data integrity | Session | `_evict_expired` тоже не чистит backend | 🟠 High |
| 172 | Reliability | Watcher | `stat()` TOCTOU crash + потеря отслеживания | 🟠 High |
| ~~173~~ | ~~Architecture~~ | ~~Session~~ | ~~TTL по `created_at`, не last access — active sessions expire~~ | ✅ Fixed |
| ~~174~~ | ~~Security~~ | ~~Server~~ | ~~Content-Type check не покрывает compile endpoints~~ | ✅ Fixed |
| ~~175~~ | ~~Reliability~~ | ~~Server~~ | ~~Backpressure не покрывает compile-and-apply~~ | ✅ Fixed |
| ~~176~~ | ~~Logic bug~~ | ~~CrewAI~~ | ~~`post_check` coroutine не await'ится с async engine~~ | ✅ Fixed |
| ~~177~~ | ~~Performance~~ | ~~Engine~~ | ~~`ThreadPoolExecutor` per-call overhead (дефолт 5s timeout)~~ | ✅ Fixed |
| 178 | Observability | Engine | `post_check` — нет OTel tracing | 🔵 Low |
| 179 | Logic bug | Server | `_rules_hash` не включает output_rules/honeypots | 🔵 Low |
| 180 | Feature gap | Config | LLM Guard не настраивается через YAML config | 🔵 Low |
| ~~181~~ | ~~Logic bug~~ | ~~Telegram Bot~~ | ~~`_deploy()` — двойное закрытие fd при ошибке~~ | ✅ Fixed |
| ~~182~~ | ~~Concurrency~~ | ~~MCP Server~~ | ~~`reload_rules()` sync вызов блокирует async event loop~~ | ✅ Fixed |
| ~~183~~ | ~~Concurrency~~ | ~~MCP Server~~ | ~~`kill()`/`resume()` sync с lock в async context~~ | ✅ Fixed |
| 184 | Logic bug | LangChain | `_arun()` native async — sync `_run()` на wrapped tool | 🟠 High |
| 185 | Resource leak | Approval | `SlackApprovalBackend` нет `stop()` → GC thread leak | 🟠 High |
| 186 | Race condition | Approval | `InMemoryBackend.stop()` data race при чтении events | 🟠 High |
| 187 | Portability | Server | `compile-and-apply` `os.rename()` вместо `os.replace()` | 🟠 High |
| ~~188~~ | ~~Security~~ | ~~MCP Server~~ | ~~`admin_token` не декларирован в `inputSchema`~~ | ✅ Fixed |
| ~~189~~ | ~~Security~~ | ~~Server~~ | ~~Per-IP rate limit не работает за reverse proxy~~ | ✅ Fixed |
| ~~190~~ | ~~Data loss~~ | ~~Telegram Bot~~ | ~~`_deploy()` fallback тихо перезаписывает правила~~ | ✅ Fixed |
| ~~191~~ | ~~Architecture~~ | ~~SDK~~ | ~~Три `CheckResult` с несовместимыми полями~~ | ✅ Fixed |
| ~~192~~ | ~~Feature gap~~ | ~~SDK~~ | ~~`AsyncPolicyShieldClient` отсутствуют критические методы~~ | ✅ Fixed |
| ~~193~~ | ~~Code quality~~ | ~~MCP Proxy~~ | ~~String comparison для enum вместо `Verdict.BLOCK`~~ | ✅ Fixed |
| ~~194~~ | ~~Concurrency~~ | ~~Engine~~ | ~~Plugin hooks — sync-only в async engine path~~ | ✅ Fixed |
| 195 | Logic bug | LangChain | `_run()` async engine вызывается синхронно | 🔵 Low |
| 196 | Resource leak | Telegram Bot | `httpx.AsyncClient` не закрывается при `KeyboardInterrupt` | 🔵 Low |
| 197 | Performance | Server | `payload_size_limit` middleware — двойное чтение body | 🔵 Low |
| 198 | Security | MCP Server | `health` tool раскрывает `is_killed` без auth | 🔵 Low |
| ~~199~~ | ~~Race condition~~ | ~~Server~~ | ~~`clear_taint()` API — race без SessionManager lock~~ | ✅ Fixed |
| ~~200~~ | ~~Concurrency~~ | ~~Engine~~ | ~~`_apply_post_check` async deadlock при shared Lock~~ | ✅ Fixed |
| 201 | Memory leak | Engine | `_approval_meta` unbounded growth без proactive GC | 🟠 High |
| 202 | Memory leak | Server | `IdempotencyCache` без TTL и size limit | 🟠 High |
| 203 | Resource leak | Engine | `LLMGuard._http_client` TOCTOU race при lazy init | 🟠 High |
| 204 | Data race | Server | `reload()` + `compile-and-apply` — разные locks | 🟠 High |
| ~~205~~ | ~~Architecture~~ | ~~Decorator~~ | ~~`shield()` `session_id` захватывается при декорировании~~ | ✅ Fixed |
| ~~206~~ | ~~Logic bug~~ | ~~Approval~~ | ~~Telegram `wait_for_response()` удаляет response~~ | ✅ Fixed |
| ~~207~~ | ~~Race condition~~ | ~~Engine~~ | ~~`event_buffer` вне atomic snapshot~~ | ✅ Fixed |
| 208 | Resource leak | Decorator | `_get_default_engine()` глобальный singleton без cleanup | 🔵 Low |
| 209 | Logic bug | Engine | `_build_prompt()` truncation ломает JSON | 🔵 Low |
| 210 | DX | Watcher | `_scan_mtimes()` hardcoded extensions, двойной rglob | 🔵 Low |
| 211 | Feature gap | Config | `build_*_engine_from_config()` не создаёт OTel exporter | 🟠 High |
| 212 | Feature gap | Config | `_build_approval_backend()` не поддерживает Slack/Telegram/Webhook | 🟠 High |
| ~~213~~ | ~~Thread safety~~ | ~~Engine~~ | ~~`mode` setter не thread-safe (free-threading risk)~~ | ✅ Fixed |
| ~~214~~ | ~~Reliability~~ | ~~Engine~~ | ~~Plugin hooks partial execution при timeout в sync engine~~ | ✅ Fixed |
| ~~215~~ | ~~Concurrency~~ | ~~Server~~ | ~~`reload()` FastAPI endpoint — sync I/O блокирует event loop~~ | ✅ Fixed |
| ~~216~~ | ~~Resource leak~~ | ~~Engine~~ | ~~`LLMGuard._http_client` не закрывается при shutdown~~ | ✅ Fixed |
| 217 | Concurrency | Server | `respond_approval()` sync I/O в async handler | 🔵 Low |
| 218 | Reliability | Server | Self-test блокируется wildcard правилами (`tool: .*`) | 🔵 Low |
| 219 | Feature gap | Server | `compile-and-apply` не поддерживает context conditions | 🔵 Low |

