# Tier 1.5 Prompt Chains — v12

> ~48 atomic prompts для production readiness: hardening, security, DX.

## Правила выполнения

1. **Один промпт = один коммит** — атомарность
2. **Не ломай существующее** — `pytest tests/ -q` после каждого промпта
3. **Lint & format** — `ruff check . && ruff format --check .`
4. **Порядок** — соблюдай зависимости между фазами

## Порядок выполнения

```
Фаза 1 (параллельно): Server Hardening (301–308) + Approval Flow (311–317)
Фаза 2 (параллельно): Security (321–326) + Lifecycle (331–340)
Фаза 3:               DX & Adoption (351–367)
```

---

## Server Hardening (8 промптов)

| #   | Файл                    | Фича                                |
| --- | ----------------------- | ------------------------------------ |
| 301 | `301_error_handler.md`  | Global exception handler → JSON      |
| 302 | `302_request_id.md`     | Request / correlation ID             |
| 303 | `303_cors.md`           | CORS middleware (env config)         |
| 304 | `304_content_type.md`   | Content-Type validation (415)        |
| 305 | `305_payload_limit.md`  | Payload size limit (default 1MB)     |
| 306 | `306_input_validation.md` | tool_name pattern, args depth      |
| 307 | `307_backpressure.md`   | Max concurrent checks (503)         |
| 308 | `308_request_timeout.md` | HTTP request timeout (504)          |

## Approval Flow (7 промптов)

| #   | Файл                          | Фича                              |
| --- | ----------------------------- | ---------------------------------- |
| 311 | `311_approval_timeout.md`     | Approval timeout + auto-resolve    |
| 312 | `312_approval_audit.md`       | Audit trail (who/when/channel)     |
| 313 | `313_approval_gc.md`          | Stale approval GC (TTL + timer)    |
| 314 | `314_approval_race.md`        | First-response-wins guard          |
| 315 | `315_approval_sanitize.md`    | Args sanitization in approval flow |
| 316 | `316_approval_poll_timeout.md` | HTTP polling timeout              |
| 317 | `317_approval_meta_cleanup.md` | _approval_meta TTL + size limit   |

## Security & Data Protection (6 промптов)

| #   | Файл                       | Фича                                 |
| --- | -------------------------- | ------------------------------------- |
| 321 | `321_secret_detection.md`  | Secret detector (AWS, OpenAI, JWT)    |
| 322 | `322_admin_token.md`       | Admin token separation                |
| 323 | `323_error_scrub.md`       | Scrub sensitive data from errors      |
| 324 | `324_log_filter.md`        | Hide arg values from INFO logs        |
| 325 | `325_trace_permissions.md` | Trace file permissions (0o600)        |
| 326 | `326_rate_limiting.md`     | Rate limiting for admin endpoints     |

## Lifecycle & Reliability (10 промптов)

| #   | Файл                        | Фича                                |
| --- | --------------------------- | ------------------------------------ |
| 331 | `331_graceful_shutdown.md`  | Graceful shutdown + request draining |
| 332 | `332_trace_flush.md`        | Trace flush on shutdown (atexit)     |
| 333 | `333_config_validation.md`  | Config validation at startup         |
| 334 | `334_fail_mode.md`          | Fail-open / fail-closed config       |
| 335 | `335_engine_timeout.md`     | Per-check engine timeout             |
| 336 | `336_atomic_reload.md`      | Atomic hot-reload (validate→swap)    |
| 337 | `337_startup_selftest.md`   | Startup self-test (fail-fast)        |
| 338 | `338_python_version.md`     | Python 3.10+ version check           |
| 339 | `339_structured_logging.md` | JSON logging (POLICYSHIELD_LOG_FORMAT)|
| 340 | `340_telegram_shutdown.md`  | Telegram poller graceful shutdown    |

## DX & Adoption (17 промптов)

| #   | Файл                        | Фича                                 |
| --- | --------------------------- | ------------------------------------- |
| 351 | `351_python_sdk.md`         | PolicyShieldClient (sync)             |
| 352 | `352_retry_backoff.md`      | Retry + exponential backoff in SDK    |
| 353 | `353_dryrun_cli.md`         | CLI `--dry-run` mode                  |
| 354 | `354_decorator_api.md`      | `@guard()` decorator                  |
| 355 | `355_presets.md`            | Rule presets (strict/permissive/min)  |
| 356 | `356_mcp_server.md`         | MCP server transport                  |
| 357 | `357_k8s_probes.md`         | `/healthz` + `/readyz` K8s probes     |
| 358 | `358_env_config.md`         | Centralized env config dataclass      |
| 359 | `359_idempotency.md`        | Idempotency key (`x-idempotency-key`) |
| 360 | `360_examples.md`           | Integration examples                  |
| 361 | `361_openapi_schema.md`     | OpenAPI schema export CLI             |
| 362 | `362_metrics.md`            | `/metrics` Prometheus endpoint        |
| 363 | `363_coverage.md`           | Test coverage gate (80%)              |
| 364 | `364_async_client.md`       | AsyncPolicyShieldClient               |
| 365 | `365_validate_cli.md`       | CLI `policyshield validate`           |
| 366 | `366_webhooks.md`           | Webhook notifications                 |
| 367 | `367_async_engine_compat.md` | Async engine compatibility tests     |

---

## Env Variables (полный список)

| Variable                                | Default    | Промпт |
| --------------------------------------- | ---------- | ------ |
| `POLICYSHIELD_API_TOKEN`                | (none)     | 322    |
| `POLICYSHIELD_ADMIN_TOKEN`              | (none)     | 322    |
| `POLICYSHIELD_CORS_ORIGINS`             | (disabled) | 303    |
| `POLICYSHIELD_MAX_REQUEST_SIZE`         | 1048576    | 305    |
| `POLICYSHIELD_MAX_CONCURRENT_CHECKS`    | 100        | 307    |
| `POLICYSHIELD_REQUEST_TIMEOUT`          | 30         | 308    |
| `POLICYSHIELD_ENGINE_TIMEOUT`           | 5          | 335    |
| `POLICYSHIELD_FAIL_MODE`                | closed     | 334    |
| `POLICYSHIELD_DEBUG`                    | false      | 323    |
| `POLICYSHIELD_LOG_LEVEL`                | INFO       | 339    |
| `POLICYSHIELD_LOG_FORMAT`               | text       | 339    |
| `POLICYSHIELD_WEBHOOK_URL`              | (none)     | 366    |
| `POLICYSHIELD_APPROVAL_POLL_TIMEOUT`    | 30         | 316    |
