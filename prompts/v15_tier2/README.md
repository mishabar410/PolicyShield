# Tier 2 Prompt Chains — DX, Integrations, Improvements

Prompt chains for Tier 2 features. Organized into 4 phases.

> Some features partially exist from Tier 1.5 work (MCP server, OpenAPI CLI,
> integration examples). Those chains focus on **expanding** what exists.

## Numbering

| Phase | Range | Theme |
|-------|-------|-------|
| 6 | 501–504 | SDK & Integrations |
| 7 | 511–514 | CLI & DX |
| 8 | 521–524 | Reliability |
| 9 | 531–534 | Operations & Observability |

## Execution Order

1. **Phase 6** — Python SDK client, MCP proxy, JS/TS SDK, decorator API
2. **Phase 7** — Role presets, quickstart wizard, dry-run CLI, test coverage
3. **Phase 8** — Idempotency, retry/backoff, deep health checks, K8s probes
4. **Phase 9** — ENV config (12-factor), OpenAPI expansion, Slack/webhook, more examples

## Files

```
prompts/v15_tier2/
├── README.md              ← this file
├── 501_python_sdk.md
├── 502_mcp_proxy.md
├── 503_js_ts_sdk.md
├── 504_decorator_api.md
├── 511_role_presets.md
├── 512_quickstart.md
├── 513_dry_run_cli.md
├── 514_test_coverage_report.md
├── 521_idempotency.md
├── 522_retry_backoff.md
├── 523_deep_health.md
├── 524_k8s_probes.md
├── 531_env_config.md
├── 532_openapi_expand.md
├── 533_slack_webhook.md
└── 534_integration_examples.md
```
