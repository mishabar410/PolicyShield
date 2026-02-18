# Prompt 79 — Compatibility Matrix & Migration Guide

## Цель

Добавить compatibility matrix (какие версии OpenClaw работают с какими версиями PolicyShield) и migration guide в документацию.

## Контекст

- Нет информации о совместимости версий — пользователь не знает, сломается ли плагин при обновлении OpenClaw
- Нет гайда по обновлению PolicyShield — что меняется в конфиге между версиями
- Эта информация критична для production-использования

## Что сделать

### 1. Добавить в `docs/integrations/openclaw.md` секцию Compatibility

```markdown
## Compatibility

### Version Matrix

| PolicyShield Server | PolicyShield Plugin | OpenClaw | Status |
|---------------------|---------------------|----------|--------|
| 0.9.x               | 0.9.x               | ≥ 2026.2 | ✅ Verified (E2E) |
| 0.8.x               | 0.8.x               | ≥ 2026.2 | ✅ Verified (unit tests) |
| ≤ 0.7.x             | ≤ 0.7.x             | —        | ❌ Incompatible (API mismatch) |

> **Important:** Server and plugin versions should always match (both 0.9.x).
> Cross-version combinations (e.g., server 0.8 + plugin 0.9) are not tested.

### How We Verify

- **E2E tests** run on every PR: Docker Compose stack with real OpenClaw + PolicyShield
- **SDK type sync** checked weekly: CI compares our stubs with upstream OpenClaw types
- **Plugin unit tests** with mocked API cover all hook signatures
```

### 2. Создать `docs/integrations/openclaw-migration.md`

```markdown
# OpenClaw Plugin — Migration Guide

## Upgrading PolicyShield

### From 0.8.x to 0.9.x

#### Server changes
- **New:** `POLICYSHIELD_API_TOKEN` env var for authentication
  - Optional — server works without it (same as 0.8.x)
  - If set, plugin config needs `api_token` to match
- **New:** `/api/v1/clear-taint` endpoint
- **New:** `taint_chain` config section in rules YAML

#### Plugin changes
- **New config field:** `api_token` in `openclaw.plugin.json`
  - If server uses `POLICYSHIELD_API_TOKEN`, set this to match
- No breaking changes to existing config fields

#### Rules changes
- **New optional section:** `taint_chain`
  ```yaml
  taint_chain:
    enabled: true
    outgoing_tools: [send_message, web_fetch, exec]
  ```
  - Disabled by default — existing rules work without changes
- `policyshield init --preset openclaw` now includes taint_chain (disabled)

#### Migration steps
1. Update server: `pip install --upgrade "policyshield[server]"`
2. Update plugin: `openclaw plugins update @policyshield/openclaw-plugin`
3. (Optional) Set API token:
   ```bash
   export POLICYSHIELD_API_TOKEN="your-secret-token"
   openclaw config set plugins.entries.policyshield.config.api_token "your-secret-token"
   ```
4. (Optional) Enable taint chain in rules:
   ```yaml
   taint_chain:
     enabled: true
     outgoing_tools: [send_message, web_fetch]
   ```
5. Restart server and OpenClaw

### From 0.7.x to 0.8.x

#### Breaking changes
- Plugin ID changed from `policy-shield` to `policyshield`
- OpenClaw SDK hook signatures updated to match real API
- `mode: audit` removed from plugin config (audit mode is server-side only)

#### Migration steps
1. Uninstall old plugin: `openclaw plugins remove policy-shield`
2. Install new plugin: `openclaw plugins install @policyshield/openclaw-plugin`
3. Update config key: `plugins.entries.policy-shield` → `plugins.entries.policyshield`
4. If using `mode: audit` in plugin config: remove it, configure on server:
   ```bash
   policyshield server --mode audit --rules rules.yaml
   ```
```

### 3. Добавить ссылку из `docs/integrations/openclaw.md`

В конец файла:

```markdown
## Upgrading

See the [Migration Guide](openclaw-migration.md) for version-specific upgrade instructions.
```

### 4. Добавить ссылку из `README.md`

В секцию OpenClaw:

```markdown
- [Compatibility & Migration Guide](docs/integrations/openclaw-migration.md)
```

## Самопроверка

```bash
# Markdown линтинг (если настроен)
# markdownlint docs/integrations/openclaw-migration.md

# Ссылки не сломаны
grep -r "openclaw-migration" docs/ README.md

# Тесты не сломаны
pytest tests/ -q
```

## Коммит

```
docs: add OpenClaw compatibility matrix and migration guide

- Add version compatibility table to docs/integrations/openclaw.md
- Create docs/integrations/openclaw-migration.md with upgrade steps
- Document 0.7→0.8 breaking changes and 0.8→0.9 additions
- Link from README and integration guide
```
