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
2. Update plugin:
   ```bash
   npm install --prefix ~/.openclaw/extensions/policyshield @policyshield/openclaw-plugin@latest
   cp -r ~/.openclaw/extensions/policyshield/node_modules/@policyshield/openclaw-plugin/* \
        ~/.openclaw/extensions/policyshield/
   ```
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
1. Remove old plugin: `rm -rf ~/.openclaw/extensions/policy-shield`
2. Install new plugin:
   ```bash
   npm install --prefix ~/.openclaw/extensions/policyshield @policyshield/openclaw-plugin
   cp -r ~/.openclaw/extensions/policyshield/node_modules/@policyshield/openclaw-plugin/* \
        ~/.openclaw/extensions/policyshield/
   ```
3. Update config key: `plugins.entries.policy-shield` → `plugins.entries.policyshield`
4. If using `mode: audit` in plugin config: remove it, configure on server:
   ```bash
   policyshield server --mode audit --rules rules.yaml
   ```
