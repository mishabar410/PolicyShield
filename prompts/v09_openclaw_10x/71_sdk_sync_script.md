# Prompt 71 — SDK Type Stub Validation & Sync Script

## Status: BLOCKED — Recon finding

### Finding

Prompt 73 (API Recon) was executed ahead of schedule and revealed that
`openclaw/plugin-sdk` **does not re-export plugin hook types** through its
public barrel.

The barrel (`dist/plugin-sdk/plugin-sdk/index.d.ts`) exports ~100 types but
only includes:

| Exported from barrel | Missing from barrel |
|---|---|
| `OpenClawPluginApi` | `OpenClawPluginDefinition` |
| `OpenClawPluginService` | `PluginHookBeforeToolCallEvent` |
| `RuntimeLogger` | `PluginHookBeforeToolCallResult` |
| | `PluginHookAfterToolCallEvent` |
| | `PluginHookToolContext` |
| | `PluginHookBeforeAgentStartEvent` |
| | `PluginHookBeforeAgentStartResult` |
| | `PluginHookAgentContext` |
| | `PluginLogger` |

The types exist in internal files (`dist/plugin-sdk/plugins/types.d.ts`,
`dist/plugin-sdk/plugins/hooks.d.ts`) but are not accessible via any public
subpath export. OpenClaw's `package.json` only declares 4 exports:
`.`, `./plugin-sdk`, `./plugin-sdk/account-id`, `./cli-entry`.

### Decision

**Keep the manual type stubs** (`src/openclaw-plugin-sdk.d.ts`).

This is the most robust approach because:
1. Importing from internal paths (`openclaw/dist/...`) is fragile and unsupported
2. The constraint "no PRs/issues to OpenClaw" prevents us from requesting new exports
3. The stubs are already tested via `types.test.ts` and `openclaw-compat.test.ts`

### Remaining value from this prompt

A lightweight sync validation script can still add value by comparing our
stub signatures against the real OpenClaw source. This is lower priority and
can be revisited when OpenClaw publishes hook types publicly.

---

## Goal (deferred)

Create a script that fetches OpenClaw's `plugins/types.ts` and `plugins/hooks.d.ts`
from GitHub and validates our stubs match. This would run in CI as a
non-blocking warning.

## Self-check

- [x] Recon performed: `openclaw/plugin-sdk` barrel analyzed
- [x] Finding documented with evidence
- [x] Code reverted to working state (manual stubs)
- [x] All 49 tests pass, `tsc --noEmit` clean

## Commit message

```
docs(openclaw): document SDK barrel limitation for hook types

openclaw/plugin-sdk does not re-export PluginHook* types or
PluginLogger through its public barrel. Keep manual stubs until
OpenClaw publishes these types.

Refs: prompt 71, 73 recon finding
```
