# Prompt 72 — SDK Sync CI & Version Tracking

## Status: DEFERRED — depends on prompt 71

### Context

Since prompt 71 found that `openclaw/plugin-sdk` does not export the hook
types we need, the original plan (Dependabot tracking + `tsc --noEmit`
against official types) is not feasible.

### Alternative approach (lower priority)

When/if this is revisited:

1. **GitHub-based stub validation** — a CI script that:
   - Fetches `src/plugins/types.ts` and `src/plugins/hooks.ts` from
     OpenClaw's GitHub repo (raw URL)
   - Extracts exported type names
   - Compares against our `openclaw-plugin-sdk.d.ts` exports
   - Warns (non-blocking) if new types appear or signatures change

2. **Dependabot for runtime dependency** — if we add `openclaw` as a
   `peerDependency` for runtime (not types), Dependabot can still track
   version updates. But this only helps when OpenClaw eventually exports
   the hook types.

### Self-check

- [x] Dependency on prompt 71 finding documented
- [x] Alternative approach outlined
- [ ] Implementation deferred

## Commit message

```
docs(openclaw): defer SDK sync CI — hook types not publicly exported

Prompt 71 recon found that openclaw/plugin-sdk barrel does not include
PluginHook* types. Defer automated sync until types are public.
```
