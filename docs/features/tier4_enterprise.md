# 🔵 Tier 4 — Enterprise/Scale (Post Product-Market Fit)

| Feature | Description |
|---------|-------------|
| RBAC | Per-role policy sets |
| Agent Identity & Attribution | Per-agent privileges, identity propagation, per-agent audit |
| Multi-Agent Orchestration | Cross-agent policy, session isolation/sharing |
| Federated Policies | Central policy server with push-updates |
| Multi-Tenant | Per-org policy sets with inheritance |
| Rule Versioning & Rollback | Git-like `rules history`, `rules rollback v3` |
| HA / Stateless Mode | Redis-backed sessions + approvals for multi-instance |
| Signed Rule Bundles | Signed rule packages for air-gapped environments |
| Offline / Airgapped Mode | Guarantee of operation without network |
| Config Encryption / Secrets Mgmt | Integration with Vault / AWS Secrets Manager / SOPS |
| API Versioning & Deprecation | Formal v1 → v2 migration policy |
| Config Schema Migration | Auto-migrate old config format on upgrade |
| Cost Attribution | Cost breakdown per agent/session/user |

---

## Deferred

| Feature | Reason |
|---------|--------|
| Rego/OPA bridge | Heavy dependency, confusing for users |
| Multi-language SDKs (Go, Rust) | Premature without product-market fit |
| Agent sandbox | Different domain, different project |
| Data watermarking | Niche feature |

---

## Integrations to Consider

| Framework | Priority | Notes |
|-----------|----------|-------|
| OpenAI Agents SDK | 🔥🔥 | New SDK, replaces Assistants API |
| Anthropic tool use | 🔥🔥 | Direct integration |
| AutoGen | 🔥🔥 | Fast growing, multi-agent |
| Dify | 🔥🔥 | Huge OSS base, workflow agents |
| n8n | 🔥 | AI agents in workflow automation |
| LlamaIndex Agents | 🔥 | Agents mode gaining traction |
| Semantic Kernel | 🔥 | Microsoft ecosystem |
| Haystack | 🔥 | Pipeline-based agents by deepset |
