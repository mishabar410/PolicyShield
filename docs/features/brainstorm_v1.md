# PolicyShield v1.0 — Roadmap (Unrealized Features)

> Current state: **v0.14.0** released. 1350 tests, 85% coverage.

---

## 🏗️ Technical Debt

### Test Coverage (current: 85%)
| File | Coverage | Needed |
|------|----------|--------|
| `mcp_proxy.py` | ~0% | Unit tests for forward/block/modify path |
| `mcp_server.py` | ~16% | Tests for start/stop/tool_list/check |
| `cli/quickstart.py` | ~0% | Mock stdin for interactive flow |
| `cli/openclaw.py` | ~28% | Tests for fetch tools, error handling |
| `sdk/async_client.py` | ~40% | Tests for timeout, retry, error scenarios |
| `trace/search.py` | ~81% | Edge-cases for filtering |
| **Target** | **90%** | Raise coverage gate in CI |

### Code Quality
- [ ] 2 mypy errors in `cli/main.py` (lines ~1428, 1430)
- [ ] Remove `# type: ignore` where possible

---

## 🟡 Tier 3B — High Value, Post-v1.0

### Compile Diff Mode
- [ ] `policyshield compile --diff` — show what changes vs current rules

### Session Metrics
- [ ] Metrics: active_sessions, evicted_sessions_total

### Production Deployment Gaps
- [ ] Helm chart
- [ ] Monitoring/alerting recommendations
- [ ] Backup/restore for traces

### Web UI Dashboard

Full-featured web dashboard:

- [ ] Rule editor (YAML + validation)
- [ ] Trace viewer + search
- [ ] Session inspector
- [ ] Kill switch button 🔴
- [ ] Health dashboard
- [ ] API token management

Stack recommendation: HTMX + Jinja2 — minimal complexity, 0 external deps.

### RBAC (Role-Based Access Control)

```yaml
roles:
  admin:
    allowed: ["*"]
  developer:
    allowed: ["read_file", "write_file", "exec"]
    denied: ["delete_*", "deploy"]
  viewer:
    allowed: ["read_*"]
```

- [ ] Role definitions in YAML
- [ ] Role → tool permission mapping
- [ ] API: `engine.check(tool, args, role='developer')`
- [ ] CLI: `policyshield check --tool deploy --role viewer`

### Agent Identity & Attribution

```python
result = engine.check("exec", {"cmd": "ls"},
    agent_id="coding-agent-1",
    parent_agent_id="orchestrator",
    session_id="s1"
)
```

- [ ] `agent_id` in traces
- [ ] Per-agent rate limits
- [ ] Per-agent policy overrides
- [ ] Agent reputation score (based on historical behavior)

---

## 🔵 Tier 4 — Enterprise / Scale

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

### Deferred

| Feature | Reason |
|---------|--------|
| Rego/OPA bridge | Heavy dependency, confusing for users |
| Multi-language SDKs (Go, Rust) | Premature without product-market fit |
| Agent sandbox (containers, seccomp) | Different domain, different product |
| Data watermarking | Niche feature |
| Chaos testing | Can be replaced with unit tests |

---

## 🧩 Integrations

| Framework | Priority | Status |
|-----------|----------|--------|
| **OpenAI Agents SDK** | 🔥🔥🔥 | ❌ Needed |
| **Anthropic tool_use** | 🔥🔥🔥 | ❌ Needed |
| **AutoGen** | 🔥🔥 | ❌ Needed |
| **Dify** | 🔥🔥 | ❌ Needed |
| **Vercel AI SDK** | 🔥🔥 | ❌ Needed |
| **n8n** | 🔥 | ❌ Needed |
| **LlamaIndex** | 🔥 | ❌ Needed |
| **Semantic Kernel** | 🔥 | ❌ Needed |
| **Haystack** | 🔥 | ❌ Needed |

Each integration = 3 files:
```
policyshield/integrations/<framework>/
├── __init__.py      # adapter code
├── README.md        # usage guide
└── examples/        # working examples
```

---

## 🚀 DX & Community

### VS Code Extension
- Syntax highlighting for `rules.yaml`
- Inline validation (like ESLint for rules)
- Code actions: "Add BLOCK rule for this tool"
- Snippets for common patterns

### GitHub Action
```yaml
- uses: policyshield/action@v1
  with:
    rules: policies/rules.yaml
    fail-on: warning
```

### Rule Marketplace / Community Packs
```bash
policyshield install-pack owasp-top10
policyshield install-pack coding-agent-security
```

### Interactive Playground
- Web-based: paste rules YAML → test tool calls → see verdicts
- Zero install
- Shareable links

---

## 💡 Wild Ideas

- **PolicyShield Cloud** — hosted SaaS version, `pip install policyshield && policyshield login`
- **"PolicyShield Certified" badge** — for agents that passed audit
- **AI rule advisor** — "your rules have a gap: tool X is unprotected"
- **Compliance-as-a-Service** — SOC2/GDPR/HIPAA rule packs with automatic audit trail
- **Agent Firewall** — network-level interception (eBPF?) for full control
- **Policy language DSL** — not YAML, but `BLOCK exec WHERE args.command CONTAINS "rm -rf"`
