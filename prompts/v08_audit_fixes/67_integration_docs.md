# Prompt 67 — Integration Docs

## Цель

Переписать `plugins/openclaw/README.md` и обновить корневой `README.md` чтобы пользователь OpenClaw мог интегрировать PolicyShield за **3 шага**, а не за 6.

## Контекст

Текущий путь интеграции:
1. `pip install "policyshield[server]"` — Python
2. Создать YAML rules
3. `policyshield server --rules rules.yaml` — запустить сервер
4. Скопировать плагин вручную
5. Настроить `openclaw.yaml`
6. Молиться что SDK stubs совпадают

Целевой путь (3 шага):
1. `pip install "policyshield[server]"` + `npm install @policyshield/openclaw-plugin`
2. Создать rules + добавить 3 строки в `openclaw.yaml`
3. `policyshield server --rules rules.yaml` + запустить OpenClaw

## Что сделать

### 1. Переписать `plugins/openclaw/README.md`

Структура:

```markdown
# PolicyShield Plugin for OpenClaw

Runtime policy enforcement for OpenClaw tool calls — block, redact, audit.

## Quick Start (3 steps)

### Step 1: Install

```bash
# PolicyShield server (Python)
pip install "policyshield[server]"

# OpenClaw plugin (npm)
npm install @policyshield/openclaw-plugin
# — или добавить в openclaw extensions:
# openclaw install @policyshield/openclaw-plugin
```

### Step 2: Configure

Create `rules.yaml`:
```yaml
version: 1
rules:
  - name: block-destructive
    tool: exec
    match:
      args.command:
        regex: "rm\\s+-rf|mkfs|dd\\s+if="
    verdict: BLOCK
    message: "Destructive command blocked by policy"
```

Add to your `openclaw.yaml`:
```yaml
plugins:
  entries:
    policyshield:
      enabled: true
      config:
        url: "http://localhost:8100"
```

### Step 3: Run

```bash
# Terminal 1: Start PolicyShield server
policyshield server --rules rules.yaml

# Terminal 2: Start OpenClaw (plugin loads automatically)
openclaw
```

## What It Does

| Hook | Action |
|------|--------|
| `before_tool_call` | Check policy → BLOCK / REDACT / APPROVE / ALLOW |
| `after_tool_call` | Scan tool output for PII (email, phone, SSN, etc.) |
| `before_agent_start` | Inject active policy rules into agent context |

## Configuration

All options in `openclaw.yaml` under `plugins.entries.policyshield.config`:

| Option | Default | Description |
|--------|---------|-------------|
| `url` | `http://localhost:8100` | PolicyShield server URL |
| `mode` | `enforce` | `enforce` or `disabled` |
| `fail_open` | `true` | Allow tool calls if server unreachable |
| `timeout_ms` | `5000` | HTTP request timeout |
| `approve_timeout_ms` | `60000` | Max wait for human approval |
| `approve_poll_interval_ms` | `2000` | Approval polling interval |
| `max_result_bytes` | `10000` | Max result size for PII scan |

## Troubleshooting

### Plugin not loading
- Check `openclaw.yaml` has `plugins.entries.policyshield.enabled: true`
- Run `openclaw` with `--verbose` to see plugin load logs

### Server unreachable
- Verify server is running: `curl http://localhost:8100/api/v1/health`
- Check `url` in config matches server address
- If `fail_open: true` (default), tool calls will proceed when server is down

### PII not detected
- Post-check only scans first `max_result_bytes` (default 10KB) of result
- Increase `max_result_bytes` for larger tool outputs

## Development

```bash
cd plugins/openclaw
npm install
npm run typecheck  # tsc --noEmit
npm test           # vitest
npm run build      # compile to dist/
```
```

### 2. Обновить корневой README.md секцию "OpenClaw Integration"

Заменить текущую секцию на:

```markdown
## OpenClaw Integration

Install the plugin and start protecting tool calls:

```bash
pip install "policyshield[server]"
npm install @policyshield/openclaw-plugin
```

Add to `openclaw.yaml`:
```yaml
plugins:
  entries:
    policyshield:
      enabled: true
      config:
        url: "http://localhost:8100"
```

Start the server and go:
```bash
policyshield server --rules rules.yaml
```

See [`plugins/openclaw/README.md`](plugins/openclaw/README.md) for full configuration.
```

### 3. Добавить example `openclaw.yaml` snippet

Создать `examples/openclaw.yaml`:

```yaml
# Example OpenClaw configuration with PolicyShield
# Add this to your existing openclaw.yaml

plugins:
  entries:
    policyshield:
      enabled: true
      config:
        url: "http://localhost:8100"
        mode: enforce           # "enforce" or "disabled"
        fail_open: true         # allow tool calls if server is down
        timeout_ms: 5000        # request timeout
        approve_timeout_ms: 60000
```

## Самопроверка

- `cat plugins/openclaw/README.md | head -5` — title correct
- Quick Start section has exactly 3 numbered steps
- `openclaw.yaml` example is valid YAML: `python -c "import yaml; yaml.safe_load(open('examples/openclaw.yaml'))"`
- Нет ссылок на `nicepkg` нигде: `grep -r "nicepkg" .`

## Коммит

```
docs: rewrite OpenClaw integration docs — 3-step quickstart

- Rewrite plugins/openclaw/README.md for simplicity
- Update root README.md OpenClaw section
- Add examples/openclaw.yaml with full config example
- Target: install → configure → run in 3 steps
```
