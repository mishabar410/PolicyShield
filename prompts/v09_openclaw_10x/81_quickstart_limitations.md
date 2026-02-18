# Prompt 80 — Quickstart & Limitations Documentation

## Цель

Создать copypaste-ready quickstart (без `<PLACEHOLDERS>`) и задокументировать ограничения output scanning. Финальная полировка документации.

## Контекст

- Текущий quickstart в README требует знания нескольких инструментов
- Ограничения `after_tool_call` (не может заблокировать output) — нигде не описаны явно
- Нет одностраничного «попробуй за 60 секунд» гайда
- Это последний промпт в цепочке — после него интеграция должна быть 10/10

## Что сделать

### 1. Обновить секцию Quickstart в `README.md`

Заменить текущий quickstart на:

```markdown
## ⚡ Quick Start with OpenClaw (60 seconds)

### Option A: One Command (recommended)
```bash
pip install "policyshield[server]"
policyshield openclaw setup
```

That's it. This will:
1. Generate security rules (`rules.yaml`)
2. Start PolicyShield server (port 8100)
3. Install the OpenClaw plugin
4. Configure the connection
5. Verify everything works

### Option B: Docker
```bash
curl -O https://raw.githubusercontent.com/<OWNER>/PolicyShield/main/docker/docker-compose.openclaw.yml
docker compose -f docker-compose.openclaw.yml up
```

### Option C: Step by Step
```bash
# 1. Install and generate rules
pip install "policyshield[server]"
policyshield init --preset openclaw

# 2. Start server (new terminal)
policyshield server --rules rules.yaml --port 8100

# 3. Install plugin
openclaw plugins install @policyshield/openclaw-plugin

# 4. Configure
openclaw config set plugins.entries.policyshield.config.url http://localhost:8100

# 5. Verify
curl http://localhost:8100/api/v1/health
```
```

### 2. Добавить секцию Limitations в `docs/integrations/openclaw.md`

```markdown
## Limitations & Trade-offs

### Output PII Scanning — Cannot Block

The `after_tool_call` hook in OpenClaw's plugin SDK returns `void`. This means:

- ✅ PolicyShield **detects** PII in tool output (email, phone, SSN, etc.)
- ✅ PolicyShield **logs** PII detection as an audit event
- ✅ PolicyShield **taints** the session (if `taint_chain` is enabled)
- ❌ PolicyShield **cannot modify or block** the output — it has already been delivered to the agent

**Mitigation:** Enable `taint_chain` in your rules to block subsequent outgoing calls (like `send_message`, `web_fetch`) after PII is detected in output:

```yaml
taint_chain:
  enabled: true
  outgoing_tools: [send_message, web_fetch, exec]
```

This prevents the agent from **leaking** PII to external services, even though it has already **seen** the PII.

### Two-Process Architecture

PolicyShield runs as a separate Python process from OpenClaw (Node.js). This means:

- **Latency:** Each tool call adds an HTTP round-trip (~1-5ms on localhost)
- **Deployment:** Two processes to manage (or use Docker Compose)
- **Failure mode:** If PolicyShield crashes, behavior depends on `fail_open` config

### Regex-Based PII Detection

Current PII detection uses regex patterns (Level 0). This means:

- ✅ Fast (<1ms per scan)
- ❌ May produce false positives (e.g., numbers that look like phone numbers)
- ❌ Cannot detect semantic PII (e.g., "call John at his home number")
- 🔜 NER-based detection (Level 1) is on the roadmap
```

### 3. Обновить `ROADMAP.md`

Отметить v0.9 как текущую:

```markdown
## v0.9 — OpenClaw 10/10 ✅ (current)

- SDK type auto-sync script + CI (weekly cron)
- E2E integration tests with real OpenClaw (Docker Compose, 5 scenarios)
- E2E CI job on every PR
- Server Bearer token authentication (`POLICYSHIELD_API_TOKEN`)
- PII taint chain: block outgoing calls after PII leak in output
- `policyshield openclaw setup` — one-command integration
- Compatibility matrix and migration guide
- Quickstart: Option A (1 cmd), Option B (Docker), Option C (step-by-step)
- Explicit limitations documentation (output blocking, PII detection)
```

### 4. Обновить `CHANGELOG.md`

Добавить v0.9.0:

```markdown
## v0.9.0

### Added
- `policyshield openclaw setup/teardown/status` CLI commands
- Server Bearer token authentication via `POLICYSHIELD_API_TOKEN`
- PII taint chain: `taint_chain` config in rules YAML
- `/api/v1/clear-taint` endpoint
- E2E test suite with real OpenClaw (Docker Compose)
- SDK type auto-sync script + CI job
- Compatibility matrix and migration guide
- `docker-compose.openclaw.yml` for one-file deployment

### Changed
- Plugin config: added `api_token` field
- OpenClaw preset rules: includes `taint_chain` (disabled by default)
- Quickstart: three options (one-command, Docker, step-by-step)

### Documentation
- Explicit limitations section (output blocking, PII detection)
- Migration guide: 0.7→0.8 and 0.8→0.9
- Version compatibility table
```

### 5. Обновить `pyproject.toml` версию

```toml
version = "0.9.0"
```

## Самопроверка

```bash
# Версия обновлена
python -c "import policyshield; print(policyshield.__version__)"  # 0.9.0

# Все тесты
pytest tests/ -q

# TypeScript
cd plugins/openclaw && npx tsc --noEmit && npm test

# CLI работает
policyshield openclaw --help

# Линки в документации
grep -r "openclaw-migration" docs/ README.md | head -5
```

## Коммит

```
docs: quickstart, limitations, changelog, version bump to 0.9.0

- Add 3-option quickstart (one-command, Docker, step-by-step)
- Document output scanning limitations and taint chain mitigation
- Add v0.9.0 changelog entry
- Update ROADMAP v0.9 as current
- Bump version to 0.9.0
```
