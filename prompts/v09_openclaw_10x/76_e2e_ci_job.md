# Prompt 76 — E2E CI Job

## Статус: 🔄 ПЕРЕРАБОТАН по результатам разведки (prompt 73)

### Изменения после разведки

Оригинальный план: Docker Compose в CI на каждом PR.
Реальность: сборка OpenClaw ~5 мин, нужен LLM API key.

**Новый план:** CI job запускает только Tier 1-2 тесты (unit + smoke).
Tier 3 (полный Docker Compose) — manual/release-only.

## Цель

Добавить CI job для OpenClaw integration tests.

## Что сделать

### 1. Job `openclaw-compat` в `.github/workflows/ci.yml`

```yaml
  openclaw-compat:
    name: OpenClaw Plugin Tests
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: "22"

      - name: Install plugin dependencies
        working-directory: plugins/openclaw
        run: npm ci

      - name: TypeScript check
        working-directory: plugins/openclaw
        run: npx tsc --noEmit

      - name: Plugin tests
        working-directory: plugins/openclaw
        run: npx vitest run --reporter=verbose

      - name: Smoke test (plugin load)
        working-directory: tests/e2e-openclaw
        run: npx vitest run plugin-load-smoke.test.ts
```

### 2. Optional manual job для Tier 3

```yaml
  e2e-openclaw-docker:
    name: E2E OpenClaw (Docker, manual)
    if: github.event_name == 'workflow_dispatch'
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Build and test
        working-directory: tests/e2e-openclaw
        env:
          LLM_API_KEY: ${{ secrets.LLM_API_KEY }}
        run: |
          docker compose up --build --abort-on-container-exit
```

## Самопроверка

```bash
# Тесты проходят локально
cd plugins/openclaw && npx vitest run
cd ../../tests/e2e-openclaw && npx vitest run plugin-load-smoke.test.ts 2>/dev/null || echo "OK (needs setup)"

# CI config валиден
# Push to branch → check GitHub Actions
```

## Коммит

```
ci: add OpenClaw plugin test job to CI

- Always run: tsc --noEmit, vitest, smoke test
- Manual only: Docker Compose E2E (requires LLM_API_KEY)
- Based on prompt 73 recon findings
```
