# Prompt 66 — npm Package Setup

## Цель

Подготовить `plugins/openclaw/` к публикации на npm: правильные metadata, build pipeline, publish-ready конфигурация.

## Контекст

- Текущий `package.json` имеет `name: "@policyshield/openclaw-plugin"` и `version: "0.7.0"`
- В ROADMAP v1.0 записано: «OpenClaw plugin published to npm»
- Пользователь OpenClaw должен иметь возможность сделать `npm install @policyshield/openclaw-plugin`
- Twitch extension (reference plugin) — `openclaw/extensions/twitch/` — использует `openclaw/plugin-sdk` для импортов

## Что сделать

### 1. Обновить `package.json`

```json
{
    "name": "@policyshield/openclaw-plugin",
    "version": "0.8.0",
    "description": "PolicyShield runtime policy enforcement plugin for OpenClaw",
    "license": "MIT",
    "repository": {
        "type": "git",
        "url": "https://github.com/<owner>/PolicyShield",
        "directory": "plugins/openclaw"
    },
    "keywords": ["openclaw", "policyshield", "security", "policy", "ai-agent", "tool-call"],
    "main": "dist/index.js",
    "types": "dist/index.d.ts",
    "type": "module",
    "files": [
        "dist/",
        "openclaw.plugin.json",
        "README.md"
    ],
    "scripts": {
        "build": "tsc",
        "test": "vitest run",
        "test:watch": "vitest",
        "typecheck": "tsc --noEmit",
        "prepublishOnly": "npm run build"
    },
    "devDependencies": {
        "typescript": "^5.0.0",
        "vitest": "^2.0.0"
    },
    "openclaw": {
        "pluginId": "policyshield",
        "configFile": "openclaw.plugin.json"
    }
}
```

### 2. Обновить `tsconfig.json`

Убедиться что:
- `outDir: "dist"`
- `declaration: true` (генерировать .d.ts)
- `declarationMap: true`
- `sourceMap: true`
- `target: "ESNext"` (или "ES2022")
- `module: "ESNext"` (или "Node16")
- `moduleResolution: "Node16"` (или "Bundler")

```json
{
    "compilerOptions": {
        "target": "ES2022",
        "module": "Node16",
        "moduleResolution": "Node16",
        "outDir": "dist",
        "declaration": true,
        "declarationMap": true,
        "sourceMap": true,
        "strict": true,
        "esModuleInterop": true,
        "skipLibCheck": true,
        "forceConsistentCasingInFileNames": true
    },
    "include": ["src"],
    "exclude": ["dist", "tests", "node_modules"]
}
```

### 3. Добавить `.npmignore`

```
src/
tests/
tsconfig.json
vitest.config.ts
.gitignore
```

### 4. Проверить build

```bash
cd plugins/openclaw
npm run build
ls dist/  # должны быть: index.js, index.d.ts, client.js, client.d.ts, types.js, types.d.ts
```

### 5. Dry-run publish

```bash
npm pack --dry-run  # показывает что попадёт в пакет
```

Проверить что:
- `dist/` включён
- `src/` НЕ включён
- `tests/` НЕ включён
- `openclaw.plugin.json` включён
- `openclaw-plugin-sdk.d.ts` включён (в dist)

## Самопроверка

```bash
cd plugins/openclaw

# Build clean
rm -rf dist && npm run build

# Type check
npx tsc --noEmit

# Tests still pass
npm test

# Package preview
npm pack --dry-run 2>&1 | head -30

# No src/ in package
npm pack --dry-run 2>&1 | grep -c "src/"  # 0
```

## Коммит

```
build(plugin): prepare npm package for publishing

- Update package.json with proper metadata, files, and scripts
- Configure tsconfig for declaration output
- Add .npmignore to exclude source and tests
- Verify build produces correct dist/ output
```
