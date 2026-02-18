# Prompt 61 — Repo Cleanup

## Цель

Удалить клон `openclaw/` (5167 файлов) из репо, добавить в `.gitignore`, вычистить ссылки на неправильный upstream.

## Контекст

- `openclaw/` — полный клон репозитория `github.com/openclaw/openclaw`, занимает ~70% файлов проекта
- Был склонирован как reference для чтения типов — больше не нужен после синхронизации стубов
- В `openclaw-plugin-sdk.d.ts` строка 8 ссылается на `github.com/nicepkg/openclaw` — это неправильный репо

## Что сделать

### 1. Удалить `openclaw/`

```bash
rm -rf openclaw/
```

### 2. Добавить в `.gitignore`

Добавить в корневой `.gitignore`:

```
# OpenClaw source (reference clone, not part of this project)
/openclaw/
```

### 3. Исправить ссылку в `openclaw-plugin-sdk.d.ts`

Строка 8 — заменить:
```
 * Source of truth: https://github.com/nicepkg/openclaw → src/plugins/types.ts
```
На:
```
 * Source of truth: https://github.com/openclaw/openclaw → src/plugins/types.ts
```

### 4. Поиск других ссылок на `nicepkg`

```bash
grep -r "nicepkg" --include="*.ts" --include="*.md" --include="*.json" --include="*.yaml" .
```

Заменить все найденные `nicepkg/openclaw` → `openclaw/openclaw`.

## Самопроверка

```bash
# Убедиться что openclaw/ удалён
test ! -d openclaw/ && echo OK

# Убедиться что .gitignore содержит openclaw/
grep -q "/openclaw/" .gitignore && echo OK

# Нет ссылок на nicepkg
grep -r "nicepkg" --include="*.ts" --include="*.md" --include="*.json" . | wc -l  # должно быть 0

# Python тесты всё ещё проходят
pytest tests/ -q

# TypeScript type check
cd plugins/openclaw && npx tsc --noEmit
```

## Коммит

```
chore: remove openclaw/ reference clone, fix upstream URL

- Remove 5167-file openclaw/ directory (was reference clone)
- Add /openclaw/ to .gitignore
- Fix all references from nicepkg/openclaw to openclaw/openclaw
```
