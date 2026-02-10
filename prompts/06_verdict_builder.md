# Промпт 06 — Counterexample Builder (Verdict Builder)

## Контекст

Matcher (промпт 05) определяет, какое правило сработало и какой вердикт. Теперь нужен компонент, который формирует **структурированный текстовый ответ** для агента — counterexample. Это ключевой механизм repair loop: агент получает не "Error", а объяснение *что заблокировано, почему и как исправить*. Спецификация — раздел 6 `TECHNICAL_SPEC.md`.

## Задача

Создай файл `policyshield/shield/verdict.py`:

### Класс `VerdictBuilder`

Stateless-класс. Все методы принимают данные и возвращают `ShieldResult`.

**Метод `build_allow(rule_id: str | None = None) -> ShieldResult`:**
- Создаёт ShieldResult(verdict=ALLOW, rule_id=rule_id, message="")

**Метод `build_block(rule: RuleConfig, tool_name: str, args: dict, pii_matches: list[PIIMatch] | None = None) -> ShieldResult`:**

Формирует counterexample. Формат message:

```
🛡️ BLOCKED by PolicyShield
Rule: {rule.id}
Tool: {tool_name}
Reason: {rule.description or rule.message or "Policy violation"}

{если pii_matches не пустой:}
Detected PII: {перечислить типы через запятую}

Suggestion: {rule.message or сгенерировать default suggestion на основе rule и tool}
```

Default suggestions (если `rule.message` не задан):
- Для PII-блокировки: `"Remove or redact PII data before making this call."`
- Для tool = exec с regex на деструктивные команды: `"Use a non-destructive alternative."`
- Для rate limit: `"Too many calls to {tool_name}. Wait or reduce frequency."`
- Fallback: `"Reformulate your request to comply with active policies."`

**Метод `build_redact(rule: RuleConfig, tool_name: str, original_args: dict, modified_args: dict, pii_matches: list[PIIMatch]) -> ShieldResult`:**
- Создаёт ShieldResult с verdict=REDACT, сохраняет original и modified args

**Метод `build_approve_pending(rule: RuleConfig, tool_name: str, args: dict) -> ShieldResult`:**
- Создаёт ShieldResult с verdict=APPROVE, message описывает ожидание подтверждения

**Метод `format_counterexample(result: ShieldResult) -> str`:**
- Преобразует ShieldResult в финальную строку, которая вернётся агенту как "tool result". AgentLoop nanobot просто увидит эту строку как ответ от tool — ему не нужно знать о PolicyShield. LLM прочитает и перепланирует.

## Тесты

Напиши `tests/test_verdict.py`:

1. **build_allow** — проверить verdict=ALLOW, пустой message
2. **build_block с rule.message** — message содержит rule.message, tool_name, rule.id
3. **build_block без message, с PII** — message содержит "Detected PII" и default suggestion
4. **build_block default suggestion** — при отсутствии message генерируется fallback
5. **build_redact** — original_args и modified_args сохранены в ShieldResult
6. **build_approve_pending** — verdict=APPROVE, message содержит ожидание
7. **format_counterexample** — проверить что возвращает непустую строку, содержащую "BLOCKED" и rule id
8. **Roundtrip** — build_block → format_counterexample → строка содержит все ключевые элементы (rule id, tool, reason)

## Защитные условия

- VerdictBuilder не зависит от Matcher или PIIDetector — использует только модели из core
- Все предыдущие тесты проходят

## Проверки перед коммитом

```bash
ruff check policyshield/
pytest tests/ -v
```

## Коммит

```
git add -A && git commit -m "feat(shield): verdict builder — counterexample generation for repair loop"
```
