# Промпт 04 — PII-детектор (L0, regex)

## Контекст

Модели данных (`PIIType`, `PIIMatch`) созданы в промпте 02. Теперь нужно реализовать L0 PII-детектор на основе regex-паттернов. Спецификация — раздел 5 `TECHNICAL_SPEC.md`.

Детектор будет вызываться из ShieldEngine (промпт 08), но разрабатывается и тестируется полностью автономно.

## Задача

Создай файл `policyshield/shield/pii.py`:

### Класс `PIIDetector`

**Конструктор:**
- Принимает `custom_patterns: dict[str, str] | None = None` — дополнительные (пользовательские) regex-паттерны. Ключ — имя паттерна, значение — regex-строка.
- Компилирует все паттерны в `re.Pattern` объекты **один раз** в конструкторе (не при каждом вызове).

**Встроенные паттерны (минимум 9 типов):**
- `EMAIL`: стандартный email (local@domain.tld)
- `PHONE`: международный формат (+1-234-567-8901, +7 999 123 45 67, и подобные)
- `CREDIT_CARD`: 13-19 цифр с разделителями (пробелы, дефисы, без разделителей). Добавь проверку алгоритмом Луна для снижения false positives.
- `SSN`: формат XXX-XX-XXXX
- `IBAN`: 2 буквы + 2 цифры + до 30 алфанумерических
- `IP_ADDRESS`: IPv4 (четыре октета, каждый 0-255)
- `PASSPORT`: буква(ы) + 6-9 цифр (упрощённый)
- `DATE_OF_BIRTH`: форматы dd.mm.yyyy, dd/mm/yyyy, yyyy-mm-dd
- `CUSTOM`: пользовательские паттерны из `custom_patterns`

**Метод `scan(text: str, field_name: str = "") -> list[PIIMatch]`:**
- Проходит по тексту всеми скомпилированными паттернами
- Для каждого совпадения создаёт `PIIMatch` с `pii_type`, `field`, `span`, `masked_value`
- Возвращает список всех найденных PII, отсортированный по позиции

**Метод `scan_dict(data: dict, fields: list[str] | None = None) -> list[PIIMatch]`:**
- Сканирует значения словаря. Если `fields` указан — только эти ключи, иначе все строковые значения.
- Для вложенных словарей — рекурсивно (field_name через точку: `"args.command"`)
- Для списков — сканировать каждый элемент

**Статический метод `mask(value: str, pii_match: PIIMatch) -> str`:**
- Маскирует найденный PII в строке: `john@corp.com` → `j***@c***.com`, `4111111111111111` → `4111****1111`, `123-45-6789` → `***-**-6789`
- Логика маскировки зависит от типа PII

## Тесты

Напиши `tests/test_pii.py`:

1. **Email** — `"Contact john@corp.com for info"` → находит 1 PIIMatch, type=EMAIL
2. **Phone** — `"+7 999 123 45 67"` → PIIMatch, type=PHONE
3. **Credit card (с Luhn)** — `"4111 1111 1111 1111"` → PIIMatch, type=CREDIT_CARD. Но `"1234 5678 9012 3456"` (не проходит Luhn) → пустой список
4. **SSN** — `"SSN: 123-45-6789"` → PIIMatch, type=SSN
5. **Несколько PII в одном тексте** — `"Email john@x.com, CC 4111111111111111"` → 2 PIIMatch
6. **scan_dict** — `{"command": "curl -u john@x.com", "path": "/tmp"}` → 1 PIIMatch с field="command"
7. **scan_dict nested** — `{"args": {"query": "SSN 123-45-6789"}}` → PIIMatch с field="args.query"
8. **Маскировка** — проверить mask() для email, CC, SSN
9. **Custom pattern** — `PIIDetector(custom_patterns={"order_id": r"ORD-\d{6}"})`, текст `"Order ORD-123456"` → PIIMatch, type=CUSTOM
10. **Пустой текст** — `scan("")` → пустой список
11. **Текст без PII** — `scan("hello world")` → пустой список

## Защитные условия

- Не импортируй ничего из `policyshield.shield` (кроме моделей из `core`) — PII-детектор автономен
- Все предыдущие тесты должны проходить

## Проверки перед коммитом

```bash
ruff check policyshield/
pytest tests/ -v
```

## Коммит

```
git add -A && git commit -m "feat(shield): L0 PII detector — 9 types, Luhn, scan_dict, masking"
```
