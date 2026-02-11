# Prompt 03 — Advanced PII Patterns

## Цель

Расширить PII-детектор: добавить RU-специфичные паттерны (ИНН, СНИЛС, телефон RU, паспорт РФ), поддержку кастомных паттернов из YAML-конфига, и улучшить точность существующих паттернов.

## Контекст

- Существующий PII: `policyshield/shield/pii.py` — `PIIDetector`, `BUILTIN_PATTERNS`
- Модели: `PIIType`, `PIIMatch` в `models.py`
- Текущие паттерны: EMAIL, PHONE, CREDIT_CARD, SSN, IBAN, IP_ADDRESS, PASSPORT, DATE_OF_BIRTH

## Что сделать

### 1. Добавить новые PIIType в `models.py`

```python
class PIIType(str, Enum):
    # ... existing ...
    INN = "INN"              # ИНН (10 или 12 цифр)
    SNILS = "SNILS"          # СНИЛС (XXX-XXX-XXX YY)
    RU_PASSPORT = "RU_PASSPORT"  # Паспорт РФ (серия + номер, 4 + 6 цифр)
    RU_PHONE = "RU_PHONE"    # +7 (XXX) XXX-XX-XX
```

### 2. Добавить паттерны в `pii.py`

```python
# Russian PII patterns
RU_PATTERNS: list[PIIPattern] = [
    PIIPattern(
        pii_type=PIIType.INN,
        pattern=re.compile(r"\b\d{10}(?:\d{2})?\b"),  # 10 или 12 цифр
        label="inn",
    ),
    PIIPattern(
        pii_type=PIIType.SNILS,
        pattern=re.compile(r"\b\d{3}-\d{3}-\d{3}\s?\d{2}\b"),
        label="snils",
    ),
    PIIPattern(
        pii_type=PIIType.RU_PASSPORT,
        pattern=re.compile(r"\b\d{2}\s?\d{2}\s?\d{6}\b"),
        label="ru_passport",
    ),
    PIIPattern(
        pii_type=PIIType.RU_PHONE,
        pattern=re.compile(r"(?:\+7|8)[\s-]?\(?\d{3}\)?[\s-]?\d{3}[\s-]?\d{2}[\s-]?\d{2}\b"),
        label="ru_phone",
    ),
]
```

Добавить в `BUILTIN_PATTERNS` по умолчанию.

### 3. Добавить валидацию ИНН

Аналогично `_luhn_check` для кредитных карт, добавить `_inn_check(digits: str) -> bool`:
- ИНН 10 цифр: контрольная сумма по 10-й цифре
- ИНН 12 цифр: контрольная сумма по 11-й и 12-й цифрам
- Коэффициенты: `[2,4,10,3,5,9,4,6,8]` для 10-значного

### 4. Кастомные PII-паттерны из YAML

Добавить поддержку секции `pii_patterns` в YAML-файле правил:

```yaml
shield_name: my-rules
version: 1

pii_patterns:
  - type: CUSTOM
    label: "internal_employee_id"
    pattern: "EMP-\\d{6}"
  - type: CUSTOM
    label: "api_key"
    pattern: "sk-[a-zA-Z0-9]{32,}"

rules:
  - id: no-leaking-api-keys
    ...
```

**Реализация:**
- В `parser.py`: парсить `pii_patterns` секцию, создавать `PIIPattern` объекты
- Добавить `custom_pii_patterns: list[PIIPattern]` в `RuleSet`
- В `ShieldEngine.__init__()`: передавать custom patterns в `PIIDetector`

### 5. Тесты: обновить `tests/test_pii.py`

Добавить минимум 12 тестов:

```
test_detect_inn_10_digits                 — "ИНН: 7707049388" → INN
test_detect_inn_12_digits                 — "ИНН: 500100732259" → INN
test_inn_invalid_checksum                 — "ИНН: 1234567890" → не детектится
test_detect_snils                         — "СНИЛС: 112-233-445 95" → SNILS
test_detect_ru_passport                   — "Паспорт: 45 12 654321" → RU_PASSPORT
test_detect_ru_phone_plus7                — "+7 (925) 123-45-67" → RU_PHONE
test_detect_ru_phone_8                    — "8-925-123-45-67" → RU_PHONE
test_no_false_positive_short_number       — "12345" → не детектится как INN
test_custom_pattern_from_yaml             — YAML с custom pii_patterns → детектится
test_custom_pattern_api_key               — "sk-abc123..." → CUSTOM
test_masking_inn                          — ИНН маскируется корректно
test_redact_dict_with_ru_pii              — redact_dict с RU PII → значения замаскированы
```

## Самопроверки

```bash
# Все тесты проходят
pytest tests/ -q

# Lint чист
ruff check policyshield/ tests/

# Coverage ≥ 85%
pytest tests/ --cov=policyshield --cov-fail-under=85

# Ручная проверка
python -c "
from policyshield.shield.pii import PIIDetector
d = PIIDetector()
print(d.scan('ИНН: 7707049388'))
print(d.scan('+7 (925) 123-45-67'))
print(d.scan('sk-abcdefghijklmnopqrstuvwxyz123456'))  # не custom, пока
"
```

## Коммит

```
feat(pii): add RU patterns (INN, SNILS, passport, phone) and custom YAML patterns

- Add INN/SNILS/RU_PASSPORT/RU_PHONE PIIType enums and patterns
- Add INN checksum validation (10-digit and 12-digit)
- Support custom pii_patterns section in YAML rules
- Add 12+ tests for new PII patterns
```
