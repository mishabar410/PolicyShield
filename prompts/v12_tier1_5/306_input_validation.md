# Prompt 306 — Input Validation

## Цель

Валидировать входные данные через Pydantic constraints: `tool_name` pattern, max length, args depth limit. Предотвратить injection через имя тула и JSON bomb через вложенные args.

## Контекст

- `CheckRequest.tool_name: str` — без ограничений: принимается пустая строка, 10MB строка, null-bytes, shell metacharacters
- `args: dict` — принимается бесконечно вложенный dict (JSON bomb)
- Нужно: `tool_name` = `[\w.\-:]+`, 1–256 chars; `args` depth ≤ 10

## Что сделать

### 1. Обновить `models.py`

```python
from pydantic import BaseModel, Field, field_validator

def _check_depth(obj: object, max_depth: int = 10, current: int = 0) -> None:
    """Reject deeply nested structures (bomb prevention)."""
    if current > max_depth:
        raise ValueError(f"Nesting exceeds max depth ({max_depth})")
    if isinstance(obj, dict):
        for val in obj.values():
            _check_depth(val, max_depth, current + 1)
    elif isinstance(obj, (list, tuple)):
        for item in obj:
            _check_depth(item, max_depth, current + 1)

class CheckRequest(BaseModel):
    tool_name: str = Field(..., min_length=1, max_length=256, pattern=r"^[\w.\-:]+$")
    args: dict = {}
    session_id: str = Field(default="default", min_length=1, max_length=256)
    sender: str | None = Field(default=None, max_length=256)
    request_id: str | None = Field(default=None, max_length=128)

    @field_validator("args")
    @classmethod
    def validate_args_depth(cls, v: dict) -> dict:
        _check_depth(v)
        return v
```

### 2. Аналогично обновить `PostCheckRequest`

```python
class PostCheckRequest(BaseModel):
    tool_name: str = Field(..., min_length=1, max_length=256, pattern=r"^[\w.\-:]+$")
    args: dict = {}
    result: str = Field(default="", max_length=1_000_000)  # 1MB max result
    session_id: str = Field(default="default", min_length=1, max_length=256)
```

## Тесты

```python
class TestInputValidation:
    def test_valid_tool_name(self, client):
        resp = client.post("/api/v1/check", json={"tool_name": "send_email"})
        assert resp.status_code in (200, 422)  # 200 if rule matched, 422 only if format wrong

    def test_empty_tool_name_rejected(self, client):
        resp = client.post("/api/v1/check", json={"tool_name": ""})
        assert resp.status_code == 422

    def test_too_long_tool_name_rejected(self, client):
        resp = client.post("/api/v1/check", json={"tool_name": "a" * 300})
        assert resp.status_code == 422

    def test_special_chars_rejected(self, client):
        resp = client.post("/api/v1/check", json={"tool_name": "rm -rf /"})
        assert resp.status_code == 422

    def test_dots_colons_allowed(self, client):
        resp = client.post("/api/v1/check", json={"tool_name": "my.tool:v2-beta"})
        assert resp.status_code != 422

    def test_deeply_nested_args_rejected(self, client):
        nested = {"a": {}}
        current = nested["a"]
        for _ in range(15):
            current["b"] = {}
            current = current["b"]
        resp = client.post("/api/v1/check", json={"tool_name": "test", "args": nested})
        assert resp.status_code == 422

    def test_normal_depth_accepted(self, client):
        resp = client.post("/api/v1/check", json={"tool_name": "test", "args": {"a": {"b": {"c": 1}}}})
        assert resp.status_code != 422
```

## Самопроверка

```bash
pytest tests/test_server_hardening.py::TestInputValidation -v
pytest tests/ -q
```

## Коммит

```
feat(server): add input validation (tool_name pattern, args depth limit)

- tool_name: [\w.\-:]+ pattern, 1-256 chars
- args: max nesting depth 10 (JSON bomb prevention)
- session_id/sender: max 256 chars
```
