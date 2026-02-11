# Prompt 06 — Telegram Approval Backend

## Цель

Реализовать `TelegramApprovalBackend` — отправка запроса на одобрение в Telegram чат/группу через Bot API, ожидание ответа по callback кнопкам (Approve ✅ / Deny ❌).

## Контекст

- `ApprovalBackend` ABC из Prompt 05
- Telegram Bot API: https://core.telegram.org/bots/api
- Нужна зависимость `httpx` (async-capable HTTP client) — добавить как optional dependency

## Что сделать

### 1. Добавить optional dependency

В `pyproject.toml`:
```toml
[project.optional-dependencies]
telegram = ["httpx>=0.25"]
dev = [
    "pytest",
    "pytest-asyncio",
    "pytest-cov",
    "ruff",
    "httpx>=0.25",  # для тестов telegram backend
]
```

### 2. Создать `policyshield/approval/telegram.py`

```python
class TelegramApprovalBackend(ApprovalBackend):
    """Telegram Bot API approval backend.
    
    Sends approval requests as messages with inline keyboard buttons
    and processes callback queries for approve/deny actions.
    
    Args:
        bot_token: Telegram Bot API token
        chat_id: Target chat/group ID for approval messages
        api_base: Base URL for Telegram API (for testing/mocking)
        poll_interval: Seconds between polling for updates
    """
    
    def __init__(
        self,
        bot_token: str,
        chat_id: int | str,
        api_base: str = "https://api.telegram.org",
        poll_interval: float = 2.0,
    ): ...
    
    def submit(self, request: ApprovalRequest) -> None:
        """Send approval message to Telegram with inline keyboard."""
        # POST /bot{token}/sendMessage
        # text: formatted approval request
        # reply_markup: InlineKeyboardMarkup with Approve/Deny buttons
        # callback_data: {request_id}:approve / {request_id}:deny
    
    def wait_for_response(self, request_id: str, timeout: float = 300.0) -> ApprovalResponse | None:
        """Poll Telegram for callback query updates."""
        # GET /bot{token}/getUpdates с offset
        # Фильтровать callback_query по request_id в callback_data
        # Ответить на callback: POST answerCallbackQuery + editMessageText
    
    def respond(self, request_id: str, approved: bool, **kw) -> None:
        """Programmatic response (for testing), sets internal event."""
    
    def pending(self) -> list[ApprovalRequest]:
        """Return pending requests."""
    
    def _format_message(self, request: ApprovalRequest) -> str:
        """Format the approval request as a Telegram message."""
        return (
            f"🛡️ *PolicyShield Approval Request*\n\n"
            f"*Tool:* `{request.tool_name}`\n"
            f"*Args:* `{request.args}`\n"
            f"*Rule:* `{request.rule_id}`\n"
            f"*Message:* {request.message}\n"
            f"*Session:* `{request.session_id}`\n"
        )
```

**Важно:**
- Все HTTP-вызовы через `httpx.Client` (sync)
- `wait_for_response` — polling loop с `getUpdates` и offset tracking
- При получении callback — `answerCallbackQuery` + `editMessageText` (добавить статус "✅ Approved by @user")
- Thread-safe: `threading.Event` для координации

### 3. Тесты: `tests/test_telegram_approval.py`

Используем mock HTTP server (responses library or httpx mocking).

Минимум 8 тестов:

```
test_submit_sends_message                  — submit() → HTTP POST sendMessage вызван
test_submit_message_format                 — проверить текст и InlineKeyboard в payload
test_wait_approve_callback                 — мок getUpdates с approve callback → approved
test_wait_deny_callback                    — мок getUpdates с deny callback → denied
test_wait_timeout_returns_none             — timeout без ответа → None
test_answer_callback_called                — при получении callback → answerCallbackQuery вызван
test_edit_message_on_response              — при получении callback → editMessageText вызван
test_import_error_without_httpx            — без httpx установленного → ImportError с подсказкой
```

**Мокирование:** использовать `unittest.mock.patch` для `httpx.Client.post`/`httpx.Client.get` или `respx` library.

### 4. CLI: `policyshield approve list`

Добавить подкоманду `approve` с:
- `policyshield approve list --telegram --token=TOKEN --chat-id=ID` — показать pending requests
- Информационная команда, без approve/deny (для этого используется Telegram UI)

## Самопроверки

```bash
pytest tests/ -q
ruff check policyshield/ tests/
pytest tests/ --cov=policyshield --cov-fail-under=85

# Проверить что без httpx выбрасывается нормальная ошибка
python -c "
try:
    from policyshield.approval.telegram import TelegramApprovalBackend
    print('httpx available')
except ImportError as e:
    print(f'Expected error: {e}')
"
```

## Коммит

```
feat(telegram): add Telegram Bot API approval backend

- Add TelegramApprovalBackend using Bot API sendMessage + getUpdates
- Inline keyboard with Approve/Deny buttons
- Add httpx as optional dependency [telegram]
- Add 8+ tests with mocked HTTP calls
```
