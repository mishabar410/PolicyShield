# Prompt 05 — Approval Backend (ABC)

## Цель

Реализовать абстрактный `ApprovalBackend` и конкретные реализации (`InMemoryBackend`, `CLIBackend`) для human-in-the-loop APPROVE вердикта. Когда правило возвращает `then: approve`, ShieldEngine должен запросить одобрение у человека и подождать ответа.

## Контекст

- `Verdict.APPROVE` уже есть в `models.py`, но не реализован — сейчас просто возвращается как вердикт, ничего не ждёт
- Цель: когда `verdict == APPROVE`, ShieldEngine отправляет запрос на одобрение и блокирует до получения ответа (или таймаута)

## Что сделать

### 1. Создать `policyshield/approval/__init__.py`

Экспорт: `ApprovalBackend`, `ApprovalRequest`, `ApprovalResponse`, `InMemoryBackend`, `CLIBackend`

### 2. Создать `policyshield/approval/base.py`

```python
from abc import ABC, abstractmethod

@dataclass(frozen=True)
class ApprovalRequest:
    """A request for human approval."""
    request_id: str            # UUID
    tool_name: str
    args: dict
    rule_id: str
    message: str
    session_id: str
    timestamp: datetime
    
@dataclass(frozen=True)
class ApprovalResponse:
    """Human response to an approval request."""
    request_id: str
    approved: bool
    responder: str = ""        # кто одобрил
    comment: str = ""          # комментарий
    timestamp: datetime = field(default_factory=datetime.utcnow)

class ApprovalBackend(ABC):
    """Abstract base for approval backends."""
    
    @abstractmethod
    def submit(self, request: ApprovalRequest) -> None:
        """Submit an approval request."""
        
    @abstractmethod
    def wait_for_response(
        self, request_id: str, timeout: float = 300.0
    ) -> ApprovalResponse | None:
        """Wait for a response to an approval request.
        
        Returns None on timeout.
        """
    
    @abstractmethod
    def respond(self, request_id: str, approved: bool, responder: str = "", comment: str = "") -> None:
        """Submit a response to an approval request (for testing / programmatic use)."""
    
    @abstractmethod
    def pending(self) -> list[ApprovalRequest]:
        """Return all pending (unanswered) requests."""
```

### 3. Создать `policyshield/approval/memory.py`

`InMemoryBackend` — хранит requests/responses в `dict`. `wait_for_response` использует `threading.Event` для блокировки.

```python
class InMemoryBackend(ApprovalBackend):
    """In-memory approval backend for testing and simple use cases."""
    
    def submit(self, request): ...
    def wait_for_response(self, request_id, timeout=300.0): ...
    def respond(self, request_id, approved, responder="", comment=""): ...
    def pending(self): ...
```

### 4. Создать `policyshield/approval/cli_backend.py`

`CLIBackend` — при `submit()` выводит запрос в stdout и ждёт ввода `y/n` от пользователя через stdin.

```python
class CLIBackend(ApprovalBackend):
    """CLI-based approval: prints request and reads y/n from stdin."""
    
    def submit(self, request):
        print(f"\n🛡️ APPROVE REQUIRED")
        print(f"   Tool: {request.tool_name}")
        print(f"   Args: {request.args}")
        print(f"   Rule: {request.rule_id}")
        print(f"   Message: {request.message}")
    
    def wait_for_response(self, request_id, timeout=300.0):
        # Использует threading.Timer для таймаута
        answer = input("   Approve? [y/N]: ").strip().lower()
        approved = answer in ("y", "yes")
        return ApprovalResponse(request_id=request_id, approved=approved, responder="cli")
```

### 5. Интеграция в `ShieldEngine`

- Новый параметр: `approval_backend: ApprovalBackend | None = None`
- В `_do_check()`: если вердикт == APPROVE и backend сконфигурирован:
  1. Создать `ApprovalRequest`
  2. `backend.submit(request)`
  3. `response = backend.wait_for_response(request.request_id, timeout=approval_timeout)`
  4. Если `response is None` (таймаут) → вернуть BLOCK с сообщением "Approval timed out"
  5. Если `response.approved` → вернуть ALLOW
  6. Если `not response.approved` → вернуть BLOCK с сообщением "Approval denied by {responder}"
- Если backend не сконфигурирован и verdict == APPROVE → вернуть BLOCK с сообщением "No approval backend configured"
- Новый параметр: `approval_timeout: float = 300.0`
- Trace: записывать approval requests/responses

### 6. Тесты: `tests/test_approval.py`

Минимум 14 тестов:

```
test_in_memory_submit_and_respond          — submit → respond → wait returns response
test_in_memory_approve                     — respond(approved=True) → ApprovalResponse.approved == True
test_in_memory_deny                        — respond(approved=False) → approved == False
test_in_memory_timeout                     — wait_for_response без respond → None (timeout 0.5)
test_in_memory_pending                     — submit 3 requests → pending() returns 3
test_in_memory_respond_clears_pending      — respond → pending count decreases

test_engine_approve_verdict_approved       — правило approve + respond(True) → ALLOW
test_engine_approve_verdict_denied         — правило approve + respond(False) → BLOCK
test_engine_approve_timeout_blocks         — правило approve + timeout → BLOCK
test_engine_no_backend_blocks              — правило approve + нет backend → BLOCK
test_engine_approve_traced                 — approval request записан в trace

test_cli_backend_approve                   — stdin="y" → approved
test_cli_backend_deny                      — stdin="n" → denied
test_approval_request_serialization        — request → dict → request round-trip
```

## Самопроверки

```bash
pytest tests/ -q
ruff check policyshield/ tests/
pytest tests/ --cov=policyshield --cov-fail-under=85

# Ручная проверка
python -c "
from policyshield.approval import InMemoryBackend, ApprovalRequest
from datetime import datetime
import uuid

backend = InMemoryBackend()
req = ApprovalRequest(
    request_id=str(uuid.uuid4()), tool_name='exec',
    args={'command': 'curl https://api.com'}, rule_id='approve-downloads',
    message='Downloads require approval', session_id='s1',
    timestamp=datetime.utcnow()
)
backend.submit(req)
print(f'Pending: {len(backend.pending())}')
backend.respond(req.request_id, approved=True, responder='admin')
resp = backend.wait_for_response(req.request_id, timeout=1.0)
print(f'Approved: {resp.approved}')
"
```

## Коммит

```
feat(approve): add ApprovalBackend ABC with InMemory and CLI backends

- Add ApprovalBackend abstract class with submit/wait/respond API
- Add InMemoryBackend for testing and programmatic use
- Add CLIBackend for interactive terminal approval
- Integrate approval flow into ShieldEngine for APPROVE verdict
- Add 14+ tests for approval backends and engine integration
```
