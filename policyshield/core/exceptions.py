"""PolicyShield custom exceptions."""


class PolicyShieldParseError(Exception):
    """Raised when a YAML rule file cannot be parsed or is invalid."""

    def __init__(self, message: str, file_path: str | None = None):
        self.file_path = file_path
        if file_path:
            message = f"{file_path}: {message}"
        super().__init__(message)


class PolicyShieldError(Exception):
    """Base exception for PolicyShield runtime errors."""


class ApprovalRequiredError(PolicyShieldError):
    """Raised when a tool call requires human approval.

    Attributes:
        approval_id: Unique identifier for polling approval status.
        message: Human-readable description of the approval requirement.
    """

    def __init__(self, message: str, approval_id: str = "") -> None:
        self.approval_id = approval_id
        super().__init__(message)
