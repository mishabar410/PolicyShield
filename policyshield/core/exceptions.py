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
