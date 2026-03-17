"""CLI-based approval backend: prints request and reads y/n from stdin."""

from __future__ import annotations

import sys

from policyshield.approval.base import (
    ApprovalBackend,
    ApprovalRequest,
    ApprovalResponse,
)


class CLIBackend(ApprovalBackend):
    """CLI-based approval: prints request and reads y/n from stdin."""

    def __init__(
        self,
        input_func=None,
        output_file=None,
    ) -> None:
        """Initialize CLIBackend.

        Args:
            input_func: Custom input function (for testing). Defaults to builtins.input.
            output_file: File to write output to. Defaults to sys.stdout.
        """
        self._input_func = input_func or input
        self._output = output_file or sys.stdout
        self._pending: dict[str, ApprovalRequest] = {}
        self._responses: dict[str, ApprovalResponse] = {}

    def submit(self, request: ApprovalRequest) -> None:
        self._pending[request.request_id] = request
        self._output.write("\n🛡️ APPROVE REQUIRED\n")
        self._output.write(f"   Tool: {request.tool_name}\n")
        self._output.write(f"   Args: {request.args}\n")
        self._output.write(f"   Rule: {request.rule_id}\n")
        self._output.write(f"   Message: {request.message}\n")
        self._output.flush()

    def wait_for_response(
        self, request_id: str, timeout: float = 300.0
    ) -> ApprovalResponse | None:
        # Check if already responded programmatically
        if request_id in self._responses:
            self._pending.pop(request_id, None)
            return self._responses.pop(request_id)

        try:
            answer = self._input_func("   Approve? [y/N]: ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            answer = "n"

        approved = answer in ("y", "yes")
        response = ApprovalResponse(
            request_id=request_id,
            approved=approved,
            responder="cli",
        )
        self._pending.pop(request_id, None)
        return response

    def respond(
        self,
        request_id: str,
        approved: bool,
        responder: str = "",
        comment: str = "",
    ) -> None:
        self._responses[request_id] = ApprovalResponse(
            request_id=request_id,
            approved=approved,
            responder=responder or "cli",
            comment=comment,
        )
        self._pending.pop(request_id, None)

    def pending(self) -> list[ApprovalRequest]:
        return list(self._pending.values())
