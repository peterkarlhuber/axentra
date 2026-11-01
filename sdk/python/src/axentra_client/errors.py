"""Exceptions raised by the Axentra client."""

from __future__ import annotations

from typing import Any


class AxentraError(Exception):
    """Base class of every exception this package raises."""


class AxentraApiError(AxentraError):
    """A non-2xx answer (RFC 9457 problem details).

    ``code`` is stable and machine readable (``validation_failed``, ``unauthenticated``,
    ``forbidden``, ``not_found``, ``conflict``, ``precondition_failed``, ``rate_limited``,
    ``quota_exceeded``, ``mode_not_supported``, ``internal``, ...). Treat unknown codes like their
    HTTP status.
    """

    def __init__(
        self,
        status: int,
        code: str,
        *,
        title: str = "",
        detail: str = "",
        request_id: str | None = None,
        errors: list[dict[str, Any]] | None = None,
        problem: dict[str, Any] | None = None,
        retry_after: int | None = None,
    ) -> None:
        super().__init__(f"{status} {code}" + (f": {detail}" if detail else ""))
        self.status = status
        self.code = code
        self.title = title
        self.detail = detail
        self.request_id = request_id
        self.errors = errors or []
        self.problem = problem or {}
        self.retry_after = retry_after

    def __repr__(self) -> str:
        return f"AxentraApiError(status={self.status}, code={self.code!r}, request_id={self.request_id!r})"


class IncompatibleApiError(AxentraError):
    """The server's API version cannot serve this client (different major or lower minor)."""

    def __init__(self, reason: str, server: tuple[int, int] | None, required: tuple[int, int]) -> None:
        want = f"{required[0]}.{required[1]}"
        got = f"{server[0]}.{server[1]}" if server else "an unreadable version"
        if reason == "major_mismatch":
            why = f"the server speaks API {got}, but this client needs major version {required[0]}"
        elif reason == "minor_too_low":
            why = (
                f"the server speaks API {got}, but this client needs at least {want}; "
                "upgrade the server or use an older axentra-client"
            )
        else:
            why = f"the server reported {got}; expected api_version {{major, minor}}"
        super().__init__(f"Incompatible Axentra API: {why}.")
        self.reason = reason
        self.server = server
        self.required = required
