"""The error hierarchy of Axentra.

Every error has a stable machine-readable ``code`` and an HTTP ``status`` so that the HTTP layer
can render RFC 9457 problem details without knowing the module that raised it. ``detail`` is
shown to clients and must never contain secrets, tokens, SQL or stack traces.

:func:`problem_details` maps any exception to a framework-independent :class:`ProblemInfo`
(status, code, title, detail, extra members and response headers). Axentra's own HTTP API renders
its errors through it, and applications that embed Axentra as a library and have their own web
layer use it to answer the way the Axentra API would (see docs/architecture/EMBEDDING.md).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, ClassVar

from axentra.core.redaction import redact_text

#: Base URI of the ``type`` member of problem details (``PROBLEM_BASE + code``). A URN on purpose:
#: stable, and not a web domain (``axentra.dev`` belongs to an unrelated company; ADR 0009).
#: Clients switch on ``code``, never on ``type``.
PROBLEM_BASE = "urn:axentra:problem:"
#: ``Retry-After`` (seconds) sent with a 429 when the error names no delay of its own.
DEFAULT_RETRY_AFTER_SECONDS = 60


class AxentraError(Exception):
    code: ClassVar[str] = "internal"
    status: ClassVar[int] = 500
    title: ClassVar[str] = "Internal error"

    def __init__(
        self,
        detail: str | None = None,
        *,
        extra: dict[str, Any] | None = None,
        retry_after: int | None = None,
    ) -> None:
        super().__init__(detail or self.title)
        self.detail = detail or self.title
        self.extra = extra or {}
        #: Seconds a client should wait before retrying (``Retry-After``); only used for 429/503.
        self.retry_after = retry_after


class ValidationFailed(AxentraError):
    code = "validation_failed"
    status = 422
    title = "Validation failed"


class InvalidCursor(ValidationFailed):
    """A pagination ``cursor`` that Axentra did not issue or that was altered (always the same detail)."""

    code = "invalid_cursor"
    status = 400
    title = "Invalid cursor"

    def __init__(self, detail: str | None = None, **kwargs: Any) -> None:
        super().__init__(detail or "invalid cursor", **kwargs)


class InvalidToken(AxentraError):
    """A password reset or email verification token that is unknown, expired, already used or no
    longer matches the account (always the same detail, so the reason is not revealed)."""

    code = "invalid_token"
    status = 400
    title = "Invalid or expired link"

    def __init__(self, detail: str | None = None, **kwargs: Any) -> None:
        super().__init__(detail or "the link is invalid, expired or was already used", **kwargs)


class Unauthenticated(AxentraError):
    code = "unauthenticated"
    status = 401
    title = "Authentication required"


class Forbidden(AxentraError):
    code = "forbidden"
    status = 403
    title = "Not permitted"


class ReauthenticationRequired(Forbidden):
    """The action needs a recent login (e.g. setting a first password); log in again and retry."""

    code = "reauthentication_required"


class ApiKeyCreatorLostAccess(Forbidden):
    """An API key used a permission that the key's creator no longer holds in that scope.

    A key never does more than its creator (``created_by``: a user, or the key that made it) could do
    now; the key is not revoked, so restoring the creator's access restores the key. ``extra``
    carries ``permission``."""

    code = "api_key_creator_lost_access"
    title = "API key creator lost access"


class BackdatingNotPermitted(Forbidden):
    """Usage dated before the tenant's current billing period needs product-level ``usage:manage``.

    ``extra`` carries ``period_start``: the earliest ``occurred_at`` the caller may use."""

    code = "backdating_not_permitted"
    title = "Backdating not permitted"


class NotFound(AxentraError):
    code = "not_found"
    status = 404
    title = "Not found"


class Conflict(AxentraError):
    code = "conflict"
    status = 409
    title = "Conflict"


class SetupAlreadyCompleted(Conflict):
    """First-run setup was attempted although a platform administrator already exists."""

    code = "setup_already_completed"
    title = "Setup already completed"


class EmailTaken(Conflict):
    """Another user already has this email address (email addresses are unique, case-insensitive)."""

    code = "email_taken"
    title = "Email address in use"


class PreconditionFailed(AxentraError):
    code = "precondition_failed"
    status = 412
    title = "Precondition failed"


class PayloadTooLarge(AxentraError):
    code = "payload_too_large"
    status = 413
    title = "Payload too large"


class UnsupportedMediaType(AxentraError):
    code = "unsupported_media_type"
    status = 415
    title = "Unsupported media type"


class RateLimited(AxentraError):
    code = "rate_limited"
    status = 429
    title = "Too many requests"


class QuotaExceeded(AxentraError):
    code = "quota_exceeded"
    status = 429
    title = "Quota exceeded"


class ModeNotSupported(AxentraError):
    code = "mode_not_supported"
    status = 409
    title = "Not supported in this deployment mode"


class ModuleDisabled(AxentraError):
    code = "module_disabled"
    status = 404
    title = "Module not enabled"


class ServiceUnavailable(AxentraError):
    """A dependency (for example the S3 object store) is unreachable or overloaded; retry later.

    The only 5xx error whose ``status`` and ``code`` reach the client (``503 service_unavailable`` with
    ``Retry-After``). ``detail`` is fixed by the raiser and must name the dependency kind only, never an
    endpoint, bucket, key or credential; the original exception is logged server-side."""

    code = "service_unavailable"
    status = 503
    title = "Service unavailable"
    #: ``Retry-After`` when the raiser names no delay of its own.
    default_retry_after: ClassVar[int] = 10


class ConfigurationError(AxentraError):
    """Invalid or insecure configuration; raised at startup, never to clients."""

    code = "configuration_error"
    status = 500
    title = "Configuration error"


@dataclass(frozen=True, slots=True)
class ProblemInfo:
    """A framework-independent RFC 9457 problem: what a web layer needs to answer an error."""

    status: int
    code: str
    title: str
    detail: str
    extra: dict[str, Any] = field(default_factory=dict)
    headers: dict[str, str] = field(default_factory=dict)
    #: True for server-side failures (status >= 500): log the original exception, and never show
    #: anything but the generic detail to the client.
    internal: bool = False

    @property
    def type(self) -> str:
        return PROBLEM_BASE + self.code

    def body(self, *, request_id: str | None = None) -> dict[str, Any]:
        """The ``application/problem+json`` body, as the Axentra HTTP API renders it."""
        return {
            "type": self.type,
            "title": self.title,
            "status": self.status,
            "code": self.code,
            "detail": self.detail,
            "request_id": request_id,
            **self.extra,
        }


_INTERNAL = ProblemInfo(
    status=500, code="internal", title="Internal error", detail="An internal error occurred.", internal=True
)


def problem(
    status: int,
    code: str,
    title: str,
    detail: str,
    *,
    extra: dict[str, Any] | None = None,
    retry_after: int | None = None,
) -> ProblemInfo:
    """Build a :class:`ProblemInfo`; redacts ``detail`` and adds ``Retry-After`` to a 429/503."""
    headers: dict[str, str] = {}
    if status == 429 or (status == 503 and retry_after is not None):
        headers["Retry-After"] = str(max(1, retry_after or DEFAULT_RETRY_AFTER_SECONDS))
    return ProblemInfo(
        status=status,
        code=code,
        title=title,
        detail=redact_text(detail),
        extra=dict(extra or {}),
        headers=headers,
        internal=status >= 500,
    )


def problem_details(exc: BaseException) -> ProblemInfo:
    """Map an exception to the problem details the Axentra HTTP API would answer with.

    - An :class:`AxentraError` with a 4xx status keeps its ``status``, ``code``, ``title``,
      ``detail`` (redacted) and ``extra`` members; a 429 carries ``Retry-After``.
    - A :class:`ServiceUnavailable` keeps its ``503``, ``code``, ``title`` and ``detail`` and carries
      ``Retry-After`` (``internal=True``: the caller logs ``exc``).
    - Any other :class:`AxentraError` with a 5xx status, and every other exception, becomes a generic
      ``500 internal`` problem without details (``internal=True``: the caller logs ``exc``).
    """
    if isinstance(exc, ServiceUnavailable):
        return problem(
            503,
            exc.code,
            exc.title,
            exc.detail,
            extra=exc.extra,
            retry_after=exc.retry_after or exc.default_retry_after,
        )
    if isinstance(exc, AxentraError) and exc.status < 500:
        return problem(
            exc.status, exc.code, exc.title, exc.detail, extra=exc.extra, retry_after=exc.retry_after
        )
    return _INTERNAL
