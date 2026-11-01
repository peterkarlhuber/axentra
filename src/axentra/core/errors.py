"""The error hierarchy of Axentra.

Every error has a stable machine-readable ``code`` and an HTTP ``status`` so that the HTTP layer
can render RFC 9457 problem details without knowing the module that raised it. ``detail`` is
shown to clients and must never contain secrets, tokens, SQL or stack traces.
"""

from __future__ import annotations

from typing import Any, ClassVar


class AxentraError(Exception):
    code: ClassVar[str] = "internal"
    status: ClassVar[int] = 500
    title: ClassVar[str] = "Internal error"

    def __init__(self, detail: str | None = None, *, extra: dict[str, Any] | None = None) -> None:
        super().__init__(detail or self.title)
        self.detail = detail or self.title
        self.extra = extra or {}


class ValidationFailed(AxentraError):
    code = "validation_failed"
    status = 422
    title = "Validation failed"


class Unauthenticated(AxentraError):
    code = "unauthenticated"
    status = 401
    title = "Authentication required"


class Forbidden(AxentraError):
    code = "forbidden"
    status = 403
    title = "Not permitted"


class NotFound(AxentraError):
    code = "not_found"
    status = 404
    title = "Not found"


class Conflict(AxentraError):
    code = "conflict"
    status = 409
    title = "Conflict"


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


class ConfigurationError(AxentraError):
    """Invalid or insecure configuration; raised at startup, never to clients."""

    code = "configuration_error"
    status = 500
    title = "Configuration error"
