"""Framework-free building blocks shared by every Axentra module (errors, ids, context, pagination)."""

from axentra.core.context import Actor, ActorKind, PlatformRole, Principal
from axentra.core.errors import (
    AxentraError,
    Conflict,
    Forbidden,
    InvalidCursor,
    ModeNotSupported,
    NotFound,
    PreconditionFailed,
    QuotaExceeded,
    RateLimited,
    Unauthenticated,
    ValidationFailed,
)
from axentra.core.ids import new_id, new_token
from axentra.core.pagination import Page, decode_cursor, encode_cursor

__all__ = [
    "Actor",
    "ActorKind",
    "AxentraError",
    "Conflict",
    "Forbidden",
    "InvalidCursor",
    "ModeNotSupported",
    "NotFound",
    "Page",
    "PlatformRole",
    "PreconditionFailed",
    "Principal",
    "QuotaExceeded",
    "RateLimited",
    "Unauthenticated",
    "ValidationFailed",
    "decode_cursor",
    "encode_cursor",
    "new_id",
    "new_token",
]
