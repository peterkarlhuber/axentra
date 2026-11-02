"""Cursor pagination: opaque cursors that encode the sort key of the last row.

A cursor comes from the client, so :func:`decode_cursor` treats it as untrusted input: every
malformed cursor raises :class:`~axentra.core.errors.InvalidCursor` (``400 invalid_cursor``) with
a fixed detail, never a database error (``500``) and never the text of a decoder exception.
Callers pass the expected ``shape`` (one part per value) so that a value reaches SQL only with the
type its column needs; a ``"timestamp"`` part comes back as an aware UTC :class:`datetime`.
"""

from __future__ import annotations

import base64
import binascii
from collections.abc import Sequence
from datetime import UTC, datetime
import json
import math
import re
from typing import Any, Generic, Literal, TypeVar

from pydantic import BaseModel

from axentra.core.errors import InvalidCursor, ValidationFailed

T = TypeVar("T")

DEFAULT_LIMIT = 50
MAX_LIMIT = 200
#: Longest cursor accepted (characters). Cursors Axentra issues are far shorter; a sort key that
#: is a file name (at most 255 UTF-8 bytes) still fits with JSON escaping.
MAX_CURSOR_CHARS = 4096

#: The type of one cursor value: ``"str"`` (an id or text sort key), ``"timestamp"`` (RFC 3339
#: with an explicit offset, returned as an aware UTC datetime) or ``"int"`` (a PostgreSQL bigint).
CursorPart = Literal["str", "timestamp", "int"]

_BASE64URL = re.compile(r"[A-Za-z0-9_-]*={0,2}")
# The exact form ``datetime.isoformat()`` produces for an aware value with a whole-minute offset
# (plus ``Z``). ``datetime.fromisoformat`` alone accepts more (ISO week dates, basic format, comma
# fractions, offsets with seconds and microseconds), and PostgreSQL rejects some of those forms.
_TIMESTAMP = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,6})?(Z|[+-]\d{2}:\d{2})", re.ASCII)
_BIGINT_MIN, _BIGINT_MAX = -(2**63), 2**63 - 1


class Page(BaseModel, Generic[T]):
    items: list[T]
    next_cursor: str | None = None


def clamp_limit(limit: int | None) -> int:
    if limit is None:
        return DEFAULT_LIMIT
    if limit < 1 or limit > MAX_LIMIT:
        raise ValidationFailed(f"limit must be between 1 and {MAX_LIMIT}")
    return limit


def encode_cursor(values: list[Any]) -> str:
    raw = json.dumps(values, separators=(",", ":"), default=str).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def decode_cursor(cursor: str | None, shape: Sequence[CursorPart] | None = None) -> list[Any] | None:
    """The values of ``cursor`` (``None`` without a cursor).

    With ``shape``, the cursor must hold exactly one value per part, each of that part's type
    (``"timestamp"`` values are converted to aware UTC datetimes). Without it, the cursor must be
    a JSON list whose strings are valid UTF-8 without NUL characters. Anything else raises
    :class:`InvalidCursor`.
    """
    if not cursor:
        return None
    value = _decode(cursor)
    if shape is None:
        if not _safe(value):
            raise InvalidCursor()
        return value
    if len(value) != len(shape):
        raise InvalidCursor()
    return [_part(v, kind) for v, kind in zip(value, shape, strict=True)]


def _decode(cursor: str) -> list[Any]:
    if len(cursor) > MAX_CURSOR_CHARS or not _BASE64URL.fullmatch(cursor):
        raise InvalidCursor()
    try:
        raw = base64.urlsafe_b64decode(cursor.rstrip("=") + "=" * (-len(cursor.rstrip("=")) % 4))
        value = json.loads(raw.decode("utf-8"), parse_constant=_reject_constant)
    except (ValueError, binascii.Error, RecursionError):
        # ValueError covers UnicodeDecodeError and json.JSONDecodeError. The exception text is
        # deliberately dropped: it can quote the cursor or name codec internals.
        raise InvalidCursor() from None
    if not isinstance(value, list):
        raise InvalidCursor()
    return value


def _reject_constant(name: str) -> Any:
    raise ValueError("non-finite number")


def _safe(value: Any) -> bool:
    if isinstance(value, str):
        return _safe_text(value)
    if isinstance(value, float):
        return math.isfinite(value)
    if value is None or isinstance(value, bool | int):
        return True
    if isinstance(value, list):
        return all(_safe(v) for v in value)
    if isinstance(value, dict):
        return all(_safe(k) and _safe(v) for k, v in value.items())
    return False


def _safe_text(text: str) -> bool:
    """PostgreSQL text holds neither NUL nor lone surrogates (which UTF-8 cannot encode)."""
    if "\x00" in text:
        return False
    try:
        text.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return True


def _part(value: Any, kind: CursorPart) -> Any:
    if kind == "str":
        if isinstance(value, str) and value and _safe_text(value):
            return value
    elif kind == "int":
        if isinstance(value, int) and not isinstance(value, bool) and _BIGINT_MIN <= value <= _BIGINT_MAX:
            return value
    elif kind == "timestamp" and isinstance(value, str) and _TIMESTAMP.fullmatch(value):
        try:
            return datetime.fromisoformat(value).astimezone(UTC)
        except (ValueError, OverflowError):
            pass
    raise InvalidCursor()
