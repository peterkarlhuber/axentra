"""Cursor pagination: opaque cursors that encode the sort key of the last row."""

from __future__ import annotations

import base64
import json
from typing import Any, Generic, TypeVar

from pydantic import BaseModel

from axentra.core.errors import ValidationFailed

T = TypeVar("T")

DEFAULT_LIMIT = 50
MAX_LIMIT = 200


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


def decode_cursor(cursor: str | None) -> list[Any] | None:
    if not cursor:
        return None
    try:
        pad = "=" * (-len(cursor) % 4)
        value = json.loads(base64.urlsafe_b64decode(cursor + pad))
    except (ValueError, json.JSONDecodeError) as exc:
        raise ValidationFailed("invalid cursor") from exc
    if not isinstance(value, list):
        raise ValidationFailed("invalid cursor")
    return value
