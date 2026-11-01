from __future__ import annotations

from typing import Annotated

from fastapi import Header, Query

from axentra.core.errors import ValidationFailed

Limit = Annotated[int | None, Query(ge=1, le=200, description="Page size (1-200, default 50)")]
Cursor = Annotated[str | None, Query(description="Opaque cursor from a previous page's next_cursor")]


def parse_if_match(value: str | None) -> int | None:
    if value is None:
        return None
    try:
        return int(value.strip().strip('"').removeprefix("W/").strip('"'))
    except ValueError:
        raise ValidationFailed("If-Match must be the resource version number") from None


IfMatch = Annotated[str | None, Header(alias="If-Match", description="Expected resource version")]
