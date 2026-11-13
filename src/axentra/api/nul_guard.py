"""Refuse NUL characters in request input with ``422`` (ASGI middleware).

PostgreSQL cannot store U+0000 in ``text`` or ``jsonb``: a NUL that reaches a query makes the driver
fail with an internal error (``500``, a traceback in the log, B-04). No Axentra endpoint has a use
for it, so it is refused at the API boundary, before any rate limit, session or database work:

- in the percent-decoded path and in the query string (raw or ``%00``),
- in a JSON body as the escape ``\\u0000`` (a raw NUL is invalid JSON and already a ``422``).

Other bodies (file uploads, forms) are not inspected: files may contain NUL bytes.
"""

from __future__ import annotations

import re

from starlette.exceptions import HTTPException
from starlette.requests import Request
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from axentra.api.problems import problem

#: ``\u0000`` as a JSON escape: preceded by an even number of backslashes (``\\u0000`` is a backslash
#: followed by the text ``u0000``).
_JSON_NUL = re.compile(rb"(?<!\\)(?:\\\\)*\\u0000")
_QUERY_NUL = re.compile(rb"\x00|%00")
_MESSAGE = "text must not contain NUL characters"


def _is_json(scope: Scope) -> bool:
    for name, value in scope.get("headers", ()):
        if name == b"content-type":
            media: bytes = value.split(b";", 1)[0].strip().lower()
            return media == b"application/json" or media.endswith(b"+json")
    return False


class NulInputMiddleware:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        if "\x00" in scope["path"] or _QUERY_NUL.search(scope.get("query_string", b"")):
            response = problem(Request(scope), 422, "validation_failed", "Validation failed", _MESSAGE)
            await response(scope, receive, send)
            return
        if not _is_json(scope):
            await self.app(scope, receive, send)
            return
        chunks: list[bytes] = []

        async def checked_receive() -> Message:
            message = await receive()
            if message["type"] == "http.request":
                chunks.append(message.get("body", b""))
                if not message.get("more_body", False) and _JSON_NUL.search(b"".join(chunks)):
                    # Raised inside the endpoint's body read: rendered by the HTTP exception handler.
                    raise HTTPException(422, _MESSAGE)
            return message

        await self.app(scope, checked_receive, send)
