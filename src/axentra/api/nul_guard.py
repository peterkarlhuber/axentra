"""Refuse NUL characters in request input with ``422`` (ASGI middleware).

PostgreSQL cannot store U+0000 in ``text`` or ``jsonb``: a NUL that reaches a query makes the driver
fail with an internal error (``500``, a traceback in the log, B-04). No Axentra endpoint has a use
for it, so it is refused at the API boundary, before any rate limit, session or database work:

- in the percent-decoded path and in the query string (raw or ``%00``),
- in a JSON body as the escape ``\\u0000``;
- in a JSON body as a raw ``0x00`` byte. In UTF-8 that is invalid JSON anyway, but every UTF-16 and
  UTF-32 body has such bytes, and the JSON parser accepts those encodings: a NUL escape in them would
  pass a byte search. JSON exchanged between systems must be UTF-8 (RFC 8259, section 8.1), so other
  encodings are refused as well.

Other bodies (file uploads, forms) are not inspected: files may contain NUL bytes.
"""

from __future__ import annotations

import re

from starlette.concurrency import run_in_threadpool
from starlette.exceptions import HTTPException
from starlette.requests import Request
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from axentra.api.problems import problem

#: ``\u0000`` as a JSON escape: preceded by an even number of backslashes (``\\u0000`` is a backslash
#: followed by the text ``u0000``).
_JSON_NUL = re.compile(rb"(?<!\\)(?:\\\\)*\\u0000")
_QUERY_NUL = re.compile(rb"\x00|%00")
_MESSAGE = "text must not contain NUL characters"
_BODY_MESSAGE = "JSON bodies must be UTF-8 and must not contain NUL characters"
#: Bodies above this size are searched in a worker thread, not on the event loop.
_THREAD_THRESHOLD = 256 * 1024


def _json_body_has_nul(body: bytes) -> bool:
    # The substring tests are memchr-fast; the regex runs only when an escape may be a NUL.
    return b"\x00" in body or (b"\\u0000" in body and _JSON_NUL.search(body) is not None)


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
                if not message.get("more_body", False):
                    body = b"".join(chunks)
                    chunks.clear()
                    if len(body) > _THREAD_THRESHOLD:
                        has_nul = await run_in_threadpool(_json_body_has_nul, body)
                    else:
                        has_nul = _json_body_has_nul(body)
                    if has_nul:
                        # Raised inside the endpoint's body read: rendered by the HTTP exception handler.
                        raise HTTPException(422, _BODY_MESSAGE)
            return message

        await self.app(scope, checked_receive, send)
