"""Database errors without the values they carry (finding B-06-1).

A PostgreSQL error carries the server's ``DETAIL`` (and ``HINT``, ``CONTEXT``), and for a constraint violation
that text holds the offending values: ``Key (email)=(someone@example.com) already exists.`` or
``Failing row contains (...)``. ``str(exc)`` of a psycopg error includes it, and so does every traceback that
logging prints for it. :func:`safe_message` describes such an error from its SQLSTATE and constraint name only,
and :class:`DbErrorRedactionFilter` rewrites log records so that their text, arguments and tracebacks carry that
description instead of the server's text. :func:`install_db_error_redaction` applies the filter to every log
record of the process; :func:`safe_error_text` is for error texts that are stored or returned (job and
notification ``last_error``).

This is Axentra's local fix (TABRION MIG-AXE-0). TABRION MIG-AXE-3 replaces it with ``tabrion.errors``
(``safe_message``, ``DbErrorRedactionFilter``), which behaves the same way; the regression tests in
``tests/integration/test_db_error_logging.py`` check only the observable output and stay.

Database errors are recognized without importing a driver: psycopg (and psycopg2) errors by their module,
:class:`sqlite3.Error`, and wrappers that keep the driver error in ``orig`` (SQLAlchemy's ``DBAPIError``).

TABRION TB-031 ported the fix of Tabrion's review (``tab-010-012-review.md`` H-1, H-2, M-2, N-1, N-2): database
errors are found inside containers and exception ``args``, their ``repr`` (escaped ``\\nDETAIL:``) form is
scrubbed, the formatted message is always checked, a multi-line ``DETAIL`` is removed in full, and the database
error a record names (``db_sqlstate``) follows ``orig`` and ``__cause__`` before ``__context__``.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
import contextlib
import itertools
import logging
import re
import sqlite3
import sys
import threading
import traceback
from types import TracebackType
from typing import Any

from axentra.core.redaction import redact_text

__all__ = [
    "DB_ERROR_LOGGERS",
    "DbErrorRedactionFilter",
    "db_error_fields",
    "install_db_error_redaction",
    "is_db_error",
    "primary_db_error",
    "redact_db_errors_processor",
    "redacted_traceback",
    "safe_error_text",
    "safe_message",
    "scrub_text",
]

_DRIVER_PACKAGES = frozenset({"psycopg", "psycopg2"})
#: A bound on the exceptions :func:`_chain` visits (it stops at cycles anyway; this only bounds the work).
_MAX_CHAIN = 10_000

_KIND_BY_SQLSTATE = {
    "23505": "unique violation",
    "23503": "foreign key violation",
    "23502": "not null violation",
    "23514": "check violation",
    "23P01": "exclusion violation",
    "40P01": "deadlock detected",
    "40001": "serialization failure",
    "55P03": "lock not available",
    "57014": "query canceled",
    "25P03": "idle in transaction session timeout",
    "25006": "read-only transaction",
    "42501": "insufficient privilege",
    "42601": "syntax error",
    "53100": "disk full",
    "53300": "too many connections",
}
_KIND_BY_CLASS = {
    "08": "connection error",
    "22": "data error",
    "23": "integrity constraint violation",
    "40": "transaction rollback",
    "42": "syntax error or access rule violation",
    "53": "insufficient resources",
    "54": "program limit exceeded",
    "57": "operator intervention",
    "XX": "internal database error",
}
#: Where the parts psycopg appends to a server error's message start (``DETAIL:  Key (email)=(...) already
#: exists.``, ``HINT:``, ``CONTEXT:``, and ``QUERY:`` / ``LINE n:`` with statement text): a line that starts with
#: such a label, or the label in the middle of a line (a message whose newlines were replaced; psycopg puts two
#: spaces after the colon). From there the text is removed up to the next line of a traceback's structure or the
#: end of the text, because a value may span several lines (TABRION TB-031, Tabrion review M-2).
#: The run of blanks before an inline label starts only after a non-blank character: without the look-behind,
#: every start position inside a long run of blanks rescans the run (quadratic time, review F-3).
_SERVER_TEXT_START = re.compile(
    r"^[ \t]*(?:DETAIL|HINT|CONTEXT|QUERY|LINE \d+):|(?<![ \t])[ \t]*\b(?:DETAIL|HINT|CONTEXT|QUERY): {2}"
)
#: The header line of a formatted traceback. Only after one has been seen in a text does :data:`_BOUNDARY` end
#: a removed part (review F-4): in free text (a message, a stored ``last_error``) the removal runs to the end.
_TRACEBACK_HEADER = re.compile(
    r"[ \t|]*(?:Exception Group )?Traceback \(most recent call last\):[ \t]*(?:\r?\n)?"
)
#: Lines that end a removed part inside a traceback. Each must be a whole line of the expected structure, so that
#: a value line which merely starts like one (``+-SECRET``, ``File "SECRET``) does not end it (Tabrion re-review
#: N-1).
_BOUNDARY = re.compile(
    r"[ \t|]*(?:"
    r"Traceback \(most recent call last\):"
    r"|Exception Group Traceback \(most recent call last\):"
    r"|The above exception was the direct cause of the following exception:"
    r"|During handling of the above exception, another exception occurred:"
    r'|File "[^"\r\n]*", line \d+(?:, in [^\r\n]*)?'
    r"|\+[-+]*(?: (?:\d+|\.\.\.) -+)?"
    r"|\(Background on this error at: https?://[^\s()]+\)"
    r")[ \t]*(?:\r?\n)?"
)
#: The same parts in escaped form, as ``repr()`` prints them (``UniqueViolation('...\\nDETAIL:  Key (email)=(...)
#: already exists.')``, Tabrion review H-2): removed from the escaped newline to the end of the line.
_ESCAPED_SERVER_TEXT = re.compile(r"(?:\\r)?\\n[ \t]*(?:DETAIL|HINT|CONTEXT|QUERY|LINE \d+):.*")
#: Cheap test whether a text may hold such a part (the escaped form contains the same labels).
_SERVER_TEXT_MARKERS = ("DETAIL:", "HINT:", "CONTEXT:")
#: What a removed server text part is replaced with, so that a truncated message shows that it was truncated
#: (review F-7).
SERVER_TEXT_MARK = "[redacted: database server text]"
#: The two record attributes the filter sets; ``extra=`` may still pass them (review F-6).
DB_FIELDS = ("db_sqlstate", "db_constraint")
#: Bounds of the search for database errors inside a log record's arguments and message: container levels below
#: the argument, and objects looked at (Tabrion review H-2, re-review N-3).
_MAX_COLLECT_DEPTH = 3
_MAX_COLLECT_ITEMS = 1_000
#: Argument types whose text cannot hold a database error's text unless a ``str`` carries it (fast path).
_PLAIN_TYPES = (str, int, float, bool, type(None))
#: SQLSTATEs (besides class 08) that mean the server ended the session (``admin_shutdown`` and friends).
_CONNECTION_LOSS_STATES = frozenset({"57P01", "57P02", "57P03", "57P04", "57P05"})


def _is_driver_error(exc: BaseException) -> bool:
    if isinstance(exc, sqlite3.Error):
        return True
    return type(exc).__module__.split(".", 1)[0] in _DRIVER_PACKAGES


def _driver_error(exc: BaseException) -> BaseException | None:
    """``exc`` itself or the driver error it wraps in ``orig`` (SQLAlchemy), if any."""
    if _is_driver_error(exc):
        return exc
    orig = getattr(exc, "orig", None)
    if isinstance(orig, BaseException) and _is_driver_error(orig):
        return orig
    return None


def is_db_error(exc: BaseException) -> bool:
    """True for a database driver error or a wrapper that keeps one in ``orig``."""
    return _driver_error(exc) is not None


def db_error_fields(exc: BaseException) -> tuple[str | None, str | None]:
    """The SQLSTATE (SQLite: the error name) and the constraint name of a database error; never values."""
    err = _driver_error(exc)
    if err is None:
        return None, None
    if isinstance(err, sqlite3.Error):
        name = getattr(err, "sqlite_errorname", None)
        return (name if isinstance(name, str) else None), None
    sqlstate = getattr(err, "sqlstate", None) or getattr(err, "pgcode", None)
    diag = getattr(err, "diag", None)
    constraint = getattr(diag, "constraint_name", None) if diag is not None else None
    return (
        sqlstate if isinstance(sqlstate, str) else None,
        constraint if isinstance(constraint, str) else None,
    )


def safe_message(exc: BaseException) -> str:
    """Describe a database error by its kind, SQLSTATE and constraint name, without any value it carries.

    For example ``unique violation (SQLSTATE 23505, constraint users_email_key)``. The server's message,
    ``DETAIL``, ``HINT`` and ``CONTEXT`` and the statement's parameters are left out. A psycopg error raised by
    the client (no SQLSTATE: a connection failure, a wrong number of parameters) keeps its own message, which
    holds no row values, without any server text lines, redacted with :func:`redact_text`. Any other exception
    is returned as ``str(exc)``.
    """
    err = _driver_error(exc)
    if err is None:
        return str(exc)
    sqlstate, constraint = db_error_fields(err)
    if isinstance(err, sqlite3.Error):
        return f"database error (SQLite {sqlstate})" if sqlstate else "database error (SQLite)"
    if sqlstate is None:
        text = redact_text(strip_server_text(str(err))).strip()
        return f"database client error: {text}" if text else "database client error"
    kind = _KIND_BY_SQLSTATE.get(sqlstate) or _KIND_BY_CLASS.get(sqlstate[:2], "database error")
    parts = [f"SQLSTATE {sqlstate}"]
    if constraint:
        parts.append(f"constraint {constraint}")
    return f"{kind} ({', '.join(parts)})"


def strip_server_text(text: str) -> str:
    """``text`` without the ``DETAIL:`` / ``HINT:`` / ``CONTEXT:`` (and ``QUERY:``, ``LINE n:``) parts psycopg
    adds to a server error's message, also in the escaped form of a ``repr``.

    A part is replaced by :data:`SERVER_TEXT_MARK` from its label to the end of the text, because a value may
    span several lines. Only in a formatted traceback (after a ``Traceback (most recent call last):`` header) does
    the part end earlier, at the next line of the traceback's structure (``File "...", line N``, the chain and
    exception group lines, SQLAlchemy's ``(Background on this error at: ...)``)."""
    if not any(marker in text for marker in _SERVER_TEXT_MARKERS):
        return text
    text = _ESCAPED_SERVER_TEXT.sub(" " + SERVER_TEXT_MARK, text)
    out: list[str] = []
    skipping = False
    in_traceback = False
    for line in text.splitlines(keepends=True):
        if skipping:
            if not in_traceback or _BOUNDARY.fullmatch(line) is None:
                continue
            skipping = False
        if not in_traceback and _TRACEBACK_HEADER.fullmatch(line) is not None:
            in_traceback = True
        start = _SERVER_TEXT_START.search(line)
        if start is not None:
            kept = line[: start.start()].rstrip(" \t")
            mark = f"{kept} {SERVER_TEXT_MARK}" if kept.strip() else kept + SERVER_TEXT_MARK
            out.append(mark + ("\n" if line.endswith("\n") else ""))
            skipping = True
            continue
        out.append(line)
    return "".join(out).rstrip("\n")


def _may_hold_server_text(value: object) -> bool:
    return isinstance(value, str) and any(marker in value for marker in _SERVER_TEXT_MARKERS)


def _chain(exc: BaseException) -> list[BaseException]:
    """``exc`` and every exception it was raised from or during, those it wraps in ``orig`` and the members of
    exception groups, at any depth (each exception once, so cycles end)."""
    out: list[BaseException] = []
    seen: set[int] = set()
    stack: list[BaseException] = [exc]
    while stack and len(out) < _MAX_CHAIN:
        current = stack.pop()
        if id(current) in seen:
            continue
        seen.add(id(current))
        out.append(current)
        linked: list[object] = [current.__cause__, current.__context__, getattr(current, "orig", None)]
        members = getattr(current, "exceptions", None)
        if isinstance(members, (tuple, list)):
            linked.extend(members)
        stack.extend(e for e in reversed(linked) if isinstance(e, BaseException))
    return out


def _db_errors_in(exc: BaseException) -> list[BaseException]:
    return [e for e in _chain(exc) if is_db_error(e)]


def _is_connection_loss(err: BaseException) -> bool:
    """Class 08, 57P01..57P05, or a psycopg ``OperationalError`` without SQLSTATE (a lost or refused
    connection)."""
    sqlstate, _ = db_error_fields(err)
    if sqlstate is not None:
        return sqlstate[:2] == "08" or sqlstate in _CONNECTION_LOSS_STATES
    driver = _driver_error(err)
    if driver is None or isinstance(driver, sqlite3.Error):
        return False
    return any(
        cls.__name__ == "OperationalError" and cls.__module__.split(".", 1)[0] in _DRIVER_PACKAGES
        for cls in type(driver).__mro__
    )


def primary_db_error(exc: BaseException) -> BaseException | None:
    """The database error that describes ``exc``, or ``None`` (TABRION TB-031, Tabrion review H-1, contract I-13).

    ``orig`` and ``__cause__`` say what an error wraps; ``__context__`` only says what was being handled when it
    was raised, which may be an older, unrelated error (a connection lost during COMMIT inside the ``except`` block
    of a unique violation or a serialization failure). So the exceptions reached through ``orig`` and
    ``__cause__`` (outermost first) come first, ``__context__`` is followed only while those hold no database error,
    and never when ``__suppress_context__`` is set. Among the database errors reached, the first wins when it
    reports a lost connection; otherwise the first with a SQLSTATE (SQLite: an error name), then the first one.
    """
    seen: set[int] = set()

    def wrapped(start: BaseException) -> list[BaseException]:
        out: list[BaseException] = []
        level = [start]
        while level and len(seen) < _MAX_CHAIN:
            following: list[BaseException] = []
            for e in level:
                if id(e) in seen:
                    continue
                seen.add(id(e))
                out.append(e)
                for linked in (getattr(e, "orig", None), e.__cause__):
                    if isinstance(linked, BaseException):
                        following.append(linked)
            level = following
        return out

    segment = wrapped(exc)
    while segment:
        candidates = [e for e in segment if is_db_error(e)]
        if candidates:
            first = candidates[0]
            if _is_connection_loss(first):
                return first
            return next((e for e in candidates if db_error_fields(e)[0] is not None), first)
        following: list[BaseException] = []
        for e in segment:
            if e.__suppress_context__ or not isinstance(e.__context__, BaseException):
                continue
            following.extend(wrapped(e.__context__))
        segment = following
    return None


def _forms(value: str) -> list[str]:
    """``value`` and its escaped form inside a ``repr`` (``\\n`` for a newline, escaped quotes)."""
    forms = [value]
    with contextlib.suppress(Exception):
        escaped = repr(value)[1:-1]
        if escaped != value:
            forms.append(escaped)
    return forms


def _attr(obj: object, name: str) -> Any:
    """``getattr(obj, name, None)`` that never raises (a property that raises, review D-3)."""
    try:
        return getattr(obj, name, None)
    except Exception:
        return None


def _text_of(producer: Any, value: object) -> str | None:
    try:
        text = producer(value)
    except Exception:
        return None
    return text if isinstance(text, str) else None


def _error_texts(err: BaseException) -> list[str]:
    """Every text of ``err`` that may appear in a message: ``str``, ``repr``, its string ``args``, and their
    escaped forms (``f"{e!r}"``, ``"%r" % str(e)``, ``e.args`` or ``[e]`` formatted, Tabrion review H-2)."""
    sources = [_text_of(str, err), _text_of(repr, err)]
    args = _attr(err, "args")
    for arg in args if isinstance(args, tuple) else ():
        if isinstance(arg, str):
            sources += [arg, _text_of(repr, arg)]
    texts: list[str] = []
    for source in sources:
        if source is not None:
            texts.extend(_forms(source))
    return [t for t in texts if len(t) >= 4]


def scrub_text(text: str, errors: list[BaseException]) -> str:
    """``text`` with the text of each database error in ``errors`` (plain, ``repr`` and escaped) replaced by its
    :func:`safe_message`, the values of their ``DETAIL``, ``HINT`` and ``CONTEXT`` (plain and escaped) replaced by
    ``[redacted]``, and every psycopg server text part removed (see :func:`strip_server_text`)."""
    replacements: list[tuple[str, str]] = []
    for err in errors:
        safe = safe_message(err)
        replacements.extend((t, safe) for t in _error_texts(err))
        diag = getattr(_driver_error(err), "diag", None)
        for part in ("message_detail", "message_hint", "context"):
            value = getattr(diag, part, None) if diag is not None else None
            if isinstance(value, str) and value:
                replacements.extend((form, "[redacted]") for form in _forms(value))
    # The longest first: a repr contains the str, and the str contains the DETAIL value.
    for old, new in sorted(replacements, key=lambda pair: len(pair[0]), reverse=True):
        if old in text:
            text = text.replace(old, new)
    return strip_server_text(text)


def _children(value: object) -> Iterable[object]:
    """What ``value`` holds that may be or hold a database error (exception ``args``, container items, mapping keys
    and values)."""
    if isinstance(value, BaseException):
        args = getattr(value, "args", None)
        return args if isinstance(args, tuple) else ()
    if isinstance(value, (list, tuple, set, frozenset)):
        return value
    if isinstance(value, Mapping):
        return itertools.chain(value.keys(), value.values())
    return ()


def _collect(value: object, found: list[BaseException]) -> None:
    """Add the database errors held by ``value`` to ``found``: itself and its chain, and inside lists, tuples, sets,
    mappings and exception ``args``, at most :data:`_MAX_COLLECT_DEPTH` levels down and
    :data:`_MAX_COLLECT_ITEMS` objects (Tabrion review H-2). A container whose iteration fails is skipped
    (re-review N-2); none is copied in full (N-3)."""
    stack: list[tuple[object, int]] = [(value, 0)]
    seen: set[int] = set()
    while stack and len(seen) < _MAX_COLLECT_ITEMS:
        current, depth = stack.pop()
        if id(current) in seen:
            continue
        seen.add(id(current))
        if isinstance(current, BaseException):
            found.extend(e for e in _db_errors_in(current) if all(e is not f for f in found))
        if depth >= _MAX_COLLECT_DEPTH:
            continue
        children: list[object] = []
        with contextlib.suppress(Exception):
            children.extend(itertools.islice(_children(current), _MAX_COLLECT_ITEMS))
        stack.extend((child, depth + 1) for child in reversed(children))


def _exception_may_hold_server_text(exc: BaseException) -> bool:
    """True when an exception of ``exc``'s chain carries psycopg server text in its message, ``args`` or notes
    without being a database error (``raise RuntimeError(f"gave up: {last}")`` after a retry loop, review F-1)."""
    for e in _chain(exc):
        if any(_may_hold_server_text(t) for t in _error_texts(e)):
            return True
        notes = _attr(e, "__notes__")
        if isinstance(notes, list) and any(_may_hold_server_text(n) for n in notes):
            return True
    return False


def _event_exception(value: object) -> tuple[BaseException, TracebackType | None] | None:
    """The exception an event dict's ``exc_info`` names, as structlog resolves it: ``True`` for the exception
    being handled, an exception instance, or an ``exc_info`` tuple."""
    if value is True:
        _, current, tb = sys.exc_info()
        return (current, tb) if isinstance(current, BaseException) else None
    if isinstance(value, BaseException):
        return value, value.__traceback__
    if isinstance(value, tuple) and len(value) == 3 and isinstance(value[1], BaseException):
        return value[1], value[2]
    return None


def _redact_event_dict(event: Mapping[Any, Any], found: list[BaseException]) -> dict[Any, Any] | None:
    """A copy of a mapping message or structlog event dict without database values, or ``None`` when its text
    still holds database text afterwards (review F-5).

    An ``exc_info`` that names an exception whose chain, ``args`` or notes hold a database error or its text is
    replaced by the redacted traceback under ``exception`` (and ``exc_info`` is removed), so that structlog's
    ``format_exc_info``, ``dict_tracebacks`` and ``ConsoleRenderer`` have nothing raw to render (review D-2). Each
    other value is scrubbed: a database error becomes its safe message, a string is scrubbed, any other object whose
    ``repr`` holds database text becomes its scrubbed ``repr``."""
    out: dict[Any, Any] = dict(event)
    named = _event_exception(out.get("exc_info"))
    if named is not None:
        exc, tb = named
        errors: list[BaseException] = []
        _collect(exc, errors)
        if errors or _exception_may_hold_server_text(exc):
            del out["exc_info"]
            out["exception"] = redacted_traceback(exc, tb, errors)
            found.extend(e for e in errors if all(e is not f for f in found))
    _collect(list(out.values()), found)  # so that a value's text (``str(e)``) is replaced by its safe message
    for key, value in list(out.items()):
        if _is_db_exc(value):
            out[key] = safe_message(value)
        elif isinstance(value, str):
            out[key] = scrub_text(value, found)
        else:
            text = _text_of(repr, value)
            if text is None:
                continue
            redacted = scrub_text(text, found)
            if redacted != text:
                out[key] = redacted
    text = str(out)
    if scrub_text(text, found) != text:
        return None
    return out


def redact_db_errors_processor(logger: object, method_name: str, event_dict: Any) -> Any:
    """A structlog processor that removes database values from an event dict (review D-2).

    Optional and import-free: Axentra does not depend on structlog. It redacts ``exc_info`` (``True``, an exception
    or an ``exc_info`` tuple: the redacted traceback goes under ``exception``) and every value, as
    :class:`DbErrorRedactionFilter` does for a mapping message. Put it into structlog's processor chain **before**
    ``format_exc_info``, ``dict_tracebacks`` or the renderer (``ConsoleRenderer`` renders ``exc_info`` itself), in
    the logger's ``processors`` (where ``exc_info=True`` still names the exception being handled), not only in a
    ``ProcessorFormatter``'s. It never raises: on an internal error it returns the event with only the ``event``
    text, scrubbed."""
    if not isinstance(event_dict, Mapping):
        return event_dict
    redacted: dict[Any, Any] | None = None
    with contextlib.suppress(Exception):
        redacted = _redact_event_dict(event_dict, [])
    if redacted is not None:
        return redacted
    try:
        event = event_dict.get("event")
        return {"event": strip_server_text(event) if isinstance(event, str) else "event redacted"}
    except Exception:
        return {"event": "event redacted"}


def _plain_record(record: logging.LogRecord) -> bool:
    """True when the record's message cannot carry a database error's text: a ``str`` template and plain
    arguments (exactly ``str``, ``int``, ``float``, ``bool`` or ``None``), none of them with a server text label.
    Such records are not formatted by the filter (fast path)."""
    msg = record.msg
    if type(msg) is not str or _may_hold_server_text(msg):
        return False
    args = record.args
    if args is None:
        return True
    if not isinstance(args, tuple):
        return False
    return all(type(a) in _PLAIN_TYPES and not _may_hold_server_text(a) for a in args)


def safe_error_text(exc: BaseException) -> str:
    """Text for ``exc`` that may be stored or shown (for example a job's ``last_error``).

    A database error becomes its :func:`safe_message`. Any other exception keeps ``str(exc)``, in which the text of
    database errors it was raised from (or that it quotes) is replaced as :func:`scrub_text` does."""
    if is_db_error(exc):
        return safe_message(exc)
    return scrub_text(str(exc), _db_errors_in(exc))


def _redact_traceback(
    top: traceback.TracebackException, exc: BaseException, errors: list[BaseException]
) -> None:
    """Replace the text of every exception in ``top`` (built from ``exc``): a database error's with
    :func:`safe_message`, any other one's with :func:`scrub_text`."""
    seen: set[int] = set()
    stack: list[tuple[traceback.TracebackException, BaseException]] = [(top, exc)]
    while stack:
        te, e = stack.pop()
        if id(te) in seen:
            continue
        seen.add(id(te))
        # ``_str`` is the exception's text that ``format()`` prints after the type name (Python 3.11 to 3.14;
        # tests/unit/test_db_errors_local.py fails if a Python version drops it).
        if is_db_error(e):
            te._str = safe_message(e)  # type: ignore[attr-defined]
            te.__notes__ = None
        else:
            te._str = scrub_text(str(te._str), errors)  # type: ignore[attr-defined]
            notes = getattr(te, "__notes__", None)
            if isinstance(notes, list):
                te.__notes__ = [scrub_text(str(n), errors) for n in notes]
        if te.__cause__ is not None and e.__cause__ is not None:
            stack.append((te.__cause__, e.__cause__))
        if te.__context__ is not None and e.__context__ is not None:
            stack.append((te.__context__, e.__context__))
        members = getattr(e, "exceptions", None)
        if te.exceptions and isinstance(members, (tuple, list)):
            for sub_te, sub in zip(te.exceptions, members, strict=False):
                if isinstance(sub, BaseException):
                    stack.append((sub_te, sub))


def _summary(exc: BaseException) -> str:
    return "\n".join(
        f"{type(e).__module__}.{type(e).__qualname__}: {safe_error_text(e)}" for e in _chain(exc)
    )


def redacted_traceback(
    exc: BaseException, tb: TracebackType | None = None, errors: list[BaseException] | None = None
) -> str:
    """The formatted traceback of ``exc`` (as :meth:`logging.Formatter.formatException` prints it) in which no
    exception of the chain carries the values of a database error; file names and line numbers stay."""
    errors = _db_errors_in(exc) if errors is None else errors
    te = traceback.TracebackException(
        type(exc), exc, tb if tb is not None else exc.__traceback__, compact=True
    )
    if not hasattr(te, "_str"):  # pragma: no cover - a Python version without the attribute
        return _summary(exc)
    _redact_traceback(te, exc, errors)
    return strip_server_text("".join(te.format())).rstrip("\n")


def _is_db_exc(value: object) -> bool:
    return isinstance(value, BaseException) and is_db_error(value)


class DbErrorRedactionFilter(logging.Filter):
    """A :class:`logging.Filter` that removes the values database errors carry from a log record.

    It never drops a record (:meth:`filter` always returns ``True``); it rewrites it:

    - if ``exc_info`` holds a database error anywhere in its chain, ``exc_text`` (the traceback formatters print)
      becomes :func:`redacted_traceback` and ``exc_info`` is cleared, so that no formatter can format the
      original exception again (the standard formatter prints ``exc_text`` on its own);
    - an argument (positional or a mapping's value) that is a database error is replaced by its
      :func:`safe_message`;
    - database errors are also found inside list, tuple, set and mapping arguments, inside exception ``args`` and
      in a non-``str`` message (``log.error("%s", [e])``, ``e.args``, ``log.error({"err": e})``);
    - the final, formatted message loses the text of the database errors involved (``str``, ``repr`` and escaped
      forms) and every psycopg server text part (``DETAIL:``, ``HINT:``, ``CONTEXT:``, also as an escaped
      ``\\nDETAIL:`` and with all continuation lines of a multi-line value), also when the message was formatted
      before it was logged (``f"{e!r}"``, ``"%r" % str(e)``);
    - ``db_sqlstate`` and ``db_constraint`` name the database error that describes the record's exception
      (:func:`primary_db_error`: ``orig`` and ``__cause__`` before ``__context__``), otherwise the first one found
      (for JSON formatters).

    A record whose message is a plain ``str`` with plain arguments (``str``, ``int``, ``float``, ``bool``,
    ``None``) without a server text label and without a database error in ``exc_info`` is not formatted here (fast
    path); any other record is formatted once more by the filter, so an argument's ``__str__`` may run twice.

    The exception object itself is left unchanged. :func:`install_db_error_redaction` applies it to every record
    when it is created; it can also be added to handlers and loggers.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            self._redact(record)
        except Exception:
            self._fallback(record)
        return True

    @staticmethod
    def _fallback(record: logging.LogRecord) -> None:
        """Keep the record, with a fixed message and the redacted traceback (never the original text)."""
        exc = record.exc_info[1] if isinstance(record.exc_info, tuple) and len(record.exc_info) == 3 else None
        record.msg, record.args = (
            "log message replaced by DbErrorRedactionFilter after an internal error",
            None,
        )
        if isinstance(exc, BaseException):
            try:
                record.exc_text = redacted_traceback(exc, record.exc_info[2])  # type: ignore[index]
            except Exception:
                try:
                    record.exc_text = _summary(exc)
                except Exception:
                    record.exc_text = f"{type(exc).__module__}.{type(exc).__qualname__}"
            record.exc_info = None
        elif record.exc_text:
            record.exc_text = strip_server_text(record.exc_text)

    def _redact(self, record: logging.LogRecord) -> None:
        exc = record.exc_info[1] if isinstance(record.exc_info, tuple) and len(record.exc_info) == 3 else None
        found: list[BaseException] = []
        if isinstance(exc, BaseException):
            # The chain, and database errors held in the exceptions' args (``RuntimeError(e)``, review F-1).
            _collect(exc, found)
            if not found and _exception_may_hold_server_text(exc):
                # No database error object, but its text in a message, args or notes (review F-1).
                record.exc_text = redacted_traceback(exc, record.exc_info[2], [])  # type: ignore[index]
                record.exc_info = None
                exc = None
        if not found and _plain_record(record):
            if isinstance(record.exc_text, str) and _may_hold_server_text(record.exc_text):
                record.exc_text = strip_server_text(record.exc_text)
            return
        primary = primary_db_error(exc) if isinstance(exc, BaseException) and found else None
        _collect(record.args, found)
        _collect(record.msg, found)

        args: Any = record.args
        if isinstance(args, tuple):
            if any(_is_db_exc(a) for a in args):
                record.args = tuple(safe_message(a) if _is_db_exc(a) else a for a in args)
        elif isinstance(args, Mapping) and any(_is_db_exc(v) for v in args.values()):
            record.args = {k: safe_message(v) if _is_db_exc(v) else v for k, v in args.items()}
        if isinstance(record.msg, BaseException) and is_db_error(record.msg):
            record.msg = safe_message(record.msg)
        # Before the mapping branch below, which returns early (review D-1).
        if isinstance(exc, BaseException) and found:
            record.exc_text = redacted_traceback(exc, record.exc_info[2], found)  # type: ignore[index]
            record.exc_info = None
        elif isinstance(record.exc_text, str) and _may_hold_server_text(record.exc_text):
            record.exc_text = strip_server_text(record.exc_text)

        if isinstance(record.msg, Mapping) and not record.args:
            # A mapping message stays a mapping (structlog's ProcessorFormatter copies it, review F-5), with its
            # ``exc_info`` redacted (structlog renders it itself, review D-2).
            scrubbed = _redact_event_dict(record.msg, found)
            if scrubbed is not None:
                if scrubbed != record.msg:
                    record.msg = scrubbed
                if found:
                    self._set_fields(record, primary, found)
                return

        # The check runs on the formatted message, so a value in any argument (a repr, a list, e.args) is seen.
        try:
            message = record.getMessage()
        except Exception:
            template = str(record.msg)
            if not found and not _may_hold_server_text(template):
                return  # an ordinary broken call: logging reports it as usual
            # A broken call (for example too few arguments): keep the record and say what failed.
            summary = "; ".join(safe_message(e) for e in found)
            record.msg = f"log message could not be formatted: {scrub_text(template, found)!r}" + (
                f" ({summary})" if summary else ""
            )
            record.args = None
        else:
            if found or _may_hold_server_text(message):
                redacted = scrub_text(message, found)
                if redacted != message:
                    record.msg, record.args = redacted, None
        if found:
            self._set_fields(record, primary, found)

    @staticmethod
    def _set_fields(
        record: logging.LogRecord, primary: BaseException | None, found: list[BaseException]
    ) -> None:
        sqlstate, constraint = db_error_fields(primary if primary is not None else found[0])
        record.db_sqlstate = sqlstate
        record.db_constraint = constraint


#: Loggers that also get the filter itself (besides the record factory), so that records created there are
#: redacted however they were made: Axentra's error handlers and uvicorn's "Exception in ASGI application"
#: (``uvicorn.error`` has its own handler and does not propagate).
DB_ERROR_LOGGERS = ("axentra.http", "uvicorn.error")
_FACTORY_MARK = "_axentra_db_error_redaction"
_INSTALL_LOCK = threading.Lock()


def _redacted_handle_error(self: logging.Handler, record: logging.LogRecord) -> None:
    """:meth:`logging.Handler.handleError` without database values (review F-2).

    The standard version prints the exception raised in ``emit`` with its whole chain, and its ``__context__`` is
    the exception that was being handled when the log call was made, often the database error itself. This one
    prints the same report with :func:`redacted_traceback` and a scrubbed message and arguments."""
    if not (logging.raiseExceptions and sys.stderr):
        return
    _, value, tb = sys.exc_info()
    try:
        errors = _db_errors_in(value) if isinstance(value, BaseException) else []
        _collect(record.args, errors)
        _collect(record.msg, errors)
        lines = ["--- Logging error ---"]
        if isinstance(value, BaseException):
            try:
                lines.append(redacted_traceback(value, tb))
            except Exception:
                lines.append(_summary(value))
        with contextlib.suppress(Exception):
            lines.append(f"Message: {scrub_text(repr(record.msg), errors)}")
            lines.append(f"Arguments: {scrub_text(repr(record.args), errors)}")
        sys.stderr.write("\n".join(lines) + "\n")
    except (RecursionError, OSError):  # pragma: no cover - as the standard version: never raise from here
        pass
    except Exception:  # pragma: no cover - a last resort that names no value
        with contextlib.suppress(Exception):
            sys.stderr.write("--- Logging error --- (details withheld by DbErrorRedactionFilter)\n")
    finally:
        del value, tb


setattr(_redacted_handle_error, _FACTORY_MARK, True)


def _make_record_keeping_db_fields(original: Any) -> Any:
    """``Logger.makeRecord`` that accepts ``db_sqlstate``/``db_constraint`` in ``extra`` (review F-6): the record
    factory has set them already, and the standard version raises ``KeyError`` for an existing attribute. The
    caller's values win."""

    def make_record(
        self: logging.Logger,
        name: str,
        level: int,
        fn: str,
        lno: int,
        msg: object,
        args: Any,
        exc_info: Any,
        func: str | None = None,
        extra: Mapping[str, object] | None = None,
        sinfo: str | None = None,
    ) -> logging.LogRecord:
        given: dict[str, object] = {}
        if isinstance(extra, Mapping) and any(k in extra for k in DB_FIELDS):
            given = {k: extra[k] for k in DB_FIELDS if k in extra}
            extra = {k: v for k, v in extra.items() if k not in DB_FIELDS}
        record: logging.LogRecord = original(
            self, name, level, fn, lno, msg, args, exc_info, func, extra, sinfo
        )
        record.__dict__.update(given)
        return record

    setattr(make_record, _FACTORY_MARK, True)
    return make_record


def install_db_error_redaction() -> None:
    """Redact database error values from every log record of the process (B-06-1, TABRION MIG-AXE-0).

    Wraps the log record factory (:func:`logging.setLogRecordFactory`, chained to the factory in place) so that
    :class:`DbErrorRedactionFilter` runs on each record when it is created, before any handler, formatter or
    ``logging.lastResort`` sees it, whoever configured logging. Also adds the filter to
    :data:`DB_ERROR_LOGGERS` and ``logging.lastResort``. It also replaces :meth:`logging.Handler.handleError` (the
    report of a failed ``emit``) with one that prints no database values, and lets ``extra=`` carry
    ``db_sqlstate``/``db_constraint`` (``Logger.makeRecord``). Installing twice is harmless.
    Called by :class:`axentra.platform.Axentra`, ``create_app``, ``configure_logging``, :class:`JobWorker` and
    the CLI.
    """
    with _INSTALL_LOCK:
        current = logging.getLogRecordFactory()
        if not getattr(current, _FACTORY_MARK, False):
            redaction = DbErrorRedactionFilter()

            def factory(*args: Any, **kwargs: Any) -> logging.LogRecord:
                record = current(*args, **kwargs)
                redaction.filter(record)
                return record

            setattr(factory, _FACTORY_MARK, True)
            logging.setLogRecordFactory(factory)
        if not getattr(logging.Handler.handleError, _FACTORY_MARK, False):
            logging.Handler.handleError = _redacted_handle_error  # type: ignore[method-assign]
        if not getattr(logging.Logger.makeRecord, _FACTORY_MARK, False):
            logging.Logger.makeRecord = _make_record_keeping_db_fields(  # type: ignore[method-assign]
                logging.Logger.makeRecord
            )
        targets: list[logging.Filterer] = [logging.getLogger(name) for name in DB_ERROR_LOGGERS]
        if logging.lastResort is not None:
            targets.append(logging.lastResort)
        for target in targets:
            if not any(isinstance(f, DbErrorRedactionFilter) for f in target.filters):
                target.addFilter(DbErrorRedactionFilter())
