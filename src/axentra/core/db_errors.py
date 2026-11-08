"""Database errors without the values they carry (finding B-06-1).

A PostgreSQL error carries the server's ``DETAIL`` (and ``HINT``, ``CONTEXT``), and for a constraint violation
that text holds the offending values: ``Key (email)=(someone@example.com) already exists.`` or
``Failing row contains (...)``. ``str(exc)`` of a psycopg error includes it, and so does every traceback that
logging prints for it. :func:`safe_message` describes such an error from its SQLSTATE and constraint name only,
and :class:`DbErrorRedactionFilter` rewrites log records so that their text, arguments and tracebacks carry that
description instead of the server's text.

This is Axentra's local fix (TABRION MIG-AXE-0). TABRION MIG-AXE-3 replaces it with ``tabrion.errors``
(``safe_message``, ``DbErrorRedactionFilter``), which behaves the same way; the regression tests in
``tests/integration/test_db_error_logging.py`` check only the observable output and stay.

Database errors are recognized without importing a driver: psycopg (and psycopg2) errors by their module,
:class:`sqlite3.Error`, and wrappers that keep the driver error in ``orig`` (SQLAlchemy's ``DBAPIError``).
"""

from __future__ import annotations

from collections.abc import Iterator
import logging
import re
import sqlite3
import traceback
from types import TracebackType
from typing import Any

from axentra.core.redaction import redact_text

__all__ = ["DbErrorRedactionFilter", "db_error_fields", "is_db_error", "safe_message"]

_DRIVER_PACKAGES = frozenset({"psycopg", "psycopg2"})
#: How far :func:`_chain` follows ``__cause__``, ``__context__`` and ``orig``.
_MAX_DEPTH = 5

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
#: Lines of a client-side psycopg message that would carry server text (a client error has no SQLSTATE).
_SERVER_TEXT_LINE = re.compile(r"(?m)^\s*(?:DETAIL|HINT|CONTEXT|QUERY|LINE \d+):.*$\n?")


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
        text = redact_text(_SERVER_TEXT_LINE.sub("", str(err))).strip()
        return f"database client error: {text}" if text else "database client error"
    kind = _KIND_BY_SQLSTATE.get(sqlstate) or _KIND_BY_CLASS.get(sqlstate[:2], "database error")
    parts = [f"SQLSTATE {sqlstate}"]
    if constraint:
        parts.append(f"constraint {constraint}")
    return f"{kind} ({', '.join(parts)})"


def _chain(exc: BaseException, depth: int = 0) -> Iterator[BaseException]:
    """``exc`` and the exceptions it was raised from or during, and those of an exception group."""
    yield exc
    if depth >= _MAX_DEPTH:
        return
    for linked in (exc.__cause__, exc.__context__, getattr(exc, "orig", None)):
        if isinstance(linked, BaseException) and linked is not exc:
            yield from _chain(linked, depth + 1)
    for member in getattr(exc, "exceptions", None) or ():
        if isinstance(member, BaseException):
            yield from _chain(member, depth + 1)


def _redact_traceback(te: traceback.TracebackException, exc: BaseException, seen: set[int]) -> None:
    """Replace the text of every database error in ``te`` (built from ``exc``) with :func:`safe_message`."""
    if id(te) in seen:
        return
    seen.add(id(te))
    if is_db_error(exc):
        # ``_str`` is the exception's text that ``format()`` prints after the type name (Python 3.11 to 3.14).
        te._str = safe_message(exc)  # type: ignore[attr-defined]
        te.__notes__ = None
    if te.__cause__ is not None and exc.__cause__ is not None:
        _redact_traceback(te.__cause__, exc.__cause__, seen)
    if te.__context__ is not None and exc.__context__ is not None:
        _redact_traceback(te.__context__, exc.__context__, seen)
    members = getattr(exc, "exceptions", None)
    if te.exceptions and members:
        for sub_te, sub in zip(te.exceptions, members, strict=False):
            if isinstance(sub, BaseException):
                _redact_traceback(sub_te, sub, seen)


def redacted_traceback(exc: BaseException, tb: TracebackType | None = None) -> str:
    """The formatted traceback of ``exc`` (as :meth:`logging.Formatter.formatException` prints it) in which every
    database error of the chain carries :func:`safe_message`; file names and line numbers stay."""
    te = traceback.TracebackException(type(exc), exc, tb if tb is not None else exc.__traceback__)
    if not hasattr(te, "_str"):  # pragma: no cover - a Python version without the attribute
        return "".join(
            f"{type(e).__module__}.{type(e).__qualname__}: {safe_message(e)}\n" for e in _chain(exc)
        )
    _redact_traceback(te, exc, set())
    return "".join(te.format()).rstrip("\n")


class DbErrorRedactionFilter(logging.Filter):
    """A :class:`logging.Filter` that removes the values database errors carry from a log record.

    It never drops a record (:meth:`filter` always returns ``True``); it rewrites it:

    - if ``exc_info`` holds a database error anywhere in its chain, ``exc_text`` (the cached traceback that
      formatters print) becomes :func:`redacted_traceback`;
    - an argument that is a database error is replaced by its :func:`safe_message`, and the text of a database
      error of the chain that already sits in the message is replaced the same way;
    - ``db_sqlstate`` and ``db_constraint`` name the first database error of the chain (for JSON formatters).

    The exception object itself is left unchanged. Install it on handlers (it then covers every record they
    emit) or on the loggers that log such errors (it then also covers handlers it is not installed on, such as
    pytest's ``caplog``).
    """

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            self._redact(record)
        except Exception:  # pragma: no cover - never lose a log record over the redaction
            record.msg, record.args, record.exc_text = (
                "log record dropped by DbErrorRedactionFilter",
                None,
                None,
            )
            record.exc_info = None
        return True

    def _redact(self, record: logging.LogRecord) -> None:
        found: list[BaseException] = []
        exc = record.exc_info[1] if isinstance(record.exc_info, tuple) else None
        if isinstance(exc, BaseException):
            found = [e for e in _chain(exc) if is_db_error(e)]
            if found:
                record.exc_text = redacted_traceback(exc, record.exc_info[2])  # type: ignore[index]
        args: Any = record.args
        arg_errors: list[BaseException] = []
        if isinstance(args, tuple) and any(isinstance(a, BaseException) and is_db_error(a) for a in args):
            arg_errors = [a for a in args if isinstance(a, BaseException) and is_db_error(a)]
            record.args = tuple(safe_message(a) if a in arg_errors else a for a in args)
        if isinstance(record.msg, BaseException) and is_db_error(record.msg):
            arg_errors.append(record.msg)
            record.msg = safe_message(record.msg)
        found += [e for e in arg_errors if e not in found]
        if not found:
            return
        message = record.getMessage()
        redacted = message
        for err in found:
            text = str(err)
            if text and text in redacted:
                redacted = redacted.replace(text, safe_message(err))
            diag = getattr(_driver_error(err), "diag", None)
            for part in ("message_detail", "message_hint", "context"):
                value = getattr(diag, part, None) if diag is not None else None
                if isinstance(value, str) and value and value in redacted:
                    redacted = redacted.replace(value, "[redacted]")
        if redacted != message:
            record.msg, record.args = redacted, None
        sqlstate, constraint = db_error_fields(found[0])
        record.db_sqlstate = sqlstate
        record.db_constraint = constraint
