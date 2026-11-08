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
"""

from __future__ import annotations

from collections.abc import Mapping
import logging
import re
import sqlite3
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
#: The lines psycopg appends to a server error's message (``DETAIL:  Key (email)=(...) already exists.``,
#: ``HINT:``, ``CONTEXT:``, and ``QUERY:`` / ``LINE n:`` with statement text): removed from every text this
#: module returns, wherever they come from (a message formatted before it was logged, a wrapper's text).
_SERVER_TEXT_LINE = re.compile(r"(?m)^[ \t]*(?:DETAIL|HINT|CONTEXT|QUERY|LINE \d+):.*(?:\r?\n|$)")
#: The same labels in the middle of a line (a message whose newlines were replaced): psycopg puts two spaces
#: after the colon. Removes the rest of the line.
_SERVER_TEXT_INLINE = re.compile(r"[ \t]*\b(?:DETAIL|HINT|CONTEXT): {2}.*")
#: Cheap test whether a text may hold such a line.
_SERVER_TEXT_MARKERS = ("DETAIL:", "HINT:", "CONTEXT:")


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
    adds to a server error's message."""
    if not any(marker in text for marker in _SERVER_TEXT_MARKERS):
        return text
    return _SERVER_TEXT_INLINE.sub("", _SERVER_TEXT_LINE.sub("", text)).rstrip("\n")


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


def scrub_text(text: str, errors: list[BaseException]) -> str:
    """``text`` with the text of each database error in ``errors`` replaced by its :func:`safe_message`, the
    values of their ``DETAIL``, ``HINT`` and ``CONTEXT`` replaced by ``[redacted]``, and every psycopg server text
    line removed (see :func:`strip_server_text`)."""
    for err in errors:
        whole = str(err)
        if whole and whole in text:
            text = text.replace(whole, safe_message(err))
        diag = getattr(_driver_error(err), "diag", None)
        for part in ("message_detail", "message_hint", "context"):
            value = getattr(diag, part, None) if diag is not None else None
            if isinstance(value, str) and value and value in text:
                text = text.replace(value, "[redacted]")
    return strip_server_text(text)


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
    - the final message loses the text of the database errors involved and every psycopg server text line
      (``DETAIL:``, ``HINT:``, ``CONTEXT:``), also when the message was formatted before it was logged;
    - ``db_sqlstate`` and ``db_constraint`` name the first database error found (for JSON formatters).

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
        found: list[BaseException] = _db_errors_in(exc) if isinstance(exc, BaseException) else []

        def note(value: object) -> None:
            if isinstance(value, BaseException):
                found.extend(e for e in _db_errors_in(value) if e not in found)

        args: Any = record.args
        suspicious = _may_hold_server_text(record.msg)
        if isinstance(args, tuple):
            for a in args:
                note(a)
                suspicious = suspicious or _may_hold_server_text(a)
            if any(_is_db_exc(a) for a in args):
                record.args = tuple(safe_message(a) if _is_db_exc(a) else a for a in args)
        elif isinstance(args, Mapping):
            for v in args.values():
                note(v)
                suspicious = suspicious or _may_hold_server_text(v)
            if any(_is_db_exc(v) for v in args.values()):
                record.args = {k: safe_message(v) if _is_db_exc(v) else v for k, v in args.items()}
        note(record.msg)
        if isinstance(record.msg, BaseException) and is_db_error(record.msg):
            record.msg = safe_message(record.msg)

        if isinstance(exc, BaseException) and found:
            record.exc_text = redacted_traceback(exc, record.exc_info[2], found)  # type: ignore[index]
            record.exc_info = None
        elif isinstance(record.exc_text, str) and _may_hold_server_text(record.exc_text):
            record.exc_text = strip_server_text(record.exc_text)

        if found or suspicious:
            try:
                message = record.getMessage()
            except Exception:
                # A broken call (for example too few arguments): keep the record and say what failed.
                template = scrub_text(str(record.msg), found)
                summary = "; ".join(safe_message(e) for e in found)
                record.msg = f"log message could not be formatted: {template!r}" + (
                    f" ({summary})" if summary else ""
                )
                record.args = None
            else:
                redacted = scrub_text(message, found)
                if redacted != message:
                    record.msg, record.args = redacted, None
        if found:
            sqlstate, constraint = db_error_fields(found[0])
            record.db_sqlstate = sqlstate
            record.db_constraint = constraint


#: Loggers that also get the filter itself (besides the record factory), so that records created there are
#: redacted however they were made: Axentra's error handlers and uvicorn's "Exception in ASGI application"
#: (``uvicorn.error`` has its own handler and does not propagate).
DB_ERROR_LOGGERS = ("axentra.http", "uvicorn.error")
_FACTORY_MARK = "_axentra_db_error_redaction"
_INSTALL_LOCK = threading.Lock()


def install_db_error_redaction() -> None:
    """Redact database error values from every log record of the process (B-06-1, TABRION MIG-AXE-0).

    Wraps the log record factory (:func:`logging.setLogRecordFactory`, chained to the factory in place) so that
    :class:`DbErrorRedactionFilter` runs on each record when it is created, before any handler, formatter or
    ``logging.lastResort`` sees it, whoever configured logging. Also adds the filter to
    :data:`DB_ERROR_LOGGERS` and ``logging.lastResort``. Installing twice is harmless.
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
        targets: list[logging.Filterer] = [logging.getLogger(name) for name in DB_ERROR_LOGGERS]
        if logging.lastResort is not None:
            targets.append(logging.lastResort)
        for target in targets:
            if not any(isinstance(f, DbErrorRedactionFilter) for f in target.filters):
                target.addFilter(DbErrorRedactionFilter())
