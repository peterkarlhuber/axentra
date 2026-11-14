"""Database errors without the values they carry (finding B-06-1), through ``tabrion.errors`` (TABRION MIG-AXE-3).

A PostgreSQL error carries the server's ``DETAIL`` (and ``HINT``, ``CONTEXT``), and for a constraint violation
that text holds the offending values: ``Key (email)=(someone@example.com) already exists.`` or
``Failing row contains (...)``. ``str(exc)`` of a psycopg error includes it, and so does every traceback that
logging prints for it.

The redaction itself is Tabrion's: :func:`safe_message` describes a database error by its kind, SQLSTATE and
object names only (``unique violation (SQLSTATE 23505, constraint users_email_key, table users)``), and
:class:`DbErrorRedactionFilter` rewrites log records so that their text, arguments and tracebacks carry that
description instead of the server's text. Both are ``tabrion.errors`` and re-exported here. This module keeps only
what Axentra adds around them:

- :func:`install_db_error_redaction` applies the filter to every log record of the process (Tabrion installs it
  nowhere), and makes the report of a failed ``emit`` and ``extra=`` with the record fields safe;
- :func:`safe_error_text` and :func:`redacted_traceback` give the same redaction for texts that are stored or
  exported (job and notification ``last_error``, trace spans);
- :func:`strip_server_text` for a text whose error object is gone;
- :func:`redact_db_errors_processor`, an optional structlog processor;
- :func:`redacted_excepthook`, :func:`redacted_threading_excepthook` and :func:`redacted_unraisablehook`, which
  the CLI installs (:func:`install_redacted_excepthooks`) for uncaught and unraisable exceptions.

Each of them runs Tabrion's filter on a record of its own, so there is one redaction rule (no second copy of the
patterns here). TABRION MIG-AXE-3 replaced Axentra's local fix (TABRION MIG-AXE-0); its regression tests in
``tests/integration/test_db_error_logging.py`` stay.
"""

from __future__ import annotations

from collections.abc import Mapping
import contextlib
import logging
import sys
import threading
import traceback
from types import BuiltinFunctionType, FunctionType, MethodType, TracebackType
from typing import Any

from tabrion.errors import DbErrorRedactionFilter, safe_message

__all__ = [
    "DB_ERROR_LOGGERS",
    "DbErrorRedactionFilter",
    "install_db_error_redaction",
    "install_redacted_excepthooks",
    "redact_db_errors_processor",
    "redacted_excepthook",
    "redacted_threading_excepthook",
    "redacted_traceback",
    "redacted_unraisablehook",
    "safe_error_text",
    "safe_message",
    "strip_server_text",
]

#: The two record attributes the filter sets; ``extra=`` may still pass them (review F-6).
DB_FIELDS = ("db_sqlstate", "db_constraint")
#: The filter instance the helpers below run on records of their own. It keeps no state between calls.
_REDACTION = DbErrorRedactionFilter()


def _redacted_record(
    msg: object,
    args: tuple[object, ...] | None,
    exc: BaseException | None = None,
    tb: TracebackType | None = None,
) -> logging.LogRecord:
    """A log record of ``msg % args`` (with ``exc`` as its ``exc_info``) after Tabrion's filter has run on it.

    The record is built directly, not through the record factory, so the filter runs exactly once."""
    exc_info = None
    if exc is not None:
        exc_info = (type(exc), exc, tb if tb is not None else exc.__traceback__)
    record = logging.LogRecord(__name__, logging.ERROR, __file__, 0, msg, args, exc_info)
    _REDACTION.filter(record)
    return record


def _plain_traceback(exc: BaseException, tb: TracebackType | None) -> str:
    return "".join(traceback.format_exception(type(exc), exc, tb if tb is not None else exc.__traceback__))


def safe_error_text(exc: BaseException) -> str:
    """Text for ``exc`` that may be stored or shown (for example a job's ``last_error``).

    A database error becomes its :func:`safe_message`. Any other exception keeps ``str(exc)``, in which the text of
    the database errors it was raised from (or that it holds in its ``args``) is replaced by their safe message and
    every server text part (``DETAIL:``, ``HINT:``, ``CONTEXT:``) is removed, as Tabrion's filter does for a log
    message."""
    try:
        return _redacted_record("%s", (exc,)).getMessage()
    except Exception:
        # ``str(exc)`` itself failed (a broken ``__str__``): Tabrion's message never holds a value.
        return safe_message(exc)


def redacted_traceback(exc: BaseException, tb: TracebackType | None = None) -> str:
    """The formatted traceback of ``exc`` (as :meth:`logging.Formatter.formatException` prints it) in which no
    exception of the chain carries the values of a database error; file names and line numbers stay.

    Tabrion's filter redacts the traceback of an exception whose chain or ``args`` hold a database error, or whose
    message, ``args`` or notes hold database server text; any other traceback is formatted unchanged."""
    record = _redacted_record("", None, exc, tb)
    if isinstance(record.exc_text, str) and record.exc_info is None:
        return record.exc_text
    return _plain_traceback(exc, tb).rstrip("\n")


def redact_db_errors_processor(logger: object, method_name: str, event_dict: Any) -> Any:
    """A structlog processor that removes database values from an event dict (review D-2).

    Optional and import-free: Axentra does not depend on structlog. It runs Tabrion's filter on the event dict as a
    mapping message: ``exc_info`` (``True``, an exception or an ``exc_info`` tuple) that names a database error or
    its text is replaced by the redacted traceback under ``exception``, and every value is scrubbed. Put it into
    structlog's processor chain **before** ``format_exc_info``, ``dict_tracebacks`` or the renderer
    (``ConsoleRenderer`` renders ``exc_info`` itself), in the logger's ``processors`` (where ``exc_info=True`` still
    names the exception being handled). It never raises: when the event dict cannot be redacted as a mapping, it
    returns only the ``event`` text, redacted."""
    if not isinstance(event_dict, Mapping):
        return event_dict
    try:
        record = _redacted_record(dict(event_dict), None)
        if isinstance(record.msg, Mapping):
            return dict(record.msg)
        event = event_dict.get("event")
        return {"event": strip_server_text(event) if isinstance(event, str) else "event redacted"}
    except Exception:
        return {"event": "event redacted"}


def strip_server_text(text: str) -> str:
    """``text`` (a message formatted before it reaches here) without database server text parts (``DETAIL:``, ``HINT:``, ``CONTEXT:``, SQLAlchemy's
    ``[parameters: ...]``), as Tabrion's filter removes them from a log message that was formatted before it was
    logged. The error object is not known here, so only these labeled parts can be removed."""
    try:
        return _redacted_record("%s", (text,)).getMessage()
    except Exception:
        return "text redacted"


def redacted_excepthook(exc_type: type[BaseException], exc: BaseException, tb: TracebackType | None) -> None:
    """A :data:`sys.excepthook` that prints the traceback of an uncaught exception without database values.

    The interpreter prints an uncaught exception with its whole chain, outside any log filter: for an exception
    raised from a database error that is the ``DETAIL`` text with row values. The CLI installs this hook (an
    application that embeds Axentra decides on its own hooks)."""
    _write_redacted(None, exc_type, exc, tb)


def _write_redacted(
    header: str | None,
    exc_type: type[BaseException],
    exc: BaseException | None,
    tb: TracebackType | None,
) -> None:
    """Print ``header`` (if any) and the traceback of ``exc`` without database values to stderr; never raises."""
    try:
        if exc is None:
            exc = exc_type()
        text = redacted_traceback(exc, tb)
    except Exception:
        message = safe_message(exc) if exc is not None else ""
        text = f"{exc_type.__module__}.{exc_type.__qualname__}: {message}"
    if header is not None:
        text = f"{header}\n{text}"
    with contextlib.suppress(Exception):
        if sys.stderr is not None:
            sys.stderr.write(text + "\n")
            sys.stderr.flush()


def redacted_threading_excepthook(args: threading.ExceptHookArgs) -> None:
    """A :data:`threading.excepthook` that prints an exception that ended a thread without database values (N-3).

    The standard hook prints the whole chain to stderr outside any log filter, as :data:`sys.excepthook` does.
    ``SystemExit`` stays silent, as there."""
    if args.exc_type is SystemExit:
        return
    name = args.thread.name if args.thread is not None else str(threading.get_ident())
    _write_redacted(f"Exception in thread {name}:", args.exc_type, args.exc_value, args.exc_traceback)


def redacted_unraisablehook(unraisable: Any) -> None:
    """A :data:`sys.unraisablehook` (an exception raised in ``__del__``, a finalizer or a weakref callback) that
    prints its traceback without database values (N-3). The object is named by its qualified name (a function) or
    its type only: its ``repr`` may hold values."""
    header = unraisable.err_msg or "Exception ignored in"
    obj = unraisable.object
    if isinstance(obj, (FunctionType, MethodType, BuiltinFunctionType)):
        header = f"{header}: <{type(obj).__name__} {obj.__qualname__}>"
    elif obj is not None:
        header = f"{header}: <{type(obj).__qualname__} object>"
    _write_redacted(header, unraisable.exc_type, unraisable.exc_value, unraisable.exc_traceback)


def install_redacted_excepthooks() -> None:
    """Install :func:`redacted_excepthook`, :func:`redacted_threading_excepthook` and
    :func:`redacted_unraisablehook` as ``sys.excepthook``, ``threading.excepthook`` and ``sys.unraisablehook``,
    each only where the interpreter's default is still in place (a hook set by the operator stays). The CLI calls
    it; the library sets no hooks (an application that embeds Axentra decides on its own)."""
    if sys.excepthook is sys.__excepthook__:
        sys.excepthook = redacted_excepthook
    if threading.excepthook is threading.__excepthook__:
        threading.excepthook = redacted_threading_excepthook
    if sys.unraisablehook is sys.__unraisablehook__:
        sys.unraisablehook = redacted_unraisablehook


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
    prints the same report through Tabrion's filter: the redacted traceback, and the message and arguments with the
    text of every database error involved replaced."""
    if not (logging.raiseExceptions and sys.stderr):
        return
    _, value, tb = sys.exc_info()
    try:
        exc = value if isinstance(value, BaseException) else None
        report = _redacted_record("Message: %r\nArguments: %r", (record.msg, record.args), exc, tb)
        lines = ["--- Logging error ---"]
        if exc is not None:
            if isinstance(report.exc_text, str) and report.exc_info is None:
                lines.append(report.exc_text)
            else:
                lines.append(_plain_traceback(exc, tb).rstrip("\n"))
        lines.append(report.getMessage())
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
    """Redact database error values from every log record of the process (B-06-1, TABRION MIG-AXE-3).

    Wraps the log record factory (:func:`logging.setLogRecordFactory`, chained to the factory in place) so that
    Tabrion's :class:`DbErrorRedactionFilter` runs on each record when it is created, before any handler,
    formatter or ``logging.lastResort`` sees it, whoever configured logging. Also adds the filter to
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
