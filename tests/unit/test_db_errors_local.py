"""Internals of Axentra's local database error redaction (``axentra.core.db_errors``, TABRION MIG-AXE-0).

Unlike ``tests/integration/test_db_error_logging.py`` (observable behavior, kept after TABRION MIG-AXE-3), these
tests pin details of the local module; MIG-AXE-3 removes this file together with the module.
"""

from __future__ import annotations

import logging
import traceback

import psycopg
import pytest

from axentra.core import db_errors
from axentra.core.db_errors import DbErrorRedactionFilter, install_db_error_redaction, safe_message


def test_traceback_exception_still_has_str() -> None:
    """``redacted_traceback`` replaces ``TracebackException._str``; without it, it would fall back to a summary
    without file names and line numbers. Fail loudly on a Python version that drops the attribute."""
    try:
        raise ValueError("x")
    except ValueError as exc:
        te = traceback.TracebackException.from_exception(exc)
    assert te._str == "x"  # type: ignore[attr-defined]
    assert hasattr(te, "exceptions")


def test_install_is_idempotent() -> None:
    install_db_error_redaction()
    factory = logging.getLogRecordFactory()
    install_db_error_redaction()
    assert logging.getLogRecordFactory() is factory
    assert sum(isinstance(f, DbErrorRedactionFilter) for f in logging.getLogger("axentra.http").filters) == 1


def test_internal_failure_keeps_the_record_without_values(monkeypatch: pytest.MonkeyPatch) -> None:
    """L-5: if the redaction itself fails, the record is kept with a fixed message and a summary that has no
    database values (never the original text)."""
    bare = psycopg.errors.UniqueViolation("duplicate key\nDETAIL:  Key (email)=(SECRET-4711) already exists.")

    def broken(*args: object, **kwargs: object) -> str:
        raise RuntimeError("broken")

    monkeypatch.setattr(db_errors, "redacted_traceback", broken)
    record = logging.LogRecord(
        "x", logging.ERROR, __file__, 1, "failed: %s", (bare,), (type(bare), bare, None)
    )
    assert DbErrorRedactionFilter().filter(record) is True
    text = logging.Formatter().format(record)
    assert "SECRET-4711" not in text and "DETAIL" not in text
    assert "replaced by DbErrorRedactionFilter" in text
    assert safe_message(bare) in text


def test_unusual_records_do_not_fail() -> None:
    f = DbErrorRedactionFilter()
    bare = psycopg.errors.UniqueViolation("no diag")
    for record in [
        logging.LogRecord("x", 40, __file__, 1, {"a": 1}, None, None),
        logging.LogRecord("x", 40, __file__, 1, "%s", (bare,), None),
        logging.LogRecord("x", 40, __file__, 1, bare, None, (type(bare), bare, None)),
        logging.LogRecord("x", 40, __file__, 1, "m", None, (None, None, None)),
        logging.LogRecord("x", 40, __file__, 1, "m %(a)s", ({"a": bare},), None),
    ]:
        assert f.filter(record) is True
        logging.Formatter().format(record)
    assert safe_message(bare) == "unique violation (SQLSTATE 23505)"
