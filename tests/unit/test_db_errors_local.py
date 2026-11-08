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


# --- TABRION TB-031 (Tabrion review H-1, H-2, M-2, N-1, N-2, N-3) ---------------------------------------------------

SECRET = "SECRET-4711"


def _unique(detail: str = f"Key (email)=({SECRET}) already exists.") -> psycopg.Error:
    return psycopg.errors.UniqueViolation(
        f'duplicate key value violates unique constraint "u_key"\nDETAIL:  {detail}'
    )


def _filtered(msg: object, args: object = None, exc: BaseException | None = None) -> logging.LogRecord:
    exc_info = (type(exc), exc, exc.__traceback__) if exc is not None else None
    record = logging.LogRecord("x", logging.ERROR, __file__, 1, msg, args, exc_info)  # type: ignore[arg-type]
    assert DbErrorRedactionFilter().filter(record) is True
    return record


def _raised_in_handler(handled: BaseException, raised: BaseException) -> BaseException:
    """``raised``, raised inside ``except`` for ``handled``: Python sets ``raised.__context__ = handled``."""
    try:
        try:
            raise handled
        except BaseException:
            raise raised  # noqa: B904 - the implicit context is the point
    except BaseException as exc:
        return exc


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        (f"dup key DETAIL:  Key (e)=({SECRET})", "dup key"),
        (f"a\nDETAIL:  {SECRET}\nHINT:  {SECRET}", "a"),
        (f"x ('dup\\nDETAIL:  {SECRET}')", "x ('dup"),  # escaped (repr) form
        (f"x ('dup\\r\\nHINT:  {SECRET}') tail", "x ('dup"),
        (f"a\nDETAIL:  Key (e)=(l1\n{SECRET}-2\n{SECRET}-3) already exists.", "a"),  # M-2
        (f"a\nDETAIL:  Key (e)=(l1\n+-{SECRET}) already exists.", "a"),  # N-1
        (f'a\nDETAIL:  Key (e)=(l1\nFile "{SECRET}) already exists.', "a"),  # N-1
        (f"a\nDETAIL:  Key (e)=(l1\n[SQL: {SECRET}) already exists.", "a"),  # N-1
        ("plain text", "plain text"),
    ],
)
def test_strip_server_text_forms(text: str, expected: str) -> None:
    assert db_errors.strip_server_text(text) == expected


def test_strip_server_text_ends_at_traceback_structure() -> None:
    text = (
        f"RuntimeError: quoting dup\nDETAIL:  Key (e)=(l1\n{SECRET}) already exists.\n\n"
        "The above exception was the direct cause of the following exception:\n\n"
        "Traceback (most recent call last):\n"
        '  File "/srv/app.py", line 12, in save\n'
        "    run()\n"
        "ValueError: next"
    )
    out = db_errors.strip_server_text(text)
    assert SECRET not in out
    assert "The above exception was the direct cause" in out
    assert 'File "/srv/app.py", line 12, in save' in out and "ValueError: next" in out


@pytest.mark.parametrize(
    ("msg", "args"),
    [
        ("x %s", ([_unique()],)),
        ("x %s", ((_unique(),),)),
        ("x %s", ({_unique()},)),
        ("x %s", ({"k": [_unique()]},)),
        ("x %s", (RuntimeError(_unique()),)),
        ({"err": _unique()}, None),
        ([_unique()], None),
    ],
)
def test_errors_inside_containers_are_found(msg: object, args: object) -> None:
    record = _filtered(msg, args)
    text = record.getMessage()
    assert SECRET not in text and "DETAIL" not in text
    assert "unique violation (SQLSTATE 23505)" in text
    assert record.db_sqlstate == "23505"  # type: ignore[attr-defined]


def test_collect_is_bounded_and_survives_cycles() -> None:
    cyclic: list[object] = []
    cyclic.append(cyclic)
    cyclic.append(_unique())
    mapping: dict[str, object] = {}
    mapping["self"] = mapping
    mapping["e"] = _unique()
    for value in (cyclic, mapping):
        found: list[BaseException] = []
        db_errors._collect(value, found)
        assert len(found) == 1
    # Beyond the bounds, the error object is not found; the escaped DETAIL of its repr is still removed.
    deep: object = _unique()
    for _ in range(6):
        deep = [deep]
    late = [*range(2_000), _unique()]
    for value in (deep, late):
        found = []
        db_errors._collect(value, found)
        assert found == []
        text = _filtered("x %s", (value,)).getMessage()
        assert SECRET not in text and "DETAIL" not in text


def test_n2_container_whose_iteration_fails_keeps_the_record() -> None:
    class BadList(list[int]):
        def __iter__(self):  # type: ignore[no-untyped-def]
            raise RuntimeError("lazy collection")

    record = _filtered("hello %s", (BadList([1]),))
    assert record.msg == "hello %s"  # not replaced by the fallback message
    assert "DbErrorRedactionFilter" not in logging.Formatter().format(record)


def test_fast_path_does_not_format_plain_records(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []
    real = logging.LogRecord.getMessage

    def counting(self: logging.LogRecord) -> str:
        calls.append("x")
        return real(self)

    monkeypatch.setattr(logging.LogRecord, "getMessage", counting)
    _filtered("job %s took %d ms (%s)", ("a", 3, None))
    assert calls == []
    # A str argument with a label, a non-plain argument or a str subclass is formatted and checked.
    for args in [(f"x\nDETAIL:  {SECRET}",), ([1],), (type("S", (str,), {})("s"),)]:
        record = _filtered("x %s", args)
        assert SECRET not in record.getMessage()
    assert len(calls) >= 3


def test_notes_on_a_driver_error_are_dropped() -> None:
    e = _unique()
    e.add_note(f"params={SECRET}")
    record = _filtered("failed", None, e)
    assert SECRET not in logging.Formatter().format(record)


def test_group_whose_only_database_error_is_a_member() -> None:
    group = ExceptionGroup("batch", [ValueError("other"), _unique()])
    assert group.__context__ is None
    text = logging.Formatter().format(_filtered("batch failed", None, group))
    assert SECRET not in text and "SQLSTATE 23505" in text


def _lost() -> psycopg.Error:
    return psycopg.OperationalError("consuming input failed: server closed the connection unexpectedly")


@pytest.mark.parametrize("handled", ["40001", "40P01", "55P03", "23505"])
def test_h1_lost_commit_inside_a_handler_is_named_by_itself(handled: str) -> None:
    older = psycopg.errors.lookup(handled)("older error")
    lost = _raised_in_handler(older, _lost())
    assert lost.__context__ is older
    assert db_errors.primary_db_error(lost) is lost
    record = _filtered("commit failed", None, lost)
    assert record.db_sqlstate is None  # type: ignore[attr-defined]
    assert db_errors.safe_error_text(lost).startswith("database client error")


def test_h1_context_is_a_fallback_only() -> None:
    # A plain wrapper raised in a handler: the context is the only database error, so it is used.
    wrapped = _raised_in_handler(_unique(), RuntimeError("save failed"))
    assert db_errors.primary_db_error(wrapped) is wrapped.__context__
    # ``raise ... from None`` suppresses the context: nothing is followed.
    suppressed = RuntimeError("save failed")
    suppressed.__context__ = _unique()
    suppressed.__suppress_context__ = True
    assert db_errors.primary_db_error(suppressed) is None
    # The cause chain wins over an older context, at any depth.
    outer = RuntimeError("outer")
    outer.__cause__ = RuntimeError("retry layer")
    outer.__cause__.__context__ = psycopg.errors.lookup("40001")("older")
    outer.__suppress_context__ = False
    outer.__context__ = _lost()
    # Both are reached through a context only: the loss is reached first.
    assert db_errors.primary_db_error(outer) is outer.__context__
    caused = RuntimeError("outer")
    caused.__context__ = psycopg.errors.lookup("40001")("handled")
    caused.__cause__ = _unique()
    caused.__suppress_context__ = False  # a context that is printed too still yields to the cause
    assert db_errors.primary_db_error(caused) is caused.__cause__
    record = _filtered("failed", None, caused)
    assert record.db_sqlstate == "23505"  # type: ignore[attr-defined]


def test_h1_outermost_connection_loss_wins_over_a_cause() -> None:
    outer = _lost()
    outer.__cause__ = psycopg.errors.lookup("40001")("inner")
    assert db_errors.primary_db_error(outer) is outer
    terminated = psycopg.errors.lookup("57P01")("terminated")
    terminated.__cause__ = _unique()
    assert db_errors.primary_db_error(terminated) is terminated
    # A driver error without SQLSTATE that is no connection loss yields to the first one with a SQLSTATE.
    programming = psycopg.ProgrammingError("2 placeholders")
    programming.__cause__ = _unique()
    assert db_errors.primary_db_error(programming) is programming.__cause__
