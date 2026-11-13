"""Logging calls pass error objects, not their text (finding B-06-1, TABRION MIG-AXE-3, review MIG-AXE-0 L-2).

Tabrion's ``DbErrorRedactionFilter`` replaces a database error that a log record holds as an object by its safe
message, and the known texts of that object (``str``, ``repr``, its ``DETAIL`` value) wherever they appear. A text
formatted before the call (an f-string, ``%`` or ``.format()`` on the message, ``str(exc)`` or ``repr(exc)`` as an
argument) leaves only the labeled server text parts to remove: a value in the first line of the message (for
example ``invalid input syntax for type integer: "..."``) stays (accepted residual R-1). This rule keeps Axentra's
own logging calls on the object form: ``logger.error("insert failed: %s", exc)``.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parents[2] / "src" / "axentra"
LEVELS = frozenset({"debug", "info", "warning", "warn", "error", "exception", "critical", "log"})
LOGGER_NAMES = frozenset({"logger", "log", "_log", "_logger", "LOGGER", "logging"})


def _is_logger(node: ast.expr) -> bool:
    if isinstance(node, ast.Name):
        return node.id in LOGGER_NAMES
    if isinstance(node, ast.Attribute):
        return node.attr in LOGGER_NAMES
    # logging.getLogger("...").error(...)
    return (
        isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "getLogger"
    )


def _preformatted(node: ast.expr) -> str | None:
    if isinstance(node, ast.JoinedStr):
        return "f-string message"
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod):
        return "message formatted with %"
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "format":
        return "message formatted with .format()"
    return None


def _text_of_object(node: ast.expr) -> str | None:
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id in ("str", "repr", "ascii")
    ):
        return f"{node.func.id}(...) as an argument"
    return None


def violations(source: str, name: str = "<src>") -> list[str]:
    found: list[str] = []
    for node in ast.walk(ast.parse(source)):
        if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)):
            continue
        if node.func.attr not in LEVELS or not _is_logger(node.func.value):
            continue
        args = node.args[1:] if node.func.attr == "log" else node.args
        if not args:
            continue
        problems = [_preformatted(args[0])] + [_text_of_object(a) for a in args[1:]]
        found.extend(f"{name}:{node.lineno}: {p}" for p in problems if p is not None)
    return found


def test_axentra_logs_error_objects_not_their_text() -> None:
    found: list[str] = []
    for path in sorted(SRC.rglob("*.py")):
        found.extend(violations(path.read_text(encoding="utf-8"), str(path.relative_to(SRC.parent.parent))))
    assert found == []


@pytest.mark.parametrize(
    "source",
    [
        'logger.error(f"insert failed: {exc}")',
        'logger.error("insert failed: %s" % exc)',
        'logger.warning("insert failed: {}".format(exc))',
        'logger.error("insert failed: %s", str(exc))',
        'logger.debug("insert failed: %r", repr(exc))',
        'log.exception("failed %s", ascii(exc))',
        'logging.getLogger("x").error(f"{exc}")',
        'self.logger.info(f"{exc}")',
        'logger.log(40, f"{exc}")',
    ],
)
def test_the_rule_finds_preformatted_text(source: str) -> None:
    assert violations(source) != []


@pytest.mark.parametrize(
    "source",
    [
        'logger.error("insert failed: %s", exc)',
        'logger.exception("insert failed")',
        'logger.warning("job %s failed", job_id, exc_info=True)',
        'logger.error("type %s", type(exc).__name__)',
        'logger.log(40, "x %s", exc)',
        'print(f"{exc}")',
    ],
)
def test_the_rule_allows_error_objects(source: str) -> None:
    assert violations(source) == []
