"""The statement splitter is Tabrion's and splits Axentra's migrations byte-identically (TABRION MIG-AXE-2, G-AX-7).

``tests/evidence/golden/statements.json`` was written with Axentra's own splitter before the step (master
``b91e05a``): the statements of every migration file of Axentra and the Taskboard example, and the test vectors of
``tests/integration/test_migrations.py`` plus edge cases where both splitters agree. ``tabrion.sql.split_statements``
must give exactly those statements; ``axentra.data.migrations.split_statements`` stays importable (G-AX-6).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from tabrion.sql import split_statements as tabrion_split

from axentra.data.migrations import split_statements

ROOT = Path(__file__).resolve().parents[2]
GOLDEN = json.loads((ROOT / "tests" / "evidence" / "golden" / "statements.json").read_text(encoding="utf-8"))


def test_the_reexport_is_tabrions_function() -> None:
    assert split_statements is tabrion_split


@pytest.mark.parametrize("path", sorted(GOLDEN["files"]))
def test_every_migration_file_splits_as_before(path: str) -> None:
    sql = (ROOT / path).read_text(encoding="utf-8")
    assert split_statements(sql) == GOLDEN["files"][path]


@pytest.mark.parametrize("name", sorted(GOLDEN["vectors"]))
def test_vectors_split_as_before(name: str) -> None:
    vector = GOLDEN["vectors"][name]
    assert split_statements(vector["sql"]) == vector["statements"]


def test_the_golden_file_covers_every_migration_of_the_step() -> None:
    files = {str(p.relative_to(ROOT)) for d in ("src", "examples") for p in (ROOT / d).rglob("*.sql")}
    # Migrations added after the step are not in the before-snapshot; every file it holds must still exist.
    assert set(GOLDEN["files"]) <= files
    assert len(GOLDEN["files"]) == 15
