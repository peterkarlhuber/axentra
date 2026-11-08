"""Rollback evidence of the old code (TABRION QA-13): the snapshots of ``tests/evidence/snapshots.py``.

The golden files in ``tests/evidence/golden/`` were written from the old code (``tests/evidence/golden/SOURCE.md``).
Each TABRION MIG-AXE step and its revert must leave them unchanged unless the step's pull request rewrites a file on
purpose (reviewed diff). Two runs on two fresh databases must write identical snapshots, so a difference is a change
of behaviour, never noise of the run.
"""

from __future__ import annotations

from collections.abc import Iterator
import json
import os
from typing import Any

import pytest

from tests.conftest import ADMIN_URL
from tests.evidence import snapshots

pytestmark = pytest.mark.postgres

#: Prefix of the databases and roles of the runs (each run drops its own objects again).
PREFIX = os.environ.get("AXENTRA_TEST_EVIDENCE_PREFIX", "axentra_ev_")


@pytest.fixture(scope="module")
def runs() -> Iterator[list[dict[str, dict[str, Any]]]]:
    if not ADMIN_URL:
        pytest.skip("AXENTRA_TEST_DATABASE_URL is not set; PostgreSQL integration tests not executed")
    yield [snapshots.collect(ADMIN_URL, PREFIX), snapshots.collect(ADMIN_URL, PREFIX)]


@pytest.mark.parametrize("name", snapshots.NAMES)
def test_snapshot_equals_the_old_code(runs: list[dict[str, dict[str, Any]]], name: str) -> None:
    text = snapshots.diff(name, snapshots.golden(name), runs[0][name])
    assert not text, f"the {name} snapshot differs from the old code:\n{text}"


@pytest.mark.parametrize("name", snapshots.NAMES)
def test_two_runs_write_identical_snapshots(runs: list[dict[str, dict[str, Any]]], name: str) -> None:
    assert snapshots.dumps(runs[0][name]) == snapshots.dumps(runs[1][name])


@pytest.mark.parametrize("name", snapshots.NAMES)
def test_golden_files_are_canonical(name: str) -> None:
    path = snapshots.GOLDEN / f"{name}.json"
    assert path.read_text("utf-8") == snapshots.dumps(json.loads(path.read_text("utf-8")))


def test_no_object_of_a_run_is_left_behind(runs: list[dict[str, dict[str, Any]]]) -> None:
    import psycopg

    assert ADMIN_URL
    with psycopg.connect(ADMIN_URL, autocommit=True) as conn:
        left = conn.execute(
            "SELECT datname FROM pg_database WHERE datname LIKE %s"
            " UNION ALL SELECT rolname FROM pg_roles WHERE rolname LIKE %s",
            (PREFIX + "%", PREFIX + "%"),
        ).fetchall()
    assert left == []


def test_the_catalog_snapshot_shows_forced_row_level_security() -> None:
    """The golden catalog holds what document 07 (AX-I-6) names: 34 tables with FORCE ROW LEVEL SECURITY."""
    summary = snapshots.golden("catalog")["summary"]
    assert summary["force_row_security"] == summary["row_security"] == 34


def test_the_role_table_has_eight_variants() -> None:
    table = snapshots.golden("roles")
    assert len(table["variants"]) == 8 and set(table["table"]) == set(table["variants"])
