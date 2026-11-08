"""Rollback evidence of the old code (TABRION QA-13): the snapshots of ``tests/evidence/snapshots.py``.

The golden files in ``tests/evidence/golden/`` were written from the old code (``tests/evidence/golden/SOURCE.md``).
Each TABRION MIG-AXE step and its revert must leave them unchanged unless the step's pull request rewrites a file on
purpose (reviewed diff). Two runs on two fresh databases must write identical snapshots, so a difference is a change
of behaviour, never noise of the run.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
import json
import os
from typing import Any

import pytest

from tests.conftest import ADMIN_URL
from tests.evidence import snapshots

pytestmark = pytest.mark.postgres

#: Prefix of the databases and roles of the runs (each run drops its own objects again).
PREFIX = os.environ.get("AXENTRA_TEST_EVIDENCE_PREFIX", snapshots.DEFAULT_PREFIX)
#: The base names of this module's runs (the leftover check looks only at these, not at parallel runs).
BASES: list[str] = []


def _admin_url() -> str:
    if not ADMIN_URL:
        pytest.skip("AXENTRA_TEST_DATABASE_URL is not set; PostgreSQL integration tests not executed")
    return ADMIN_URL


@pytest.fixture(scope="module")
def runs() -> Iterator[list[dict[str, dict[str, Any]]]]:
    url = _admin_url()
    yield [snapshots.collect(url, PREFIX, bases=BASES), snapshots.collect(url, PREFIX, bases=BASES)]


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
    assert ADMIN_URL
    assert len(BASES) == 2
    assert snapshots.leftovers(ADMIN_URL, PREFIX, bases=BASES) == []


# -- what the catalog snapshot detects (M-1 of the QA-13 review) ------------------------------------------------------


@pytest.fixture(scope="module")
def evidence() -> Iterator[tuple[snapshots.EvidenceDatabase, dict[str, Any]]]:
    with snapshots.evidence_database(_admin_url(), PREFIX, bases=BASES) as ev:
        yield ev, snapshots.catalog_snapshot(ev)


def _first_function(ev: snapshots.EvidenceDatabase) -> str:
    import psycopg

    with psycopg.connect(ev.url(), autocommit=True) as conn:
        row = conn.execute(
            "SELECT p.oid::regprocedure::text FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace"
            " WHERE n.nspname = 'public' AND NOT EXISTS (SELECT 1 FROM pg_depend d WHERE d.objid = p.oid"
            " AND d.deptype = 'e') ORDER BY 1 LIMIT 1"
        ).fetchone()
    assert row is not None
    return str(row[0])


def _acl(
    catalog: dict[str, Any], kind: str, obj: str | None, grantee: str, privilege: str, grantable: bool
) -> bool:
    return any(
        e[0] == kind
        and (obj is None or e[1] == obj)
        and e[3] == grantee
        and e[4] == privilege
        and e[5] is grantable
        for e in catalog["acl"]
    )


#: Changes that grant_runtime_role (or a step replacing it) could make; each must change the catalog snapshot.
#: ``{app}``/``{owner}`` are the run's roles, ``{variant}`` another role, ``{function}`` a function of the schema.
#: (change, revert, what the snapshot must then show)
CATALOG_MUTANTS: dict[str, tuple[str, str, Callable[[dict[str, Any]], bool]]] = {
    "column_update_grant": (
        "GRANT UPDATE (checksum) ON axentra_schema_migrations TO {app}",
        "REVOKE UPDATE (checksum) ON axentra_schema_migrations FROM {app}",
        lambda c: _acl(c, "column", "axentra_schema_migrations.checksum", "<app>", "UPDATE", False),
    ),
    "execute_with_grant_option": (
        "GRANT EXECUTE ON FUNCTION {function} TO {app} WITH GRANT OPTION",
        "REVOKE GRANT OPTION FOR EXECUTE ON FUNCTION {function} FROM {app}",
        lambda c: _acl(c, "function", None, "<app>", "EXECUTE", True),
    ),
    "table_grant_to_public": (
        "GRANT SELECT ON axentra_users TO PUBLIC",
        "REVOKE SELECT ON axentra_users FROM PUBLIC",
        lambda c: _acl(c, "relation", "axentra_users", "PUBLIC", "SELECT", False),
    ),
    "grant_to_another_role": (
        "GRANT SELECT ON axentra_users TO {variant}",
        "REVOKE SELECT ON axentra_users FROM {variant}",
        lambda c: _acl(c, "relation", "axentra_users", "<role:restricted>", "SELECT", False),
    ),
    "membership_of_the_app_role": (
        "GRANT {owner} TO {app}",
        "REVOKE {owner} FROM {app}",
        lambda c: ["<owner>", "<app>", False] in c["app_role"]["memberships"],
    ),
}


@pytest.mark.parametrize("mutant", sorted(CATALOG_MUTANTS))
def test_the_catalog_snapshot_detects_a_privilege_change(
    evidence: tuple[snapshots.EvidenceDatabase, dict[str, Any]], mutant: str
) -> None:
    import psycopg
    from psycopg import sql

    ev, before = evidence
    change, revert, shows = CATALOG_MUTANTS[mutant]
    names = {
        "app": sql.Identifier(ev.app),
        "owner": sql.Identifier(ev.owner),
        "variant": sql.Identifier(ev.variant("restricted")),
        "function": sql.SQL(_first_function(ev)),
    }
    assert not shows(before)
    with psycopg.connect(ev.url(), autocommit=True) as conn:
        if mutant == "grant_to_another_role":
            conn.execute(sql.SQL("CREATE ROLE {} NOLOGIN").format(names["variant"]))
        conn.execute(sql.SQL(change).format(**names))
        try:
            after = snapshots.catalog_snapshot(ev)
        finally:
            conn.execute(sql.SQL(revert).format(**names))
            if mutant == "grant_to_another_role":
                conn.execute(sql.SQL("DROP ROLE {}").format(names["variant"]))
    assert snapshots.diff("catalog", before, after), f"{mutant} did not change the catalog snapshot"
    assert shows(after), snapshots.diff("catalog", before, after)
    assert snapshots.diff("catalog", before, snapshots.catalog_snapshot(ev)) == ""  # the revert restored it


def test_the_login_roles_get_a_random_password_per_run() -> None:
    first, second = snapshots.EvidenceDatabase("", "a"), snapshots.EvidenceDatabase("", "b")
    assert first.password != second.password and len(first.password) >= 24
    assert first.password not in repr(first)
    source = (snapshots.GOLDEN.parent / "snapshots.py").read_text("utf-8")
    assert "evidence-pw" not in source and "PASSWORD =" not in source


@pytest.mark.parametrize("prefix", ["", "Axentra_", "ax-ev_", "ax%", "ax_ev_" + "x" * 15, "1ax"])
def test_an_invalid_prefix_is_refused(prefix: str) -> None:
    with pytest.raises(ValueError, match="invalid prefix"):
        snapshots.validate_prefix(prefix)
    with pytest.raises(SystemExit):
        snapshots.main(["--url", "postgresql://", "--prefix", prefix, "check"])


def test_leftovers_match_only_the_names_a_run_creates() -> None:
    database, role = snapshots._run_names("axentra_ev_")
    assert database.fullmatch("axentra_ev_0123abcd") and role.fullmatch("axentra_ev_0123abcd_v_superuser")
    for other in (
        "axentra_evx0123abcd",
        "axentra_ev_0123abcd_other",
        "axentra_ev_0123abc",
        "xaxentra_ev_0123abcd",
    ):
        assert not database.fullmatch(other) and not role.fullmatch(other), other


def test_cleanup_drops_the_leftovers_of_a_killed_run_and_nothing_else() -> None:
    import psycopg
    from psycopg import sql

    url = _admin_url()
    prefix = PREFIX + "kill_"  # a prefix of its own: no other run's objects
    base = prefix + "deadbeef"
    left = [f"database {base}", f"role {base}_app", f"role {base}_v_superuser"]
    untouched = f"{base}_other"  # same start, not a name a run creates
    with psycopg.connect(url, autocommit=True) as conn:
        for name in (f"{base}_app", f"{base}_v_superuser", untouched):
            conn.execute(sql.SQL("CREATE ROLE {} NOLOGIN").format(sql.Identifier(name)))
        conn.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(base)))
    try:
        assert snapshots.leftovers(url, prefix) == sorted(left)
        assert snapshots.main(["--url", url, "--prefix", prefix, "cleanup"]) == 0
        assert snapshots.leftovers(url, prefix) == []
        with psycopg.connect(url, autocommit=True) as conn:
            assert conn.execute("SELECT 1 FROM pg_roles WHERE rolname = %s", (untouched,)).fetchone()
    finally:
        with psycopg.connect(url, autocommit=True) as conn:
            conn.execute(sql.SQL("DROP DATABASE IF EXISTS {} WITH (FORCE)").format(sql.Identifier(base)))
            for name in (f"{base}_app", f"{base}_v_superuser", untouched):
                conn.execute(sql.SQL("DROP ROLE IF EXISTS {}").format(sql.Identifier(name)))


def test_the_catalog_snapshot_shows_forced_row_level_security() -> None:
    """The golden catalog holds what document 07 (AX-I-6) names: 34 tables with FORCE ROW LEVEL SECURITY."""
    summary = snapshots.golden("catalog")["summary"]
    assert summary["force_row_security"] == summary["row_security"] == 34


def test_the_role_table_has_eight_variants() -> None:
    table = snapshots.golden("roles")
    assert len(table["variants"]) == 8 and set(table["table"]) == set(table["variants"])
