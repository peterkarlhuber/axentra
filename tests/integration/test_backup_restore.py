"""Backup and restore: a ``pg_dump`` custom-format dump restores into a new database that works.

This is the automated form of docs/operations/BACKUP_RESTORE.md. It needs the PostgreSQL client
binaries ``pg_dump`` and ``pg_restore`` (major version >= the server's). Set
``AXENTRA_TEST_PG_BINDIR`` to pick a directory (e.g. ``/usr/lib/postgresql/17/bin``); otherwise
they are looked up on ``PATH``. Missing or too old binaries skip the test with the reason.
"""

from __future__ import annotations

import os
from pathlib import Path
import re
import shutil
import subprocess
from typing import Any
import uuid

from fastapi.testclient import TestClient
import psycopg
from psycopg import sql
from psycopg.conninfo import conninfo_to_dict, make_conninfo
import pytest

from axentra.api.app import create_app
from axentra.data.database import DbScope
from axentra.data.migrations import MigrationRunner
from axentra.platform import Axentra
from tests.conftest import APP_ROLE, make_settings
from tests.integration.conftest import ADMIN_EMAIL, ADMIN_PASSWORD, ORIGIN

pytestmark = [pytest.mark.postgres, pytest.mark.slow]

TABLES_WITH_RLS = (
    "axentra_products",
    "axentra_product_members",
    "axentra_tenants",
    "axentra_memberships",
    "axentra_invitations",
    "axentra_roles",
    "axentra_api_keys",
    "axentra_audit_events",
    "axentra_records",
)


def _binary(name: str) -> str:
    bindir = os.environ.get("AXENTRA_TEST_PG_BINDIR")
    path = str(Path(bindir) / name) if bindir else shutil.which(name)
    if not path or not Path(path).exists():
        pytest.skip(f"{name} not found (install the PostgreSQL client or set AXENTRA_TEST_PG_BINDIR)")
    return path


def _major(binary: str) -> int:
    out = subprocess.run([binary, "--version"], capture_output=True, text=True, check=True).stdout
    m = re.search(r"(\d+)(?:\.\d+)?", out)
    assert m, out
    return int(m.group(1))


def _libpq_env(url: str) -> tuple[dict[str, str], str]:
    """Pass credentials through the environment, never on the command line."""
    p = conninfo_to_dict(url)
    env = dict(os.environ)
    env.update(
        {
            "PGHOST": str(p.get("host", "127.0.0.1")),
            "PGPORT": str(p.get("port", "5432")),
            "PGUSER": str(p.get("user", "postgres")),
        }
    )
    if p.get("password"):
        env["PGPASSWORD"] = str(p["password"])
    return env, str(p["dbname"])


def _snapshot(url: str) -> dict[str, Any]:
    with psycopg.connect(url) as conn:
        counts = {
            t: conn.execute(sql.SQL("SELECT count(*) FROM {}").format(sql.Identifier(t))).fetchone()[0]  # type: ignore[index]
            for t in (*TABLES_WITH_RLS, "axentra_users", "axentra_sessions", "axentra_schema_migrations")
        }
        rls = {
            r[0]: (r[1], r[2])
            for r in conn.execute(
                "SELECT relname, relrowsecurity, relforcerowsecurity FROM pg_class"
                " WHERE relkind = 'r' AND relname LIKE 'axentra_%'"
            ).fetchall()
        }
        policies = sorted(
            conn.execute(
                "SELECT tablename, policyname, qual, with_check FROM pg_policies WHERE schemaname = 'public'"
            ).fetchall()
        )
        owners = {
            r[0]: r[1]
            for r in conn.execute(
                "SELECT tablename, tableowner FROM pg_tables WHERE schemaname = 'public'"
            ).fetchall()
        }
        func = conn.execute("SELECT count(*) FROM pg_proc WHERE proname = 'axentra_scope_allows'").fetchone()
    return {"counts": counts, "rls": rls, "policies": policies, "owners": owners, "func": func}


def test_dump_and_restore_preserves_data_rls_and_a_working_app(world, pg_urls, tmp_path):
    pg_dump, pg_restore = _binary("pg_dump"), _binary("pg_restore")
    with psycopg.connect(pg_urls["admin"]) as conn:
        server_major = int(conn.execute("SHOW server_version_num").fetchone()[0]) // 10000  # type: ignore[index]
    if _major(pg_dump) < server_major or _major(pg_restore) < server_major:
        pytest.skip(
            f"pg_dump/pg_restore {_major(pg_dump)} is older than the PostgreSQL {server_major} server;"
            " set AXENTRA_TEST_PG_BINDIR to matching client binaries"
        )

    # Seed data through the public API: two tenants with records, an API key, audit events.
    admin = world.admin
    pid = admin.post("/v1/products", json={"slug": "crm", "name": "CRM"}).json()["id"]
    t1 = admin.post(f"/v1/products/{pid}/tenants", json={"slug": "acme", "name": "Acme"}).json()["id"]
    t2 = admin.post(f"/v1/products/{pid}/tenants", json={"slug": "globex", "name": "Globex"}).json()["id"]
    rec = admin.post(f"/v1/products/{pid}/tenants/{t1}/records/notes", json={"text": "kept"}).json()
    admin.post(f"/v1/products/{pid}/tenants/{t2}/records/notes", json={"text": "other"})
    created = admin.post(
        f"/v1/products/{pid}/api-keys",
        json={"name": "backup-test", "permissions": ["records:read"], "tenant_id": t1},
    )
    assert created.status_code == 201, created.text
    api_key = created.json()["secret"]
    before = _snapshot(pg_urls["admin"])
    assert before["counts"]["axentra_records"] == 2

    # Backup: custom format, as documented.
    dump = tmp_path / "axentra.dump"
    env, dbname = _libpq_env(pg_urls["admin"])
    subprocess.run(
        [pg_dump, "--format=custom", "--file", str(dump), "--dbname", dbname],
        env=env,
        check=True,
        capture_output=True,
    )
    assert dump.stat().st_size > 0

    # Restore into a NEW database (the documented restore target), owned by the application role.
    restored = f"{pg_urls['dbname']}_restored_{uuid.uuid4().hex[:6]}"
    with psycopg.connect(pg_urls["server_admin"], autocommit=True) as conn:
        conn.execute(
            sql.SQL("CREATE DATABASE {} OWNER {}").format(sql.Identifier(restored), sql.Identifier(APP_ROLE))
        )
    try:
        out = subprocess.run(
            [pg_restore, "--exit-on-error", "--single-transaction", "--dbname", restored, str(dump)],
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )
        assert out.returncode == 0, out.stderr

        restored_admin = make_conninfo(**{**conninfo_to_dict(pg_urls["admin"]), "dbname": restored})
        restored_app = make_conninfo(**{**conninfo_to_dict(pg_urls["app"]), "dbname": restored})
        after = _snapshot(restored_admin)
        assert after == before
        for table in TABLES_WITH_RLS:
            assert after["rls"][table] == (True, True), f"{table} lost ENABLE/FORCE ROW LEVEL SECURITY"

        # Migrations: nothing pending, checksums still match.
        runner = MigrationRunner(restored_app)
        assert runner.migrate() == []
        assert all(s["applied"] and s["checksum_ok"] for s in runner.status())

        # The application works against the restored database with the non-superuser role.
        settings = make_settings({**pg_urls, "app": restored_app}, _storage_path=str(tmp_path / "storage"))
        ax = Axentra.from_settings(settings)
        ax.start()
        try:
            assert ax.db.check_role(allow_superuser=False) == {"superuser": False, "bypass_rls": False}
            # RLS still confines an unfiltered query to the transaction's tenant.
            with ax.db.transaction(DbScope.tenant(pid, t1), read_only=True) as tx:
                assert {r["tenant_id"] for r in tx.all("SELECT tenant_id FROM axentra_records")} == {t1}
            # Without a scope the application role sees nothing.
            with psycopg.connect(restored_app) as conn:
                assert conn.execute("SELECT count(*) FROM axentra_records").fetchone()[0] == 0  # type: ignore[index]

            client = TestClient(create_app(axentra=ax, start=False), headers={"Origin": ORIGIN})
            login = client.post(
                "/v1/auth/login/password", json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD}
            )
            assert login.status_code == 200, login.text
            got = client.get(f"/v1/products/{pid}/tenants/{t1}/records/notes/{rec['id']}")
            assert got.status_code == 200 and got.json()["data"] == {"text": "kept"}
            # The restored API key still authenticates and stays confined to its tenant.
            key = TestClient(
                create_app(axentra=ax, start=False), headers={"Authorization": f"Bearer {api_key}"}
            )
            assert (
                key.get(f"/v1/products/{pid}/tenants/{t1}/records/notes").json()["items"][0]["id"]
                == rec["id"]
            )
            assert key.get(f"/v1/products/{pid}/tenants/{t2}/records/notes").status_code == 404
            # And it accepts writes.
            csrf = login.json()["csrf_token"]
            new = client.post(
                f"/v1/products/{pid}/tenants/{t1}/records/notes",
                json={"text": "after restore"},
                headers={"X-Axentra-CSRF": csrf},
            )
            assert new.status_code == 201, new.text
        finally:
            ax.close()
    finally:
        with psycopg.connect(pg_urls["server_admin"], autocommit=True) as conn:
            conn.execute(sql.SQL("DROP DATABASE IF EXISTS {} WITH (FORCE)").format(sql.Identifier(restored)))
