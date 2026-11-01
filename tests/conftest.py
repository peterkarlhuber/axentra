"""Test fixtures.

Integration tests need a real PostgreSQL: set ``AXENTRA_TEST_DATABASE_URL`` to a superuser URL
(e.g. ``postgresql://postgres:pg@127.0.0.1:5432/postgres``). The fixtures create a fresh database
and a NON-superuser role that owns the schema, so row-level security is really enforced.
Without the variable, integration tests are skipped and reported as skipped.
"""

from __future__ import annotations

from collections.abc import Iterator
import os
import uuid

import psycopg
from psycopg import sql
import pytest

ADMIN_URL = os.environ.get("AXENTRA_TEST_DATABASE_URL")
APP_ROLE = "axentra_test_app"
APP_PASSWORD = "axentra-test-pw"


def _with_db(url: str, dbname: str, user: str | None = None, password: str | None = None) -> str:
    from psycopg.conninfo import conninfo_to_dict, make_conninfo

    params = conninfo_to_dict(url)
    params["dbname"] = dbname
    if user:
        params["user"] = user
        params["password"] = password
    return make_conninfo(**params)


@pytest.fixture(scope="session")
def pg_urls() -> Iterator[dict[str, str]]:
    if not ADMIN_URL:
        pytest.skip("AXENTRA_TEST_DATABASE_URL is not set; PostgreSQL integration tests not executed")
    dbname = f"axentra_test_{uuid.uuid4().hex[:8]}"
    with psycopg.connect(ADMIN_URL, autocommit=True) as conn:
        exists = conn.execute("SELECT 1 FROM pg_roles WHERE rolname = %s", (APP_ROLE,)).fetchone()
        if not exists:
            conn.execute(
                sql.SQL("CREATE ROLE {} LOGIN NOSUPERUSER NOBYPASSRLS PASSWORD {}").format(
                    sql.Identifier(APP_ROLE), sql.Literal(APP_PASSWORD)
                )
            )
        conn.execute(
            sql.SQL("CREATE DATABASE {} OWNER {}").format(sql.Identifier(dbname), sql.Identifier(APP_ROLE))
        )
    urls = {
        "admin": _with_db(ADMIN_URL, dbname),
        "app": _with_db(ADMIN_URL, dbname, APP_ROLE, APP_PASSWORD),
        "server_admin": ADMIN_URL,
        "dbname": dbname,
    }
    from axentra.data.migrations import MigrationRunner

    MigrationRunner(urls["app"]).migrate()
    yield urls
    with psycopg.connect(ADMIN_URL, autocommit=True) as conn:
        conn.execute(sql.SQL("DROP DATABASE IF EXISTS {} WITH (FORCE)").format(sql.Identifier(dbname)))


def truncate_all(admin_url: str) -> None:
    with psycopg.connect(admin_url, autocommit=True) as conn:
        tables = [
            r[0]
            for r in conn.execute(
                "SELECT tablename FROM pg_tables WHERE schemaname = 'public' AND tablename LIKE 'axentra_%%'"
                " AND tablename <> 'axentra_schema_migrations'"
            ).fetchall()
        ]
        if tables:
            conn.execute(
                sql.SQL("TRUNCATE {} CASCADE").format(sql.SQL(", ").join(sql.Identifier(t) for t in tables))
            )


def make_settings(pg_urls: dict[str, str], **overrides):  # type: ignore[no-untyped-def]
    from axentra.config.secrets import generate_key
    from axentra.config.settings import load_settings

    base = {
        "environment": "test",
        "mode": "multi",
        "database": {"url": pg_urls["app"], "pool_max": 6},
        "security": {
            "master_keys": f"t1:{generate_key()}",
            "allowed_origins": ["http://studio.test"],
            "login_rate_per_minute": 50,
            "password_min_length": 12,
        },
        "storage": {"local_path": overrides.pop("_storage_path", "./var/test-storage")},
    }
    for k, v in overrides.items():
        if isinstance(v, dict) and isinstance(base.get(k), dict):
            base[k] = {**base[k], **v}  # type: ignore[dict-item]
        else:
            base[k] = v
    return load_settings(None, environ={}, **base)
