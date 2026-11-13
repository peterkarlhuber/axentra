"""Test fixtures.

Integration tests need a real PostgreSQL: set ``AXENTRA_TEST_DATABASE_URL`` to a superuser URL
(e.g. ``postgresql://postgres:pg@127.0.0.1:5432/postgres``). The fixtures create a fresh database
and a NON-superuser role that owns the schema, so row-level security is really enforced.
Without the variable, integration tests are skipped and reported as skipped.

``AXENTRA_TEST_SPLIT_ROLES=1`` runs the suite as a production deployment does: a separate owner role
(``axentra_test_owner``) owns the database and runs every migration (``pg_urls["owner"]``,
``database.migration_url``), and the application role ``axentra_test_app`` owns nothing and only
has the privileges of ``axentra db grant-runtime-role`` (so it cannot even switch RLS off).
Without it, ``pg_urls["owner"]`` is the application role.

The database and its roles come from Tabrion's test fixtures (TABRION MIG-AXE-1, ``tabrion.testing``):
``tabrion_postgres_database`` creates the database ``axentra_test_<hex>`` and the roles
(``LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION``, random passwords), owns
schema ``public`` with the owner role, revokes ``CREATE`` on it from ``PUBLIC``, and drops the database
and the roles at the end of the session. The roles must not exist before the run (a leftover from an
older run fails with a clear message; drop it with ``DROP ROLE``). Axentra's own migrations and
``grant_runtime_role`` stay here.
"""

from __future__ import annotations

from collections.abc import Iterator
import logging
import os

from psycopg.conninfo import conninfo_to_dict
import pytest
from tabrion.testing import PostgresDatabaseHandle, RoleSetup, configure, truncate_tables

pytest_plugins = ["tabrion.testing"]

# The variable names stay Axentra's: the URL is AXENTRA_TEST_DATABASE_URL, and the require variable
# AXENTRA_REQUIRE_POSTGRES=1 turns a missing database into an error instead of a skip.
configure(env_prefix="AXENTRA", postgres_env=["AXENTRA_TEST_DATABASE_URL"], schema_prefix="axentra_test_")

ADMIN_URL = os.environ.get("AXENTRA_TEST_DATABASE_URL")
APP_ROLE = "axentra_test_app"
OWNER_ROLE = "axentra_test_owner"
SPLIT_ROLES = os.environ.get("AXENTRA_TEST_SPLIT_ROLES") == "1"


@pytest.fixture(autouse=True)
def _restore_root_logging() -> Iterator[None]:
    """Undo ``configure_logging`` (called by CLI commands under test): it replaces the root logger's
    handlers with a stream handler on the ``sys.stderr`` of that moment, which is pytest's capture
    file. Background threads that log after pytest closed that file (for example aiosmtpd's server
    thread in the SMTP tests) then printed "--- Logging error ---" tracebacks (AX2-10)."""
    root = logging.getLogger()
    handlers, level = root.handlers[:], root.level
    yield
    root.handlers[:] = handlers
    root.setLevel(level)


def _with_db(url: str, dbname: str, user: str | None = None, password: str | None = None) -> str:
    from psycopg.conninfo import conninfo_to_dict, make_conninfo

    params = conninfo_to_dict(url)
    params["dbname"] = dbname
    if user:
        params["user"] = user
        params["password"] = password
    return make_conninfo(**params)


@pytest.fixture(scope="session")
def tabrion_role_setup() -> RoleSetup:
    """The role names QA-25 relies on (``APP_ROLE``); a separate owner only with ``AXENTRA_TEST_SPLIT_ROLES=1``."""
    return RoleSetup(app=APP_ROLE, owner=OWNER_ROLE if SPLIT_ROLES else None, split=SPLIT_ROLES)


@pytest.fixture(scope="session")
def pg_urls(request: pytest.FixtureRequest) -> dict[str, str]:
    if not ADMIN_URL:
        pytest.skip("AXENTRA_TEST_DATABASE_URL is not set; PostgreSQL integration tests not executed")
    # Requested here, after the check above, so that the skip message stays Axentra's.
    db: PostgresDatabaseHandle = request.getfixturevalue("tabrion_postgres_database")
    owner_role = conninfo_to_dict(db.owner_url)["user"]
    urls = {
        "admin": db.url,
        "app": db.app_url,
        "owner": db.owner_url,
        "owner_role": str(owner_role),
        "server_admin": request.getfixturevalue("tabrion_postgres_url"),
        "dbname": db.name,
    }
    from axentra.data.migrations import MigrationRunner

    MigrationRunner(urls["owner"]).migrate()
    if db.app_url != db.owner_url:
        from axentra.data.roles import grant_runtime_role

        app_role = conninfo_to_dict(db.app_url)["user"]
        assert grant_runtime_role(urls["owner"], str(app_role)).restricted
    return urls


def truncate_all(admin_url: str) -> None:
    """Empty Axentra's tables (``axentra_%`` in ``public``) but keep the migration history."""
    truncate_tables(admin_url, schema="public", like="axentra_%", exclude=("axentra_schema_migrations",))


def make_settings(pg_urls: dict[str, str], **overrides):  # type: ignore[no-untyped-def]
    from axentra.config.secrets import generate_key
    from axentra.config.settings import load_settings

    base = {
        "environment": "test",
        "mode": "multi",
        "database": {"url": pg_urls["app"], "migration_url": pg_urls["owner"], "pool_max": 6},
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
