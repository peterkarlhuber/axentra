"""Production refuses a database role that owns the RLS-protected tables (MUP-ONA MP-A6, PS-6).

``database.allow_table_owner`` defaults to ``None``: refused in production, allowed elsewhere. An explicit
``true`` lets production start with a warning (as before), an explicit ``false`` refuses in every environment.
``pg_urls["owner"]`` owns the tables in both test modes (``AXENTRA_TEST_SPLIT_ROLES``).
"""

from __future__ import annotations

from collections.abc import Iterator
import logging
from pathlib import Path
from typing import Any
import uuid

import psycopg
from psycopg import sql
import pytest

from axentra.config.secrets import Keyring, generate_key
from axentra.config.settings import Settings, load_settings
from axentra.core.errors import ConfigurationError
from axentra.data.roles import grant_runtime_role
from axentra.platform import Axentra
from tests.conftest import ADMIN_URL, _with_db

WARNING = "owns tables protected by row-level security"


def _settings(environment: str, url: str, tmp_path: Path, **database: Any) -> Settings:
    return load_settings(
        None,
        environ={},
        environment=environment,
        mode="multi",
        database={"url": url, "pool_max": 2, **database},
        security={"public_url": "https://api.example", "allowed_origins": ["https://studio.example"]},
        storage={"local_path": str(tmp_path / "s")},
    )


def _axentra(settings: Settings) -> Axentra:
    return Axentra(settings, keyring=Keyring.parse(f"k1:{generate_key()}"))


def _owner_warnings(caplog: pytest.LogCaptureFixture) -> list[str]:
    return [
        r.getMessage() for r in caplog.records if r.levelno == logging.WARNING and WARNING in r.getMessage()
    ]


# MUP-ONA T-AX-ROLE-1
@pytest.mark.postgres
@pytest.mark.parametrize("explicit", [{}, {"allow_table_owner": False}], ids=["default", "explicit-false"])
def test_production_refuses_the_table_owner_by_default(
    pg_urls: dict[str, str], tmp_path: Path, explicit: dict[str, Any]
) -> None:
    ax = _axentra(_settings("production", pg_urls["owner"], tmp_path, **explicit))
    with pytest.raises(ConfigurationError, match="refusing to start") as err:
        ax.start()
    assert "database.allow_table_owner = true" in str(err.value)
    assert "separate owner role" in str(err.value)
    assert not ax._started
    assert ax.db.pool.closed  # nothing left open after the refusal


# MUP-ONA T-AX-ROLE-2
@pytest.mark.postgres
def test_production_with_explicit_override_starts_with_a_warning(
    pg_urls: dict[str, str], tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    ax = _axentra(_settings("production", pg_urls["owner"], tmp_path, allow_table_owner=True))
    with caplog.at_level(logging.WARNING, logger="axentra"):
        ax.start()
    try:
        assert ax._started
        assert len(_owner_warnings(caplog)) == 1
    finally:
        ax.close()


# MUP-ONA T-AX-ROLE-3
@pytest.mark.postgres
@pytest.mark.parametrize("environment", ["development", "test"])
def test_outside_production_the_table_owner_starts_as_before(
    pg_urls: dict[str, str], tmp_path: Path, caplog: pytest.LogCaptureFixture, environment: str
) -> None:
    ax = _axentra(_settings(environment, pg_urls["owner"], tmp_path))
    with caplog.at_level(logging.WARNING, logger="axentra"):
        ax.start()
    try:
        assert ax._started
        assert _owner_warnings(caplog) == []
    finally:
        ax.close()


@pytest.fixture
def runtime_url(pg_urls: dict[str, str]) -> Iterator[str]:
    """A runtime role without ownership (``axentra db grant-runtime-role``) in the shared test database."""
    assert ADMIN_URL
    role = f"ax_rt_{uuid.uuid4().hex[:8]}"
    password = "role-test-pw"
    with psycopg.connect(ADMIN_URL, autocommit=True) as conn:
        conn.execute(
            sql.SQL("CREATE ROLE {} LOGIN NOSUPERUSER NOBYPASSRLS PASSWORD {}").format(
                sql.Identifier(role), sql.Literal(password)
            )
        )
    try:
        assert grant_runtime_role(pg_urls["owner"], role).restricted
        yield _with_db(ADMIN_URL, pg_urls["dbname"], role, password)
    finally:
        with psycopg.connect(pg_urls["admin"], autocommit=True) as conn:
            conn.execute(sql.SQL("DROP OWNED BY {}").format(sql.Identifier(role)))
        with psycopg.connect(ADMIN_URL, autocommit=True) as conn:
            conn.execute(sql.SQL("DROP ROLE IF EXISTS {}").format(sql.Identifier(role)))


# MUP-ONA T-AX-ROLE-1
@pytest.mark.postgres
def test_production_starts_with_a_runtime_role_without_ownership(
    runtime_url: str, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    ax = _axentra(_settings("production", runtime_url, tmp_path))
    with caplog.at_level(logging.WARNING, logger="axentra"):
        ax.start()
    try:
        assert ax._started
        assert _owner_warnings(caplog) == []
    finally:
        ax.close()


# MUP-ONA T-AX-ROLE-1
@pytest.mark.parametrize(
    ("environment", "value", "allowed"),
    [
        ("production", None, False),
        ("production", True, True),
        ("production", False, False),
        ("development", None, True),
        ("test", None, True),
        ("development", False, False),
    ],
)
def test_table_owner_allowed_resolves_the_default(
    tmp_path: Path, environment: str, value: bool | None, allowed: bool
) -> None:
    database: dict[str, Any] = {} if value is None else {"allow_table_owner": value}
    settings = _settings(environment, "postgresql://unused", tmp_path, **database)
    assert settings.database.allow_table_owner is value
    assert settings.table_owner_allowed is allowed


# MUP-ONA T-AX-ROLE-1
def test_environment_variable_sets_the_override(tmp_path: Path) -> None:
    settings = load_settings(
        None,
        environ={"AXENTRA__DATABASE__ALLOW_TABLE_OWNER": "true", "AXENTRA__ENVIRONMENT": "production"},
    )
    assert settings.database.allow_table_owner is True and settings.table_owner_allowed
