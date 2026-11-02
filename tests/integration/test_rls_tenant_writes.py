"""Tenant scope may read product-level rows but never write them (security review SR-02, migration 0011).

Every statement runs as the application role (a non-superuser; with ``AXENTRA_TEST_SPLIT_ROLES=1`` it also
owns no table), so these are the real row-level security policies. For each table whose ``scope`` policy uses
``axentra_scope_allows``:

- an INSERT in tenant scope that produces ``tenant_id`` NULL is refused (the reviewer's probe inserted a
  product-wide API key from tenant scope),
- an UPDATE in tenant scope that turns a tenant row into a product-level row is refused,
- a product-level row stays readable in tenant scope (documented), but tenant scope can neither update,
  re-home nor delete it,
- product scope and platform scope still write product-level rows.
"""

from __future__ import annotations

from collections.abc import Callable
import hashlib
from typing import Any

import psycopg
from psycopg import sql
from psycopg.types.json import Jsonb
import pytest

from axentra.data.database import Database, DbScope
from axentra.platform import Axentra

P, P2, T1, T2, USER = "prd_srp", "prd_srq", "ten_sra", "ten_srb", "usr_sr"
HASH = hashlib.sha256(b"x").hexdigest()

RowFn = Callable[[str], dict[str, Any]]

# Tables with a nullable tenant_id: a row with tenant_id NULL is a product-level row. The function returns
# the columns of a valid row (without tenant_id) for a unique suffix.
NULLABLE_TENANT: dict[str, RowFn] = {
    "axentra_api_keys": lambda n: {"id": f"key_{n}", "product_id": P, "name": "k", "secret_hash": HASH},
    "axentra_audit_events": lambda n: {
        "id": f"aud_{n}",
        "product_id": P,
        "actor_kind": "system",
        "actor_id": "x",
        "action": "test.forge",
    },
    "axentra_billing_webhook_events": lambda n: {
        "provider": "fake",
        "event_id": f"ev_{n}",
        "event_type": "x",
        "outcome": "processed",
        "product_id": P,
    },
    "axentra_events": lambda n: {"id": f"evt_{n}", "product_id": P, "type": "test.event"},
    "axentra_jobs": lambda n: {"id": f"job_{n}", "product_id": P, "kind": "test.job"},
    "axentra_notify_mailbox": lambda n: {
        "id": f"mbx_{n}",
        "product_id": P,
        "message_id": "msg_x",
        "sender": "a@example.com",
        "recipient": "b@example.com",
        "subject_enc": "s",
        "body_text_enc": "t",
        "provider_message_id": f"pm_{n}",
    },
    "axentra_notify_messages": lambda n: {
        "id": f"msg_{n}",
        "product_id": P,
        "template_key": "tpl",
        "template_version": 1,
        "category": "general",
        "recipient": "b@example.com",
        "locale": "en",
        "status": "sent",
        "max_attempts": 1,
    },
    "axentra_notify_preferences": lambda n: {"id": f"npf_{n}", "product_id": P, "user_id": USER},
    "axentra_schedule_firings": lambda n: {
        "schedule_id": "sch_base",
        "slot": f"2026-01-01T00:00:{int(n[-2:]) % 60:02d}Z",
        "product_id": P,
    },
    "axentra_schedules": lambda n: {
        "id": f"sch_{n}",
        "product_id": P,
        "name": "s",
        "kind": "test.job",
        "interval_seconds": 60,
    },
    "axentra_webhook_deliveries": lambda n: {
        "id": f"dlv_{n}",
        "product_id": P,
        "endpoint_id": "whk_base",
        "event_type": "test.event",
        "payload": Jsonb({}),
    },
    "axentra_webhook_endpoints": lambda n: {
        "id": f"whk_{n}",
        "product_id": P,
        "url": "https://hooks.example.com/x",
        "event_types": ["*"],
        "secret_enc": "s",
    },
}

# Tables that hold only product-level rows (their policy passes NULL as the tenant).
PRODUCT_ONLY: dict[str, RowFn] = {
    "axentra_access_definitions": lambda n: {
        "product_id": P,
        "revision": int(n[-4:]) + 1,
        "content_hash": HASH,
    },
    "axentra_billing_plans": lambda n: {
        "id": f"pln_{n}",
        "product_id": P,
        "key": f"plan{n[-2:]}",
        "name": "p",
    },
    "axentra_notify_templates": lambda n: {
        "id": f"tpl_{n}",
        "product_id": P,
        "key": f"tpl{n[-2:]}",
        "variants": Jsonb({}),
    },
    "axentra_product_members": lambda n: {"product_id": P, "user_id": f"{USER}{n[-2:]}", "role": "viewer"},
    "axentra_product_permissions": lambda n: {
        "product_id": P,
        "name": f"crm.deal{n[-2:]}:read",
        "scope": "tenant",
        "declared_by": "api",
    },
    "axentra_roles": lambda n: {
        "id": f"rol_{n}",
        "product_id": P,
        "key": f"role{n[-2:]}",
        "name": "r",
        "scope": "tenant",
        "permissions": ["records:read"],
    },
    "axentra_usage_meters": lambda n: {"id": f"mtr_{n}", "product_id": P, "key": f"meter{n[-2:]}"},
}

# Tables whose tenant_id is NOT NULL: a NULL tenant is refused by the column as well (records is the
# example the review names; the write policy and the column both refuse it, whichever PostgreSQL checks first).
RECORD: RowFn = lambda n: {  # noqa: E731
    "id": f"rec_{n}",
    "product_id": P,
    "collection": "notes",
    "data": Jsonb({}),
}

_NULL_REFUSED = (psycopg.errors.InsufficientPrivilege, psycopg.errors.NotNullViolation)

_counter = iter(range(10, 10_000))


def _suffix() -> str:
    return f"sr{next(_counter):04d}"


def _insert(tx: Any, table: str, row: dict[str, Any]) -> int:
    cols = list(row)
    stmt = sql.SQL("INSERT INTO {} ({}) VALUES ({})").format(
        sql.Identifier(table),
        sql.SQL(", ").join(sql.Identifier(c) for c in cols),
        sql.SQL(", ").join(sql.Placeholder() * len(cols)),
    )
    return tx.execute(stmt.as_string(tx.conn), [row[c] for c in cols])


def _key(table: str, row: dict[str, Any]) -> tuple[str, list[Any]]:
    keys = {
        "axentra_billing_webhook_events": ("provider", "event_id"),
        "axentra_schedule_firings": ("schedule_id", "slot"),
        "axentra_access_definitions": ("product_id", "revision"),
        "axentra_product_members": ("product_id", "user_id"),
        "axentra_product_permissions": ("product_id", "name"),
    }.get(table, ("id",))
    where = " AND ".join(f"{k} = %s" for k in keys)
    return where, [row[k] for k in keys]


@pytest.fixture
def db(ax: Axentra) -> Database:
    with ax.db.transaction(DbScope.platform()) as tx:
        for pid in (P, P2):
            tx.execute(
                "INSERT INTO axentra_products (id, slug, name) VALUES (%s, %s, 'P')",
                (pid, pid.replace("_", "-")),
            )
        for tid in (T1, T2):
            tx.execute(
                "INSERT INTO axentra_tenants (id, product_id, slug, name) VALUES (%s, %s, %s, 'T')",
                (tid, P, tid.replace("_", "-")),
            )
        for uid in [USER, *(f"{USER}{i:02d}" for i in range(100))]:
            tx.execute("INSERT INTO axentra_users (id, email) VALUES (%s, NULL)", (uid,))
        _insert(tx, "axentra_schedules", NULLABLE_TENANT["axentra_schedules"]("base") | {"id": "sch_base"})
        _insert(
            tx,
            "axentra_webhook_endpoints",
            NULLABLE_TENANT["axentra_webhook_endpoints"]("base") | {"id": "whk_base"},
        )
    return ax.db


def _refused(db: Database, scope: DbScope, fn: Callable[[Any], Any]) -> None:
    with pytest.raises(psycopg.errors.InsufficientPrivilege), db.transaction(scope) as tx:
        fn(tx)


@pytest.mark.parametrize("table", sorted(NULLABLE_TENANT))
def test_tenant_scope_cannot_insert_a_product_level_row(db: Database, table: str) -> None:
    row = NULLABLE_TENANT[table](_suffix())
    _refused(db, DbScope.tenant(P, T1), lambda tx: _insert(tx, table, row | {"tenant_id": None}))
    # The same row for the current tenant is accepted: the refusal above is the policy, not the row.
    with db.transaction(DbScope.tenant(P, T1)) as tx:
        assert _insert(tx, table, row | {"tenant_id": T1}) == 1


@pytest.mark.parametrize("table", sorted(NULLABLE_TENANT))
def test_tenant_scope_cannot_turn_a_tenant_row_into_a_product_level_row(db: Database, table: str) -> None:
    row = NULLABLE_TENANT[table](_suffix())
    with db.transaction(DbScope.tenant(P, T1)) as tx:
        _insert(tx, table, row | {"tenant_id": T1})
    where, params = _key(table, row)
    _refused(
        db,
        DbScope.tenant(P, T1),
        lambda tx: tx.execute(f"UPDATE {table} SET tenant_id = NULL WHERE {where}", params),
    )


@pytest.mark.parametrize("table", sorted(NULLABLE_TENANT))
def test_product_level_rows_are_read_only_in_tenant_scope(db: Database, table: str) -> None:
    row = NULLABLE_TENANT[table](_suffix())
    with db.transaction(DbScope.product(P)) as tx:  # product scope still writes product-level rows
        assert _insert(tx, table, row | {"tenant_id": None}) == 1
    where, params = _key(table, row)
    with db.transaction(DbScope.tenant(P, T1)) as tx:
        # Reading stays as documented (SECURITY_MODEL.md, "Tenant scope sees product-level rows").
        assert tx.scalar(f"SELECT count(*) FROM {table} WHERE {where}", params) == 1
        # Re-homing it into the tenant, editing it, locking it or deleting it reaches no row.
        assert tx.execute(f"UPDATE {table} SET tenant_id = %s WHERE {where}", [T1, *params]) == 0
        assert tx.execute(f"UPDATE {table} SET product_id = product_id WHERE {where}", params) == 0
        assert tx.all(f"SELECT 1 FROM {table} WHERE {where} FOR UPDATE", params) == []
        assert tx.execute(f"DELETE FROM {table} WHERE {where}", params) == 0
    with db.transaction(DbScope.product(P)) as tx:
        assert tx.scalar(f"SELECT tenant_id FROM {table} WHERE {where}", params) is None
        assert tx.execute(f"UPDATE {table} SET product_id = product_id WHERE {where}", params) == 1
        assert tx.execute(f"DELETE FROM {table} WHERE {where}", params) == 1
    with db.transaction(DbScope.platform()) as tx:  # platform scope writes them too
        assert _insert(tx, table, row | {"tenant_id": None}) == 1
        assert tx.execute(f"DELETE FROM {table} WHERE {where}", params) == 1


@pytest.mark.parametrize("table", sorted(PRODUCT_ONLY))
def test_product_only_tables_are_read_only_in_tenant_scope(db: Database, table: str) -> None:
    row = PRODUCT_ONLY[table](_suffix())
    _refused(db, DbScope.tenant(P, T1), lambda tx: _insert(tx, table, row))
    with db.transaction(DbScope.product(P)) as tx:
        assert _insert(tx, table, row) == 1
    where, params = _key(table, row)
    with db.transaction(DbScope.tenant(P, T1)) as tx:
        assert tx.scalar(f"SELECT count(*) FROM {table} WHERE {where}", params) == 1
        assert tx.execute(f"UPDATE {table} SET product_id = product_id WHERE {where}", params) == 0
        assert tx.execute(f"DELETE FROM {table} WHERE {where}", params) == 0
    with db.transaction(DbScope.product(P)) as tx:
        assert tx.execute(f"UPDATE {table} SET product_id = product_id WHERE {where}", params) == 1
        assert tx.execute(f"DELETE FROM {table} WHERE {where}", params) == 1
    with db.transaction(DbScope.platform()) as tx:
        assert _insert(tx, table, row) == 1


def test_tenant_scope_cannot_change_the_product_row(db: Database) -> None:
    with db.transaction(DbScope.tenant(P, T1)) as tx:
        assert tx.scalar("SELECT name FROM axentra_products WHERE id = %s", (P,)) == "P"
        assert tx.execute("UPDATE axentra_products SET name = 'forged' WHERE id = %s", (P,)) == 0
        assert tx.execute("DELETE FROM axentra_products WHERE id = %s", (P,)) == 0
    with db.transaction(DbScope.tenant(P, T1)) as tx:  # its own tenant row stays writable
        assert tx.execute("UPDATE axentra_tenants SET name = 'T1' WHERE id = %s", (T1,)) == 1
        assert tx.execute("UPDATE axentra_tenants SET name = 'x' WHERE id = %s", (T2,)) == 0
    with db.transaction(DbScope.product(P)) as tx:
        assert tx.execute("UPDATE axentra_products SET name = 'P' WHERE id = %s", (P,)) == 1


def test_records_refuse_a_null_tenant_in_tenant_scope(db: Database) -> None:
    row = RECORD(_suffix())
    with pytest.raises(_NULL_REFUSED), db.transaction(DbScope.tenant(P, T1)) as tx:
        _insert(tx, "axentra_records", row | {"tenant_id": None})
    with db.transaction(DbScope.tenant(P, T1)) as tx:
        assert _insert(tx, "axentra_records", row | {"tenant_id": T1}) == 1
    with pytest.raises(_NULL_REFUSED), db.transaction(DbScope.tenant(P, T1)) as tx:
        tx.execute("UPDATE axentra_records SET tenant_id = NULL WHERE id = %s", (row["id"],))
    # Moving it to another tenant is refused by the write policy.
    _refused(
        db,
        DbScope.tenant(P, T1),
        lambda tx: tx.execute("UPDATE axentra_records SET tenant_id = %s WHERE id = %s", (T2, row["id"])),
    )


def test_platform_audit_events_may_still_be_appended_from_tenant_scope(db: Database) -> None:
    """Documented: platform events (product_id NULL) are insert-only from any scope, readable in platform scope."""
    with db.transaction(DbScope.tenant(P, T1)) as tx:
        assert (
            _insert(
                tx,
                "axentra_audit_events",
                NULLABLE_TENANT["axentra_audit_events"](_suffix()) | {"product_id": None},
            )
            == 1
        )


def test_reviewer_probe_product_wide_api_key_from_tenant_scope(db: Database, pg_urls: dict[str, str]) -> None:
    """The review's null_tenant_probe.py, as the application role on a raw connection."""
    with psycopg.connect(pg_urls["app"]) as conn:
        conn.execute(
            "SELECT set_config('axentra.scope', 'tenant', true), set_config('axentra.product_id', %s, true),"
            " set_config('axentra.tenant_id', %s, true)",
            (P, T1),
        )
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            conn.execute(
                "INSERT INTO axentra_api_keys (id, product_id, tenant_id, name, secret_hash, permissions)"
                " VALUES ('key_probe', %s, NULL, 'x', 'h', '{tenant:read}')",
                (P,),
            )


def test_every_scope_policy_has_a_write_side(pg_urls: dict[str, str], db: Database) -> None:
    """A table protected by axentra_scope_allows must also carry the write policies of migration 0011."""
    with psycopg.connect(pg_urls["admin"]) as conn:
        rows = conn.execute(
            "SELECT tablename, policyname, permissive, cmd, coalesce(qual, '') AS qual,"
            " coalesce(with_check, '') AS with_check FROM pg_policies"
            " WHERE schemaname = 'public' AND tablename LIKE 'axentra_%'"
        ).fetchall()
    by_table: dict[str, dict[str, tuple[str, str, str, str]]] = {}
    for table, name, permissive, cmd, qual, check in rows:
        by_table.setdefault(table, {})[name] = (permissive, cmd, qual, check)
    protected = {
        t for t, pols in by_table.items() if "axentra_scope_allows(" in pols.get("scope", ("", "", "", ""))[2]
    }
    assert set(NULLABLE_TENANT) | set(PRODUCT_ONLY) | {"axentra_records"} <= protected
    for table in sorted(protected):
        pols = by_table[table]
        assert "axentra_scope_allows_write(" in pols["scope"][3], table
        assert "axentra_scope_allows(" not in pols["scope"][3], table
        for name, cmd in (("scope_update", "UPDATE"), ("scope_delete", "DELETE")):
            permissive, got_cmd, qual, _ = pols[name]
            assert (permissive, got_cmd) == ("RESTRICTIVE", cmd), table
            assert "axentra_scope_allows_write(" in qual, table
