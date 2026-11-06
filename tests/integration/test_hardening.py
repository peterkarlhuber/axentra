"""Phase 5 hardening: secret re-encryption, record audit, body/rate limits, API docs, migration discovery."""

from __future__ import annotations

import io
import json
from pathlib import Path
import sys
import textwrap
from typing import Any

import psycopg
import psycopg.sql
import pytest

from axentra.api.app import create_app
from axentra.config.secrets import generate_key
from axentra.core.context import Actor, ActorKind, Principal
from axentra.data.database import DbScope
from axentra.platform import Axentra
from tests.conftest import make_settings
from tests.integration.conftest import ADMIN_PASSWORD, Browser, World
from tests.integration.test_notify import _member, _product, _send, _template, _tenant

# -- secrets reencrypt ----------------------------------------------------------------------------


def _kids(report: dict[str, Any]) -> set[str]:
    kids = {kid for col in report["columns"].values() for kid in col["by_kid"]}
    assert set(report["by_kid"]) == kids
    return kids


def _values_under(pg_urls: dict[str, str], kid: str) -> dict[str, int]:
    """Every text value of every Axentra table that is a ciphertext under ``kid`` (registered or not)."""
    found: dict[str, int] = {}
    with psycopg.connect(pg_urls["admin"]) as conn:
        cols = conn.execute(
            "SELECT table_name, column_name FROM information_schema.columns WHERE table_schema = 'public'"
            " AND table_name LIKE 'axentra_%%' AND data_type = 'text' ORDER BY 1, 2"
        ).fetchall()
        for table, column in cols:
            n = conn.execute(
                psycopg.sql.SQL("SELECT count(*) FROM {} WHERE {} LIKE %s").format(
                    psycopg.sql.Identifier(table), psycopg.sql.Identifier(column)
                ),
                (f"axs1.{kid}.%",),
            ).fetchone()[0]  # type: ignore[index]
            if n:
                found[f"{table}.{column}"] = n
    return found


def _write_config(path: Path, pg_urls: dict[str, str], keys: str, **database: Any) -> Path:
    db = {"url": pg_urls["app"], **database}
    lines = ['environment = "test"', 'mode = "multi"', "[database]"]
    lines += [f"{k} = {json.dumps(v)}" for k, v in db.items()]
    lines += ["[security]", f"master_keys = {json.dumps(keys)}"]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def test_reencrypt_rotates_every_column_and_old_key_can_be_removed(world: World, pg_urls, tmp_path, capsys):
    ax1 = world.ax
    old_spec = ax1.settings.security.master_keys
    assert old_spec and old_spec.startswith("t1:")
    pid = _product(world)
    tid = _tenant(world, pid)
    # Notify: a sent message (messages + local mailbox, subject/text/html encrypted).
    _template(world, pid)
    msg = _send(world.admin, pid, tid, {"email": "bob@example.com"}).json()
    assert ax1.notify is not None and ax1.notify.dispatcher().run_once(10).sent == 1
    # Notify: an in-app inbox message (stored encrypted at enqueue, never dispatched).
    _template(
        world,
        pid,
        key="run.failed",
        channel="inbox",
        category="runs",
        variants={"en": {"subject": "Run {{ name }} failed", "text": "The run {{ name }} failed."}},
    )
    bob = _member(world, pid, tid, "bob@example.com")
    ax1.notify.enqueue_system(pid, tid, template_key="run.failed", to_user_id=bob, variables={"name": "R1"})
    # Webhooks: current and previous secret.
    r = world.admin.post(
        f"/v1/products/{pid}/webhooks", json={"url": "https://hooks.example.com/x", "event_types": ["*"]}
    )
    assert r.status_code == 201, r.text
    wid, first_secret = r.json()["endpoint"]["id"], r.json()["secret"]
    r = world.admin.post(f"/v1/products/{pid}/webhooks/{wid}/rotate-secret", json={"grace_seconds": 600})
    second_secret = r.json()["secret"]
    # OIDC login state (written directly; the OIDC flow needs a provider).
    ctx = "axentra_login_states:hash1"
    with ax1.db.transaction(DbScope.platform()) as tx:
        for state, nonce_ctx in (("hash1", ctx), ("broken", "axentra_login_states:other")):
            sctx = f"axentra_login_states:{state}"
            tx.execute(
                "INSERT INTO axentra_login_states (state_hash, provider, nonce, code_verifier, invitation_token,"
                " host_context, expires_at) VALUES (%s, 'p', %s, %s, %s, %s, now() + interval '5 minutes')",
                (
                    state,
                    ax1.secrets.encrypt("nonce-1", nonce_ctx + ":nonce"),
                    ax1.secrets.encrypt("verifier-1", sctx + ":code_verifier"),
                    ax1.secrets.encrypt("invite-1", sctx + ":invitation"),
                    ax1.secrets.encrypt('{"k": "v"}', sctx + ":host_context"),
                ),
            )

    new_key = generate_key()
    ax2 = Axentra.from_settings(make_settings(pg_urls, security={"master_keys": f"t2:{new_key},{old_spec}"}))
    ax2.db.open()
    try:
        dry = ax2.reencrypt_secrets(dry_run=True).as_dict()
        assert dry["active_kid"] == "t2" and dry["reencrypted"] == 0 and _kids(dry) == {"t1"}
        cols = dry["columns"]
        assert cols["axentra_webhook_endpoints.secret_enc"]["pending"] == 1
        assert cols["axentra_webhook_endpoints.previous_secret_enc"]["pending"] == 1
        assert cols["axentra_notify_messages.body_html_enc"]["pending"] == 1
        assert cols["axentra_notify_mailbox.subject_enc"]["pending"] == 1
        assert cols["axentra_login_states.nonce"]["pending"] == 2
        assert cols["axentra_login_states.invitation_token"]["pending"] == 2
        assert cols["axentra_login_states.host_context"]["pending"] == 2
        assert cols["axentra_notify_messages.subject_enc"]["pending"] == 2  # e-mail + inbox
        # The dry run's pending count covers every value under the old key, in any Axentra column.
        assert dry["pending"] == sum(_values_under(pg_urls, "t1").values())
        # Dry run changed nothing.
        assert ax2.reencrypt_secrets(dry_run=True).as_dict()["pending"] == dry["pending"]

        run = ax2.reencrypt_secrets(batch_size=2)
        # The row encrypted under a wrong context cannot be read: counted, left alone, run continues.
        assert run.failed == 1 and run.columns["axentra_login_states.nonce"].failed == 1
        assert run.as_dict()["reencrypted"] == dry["pending"] - 1
        with ax2.db.transaction(DbScope.platform()) as tx:
            tx.execute("DELETE FROM axentra_login_states WHERE state_hash = 'broken'")
        again = ax2.reencrypt_secrets().as_dict()
        assert again["pending"] == 0 and again["reencrypted"] == 0 and again["failed"] == 0
        assert _kids(again) == {"t2"}
        # pending: 0 means no value under the old key is left anywhere, registered or not (SR-05).
        assert _values_under(pg_urls, "t1") == {}
    finally:
        ax2.close()

    # The old key is gone from the keyring: every value is still readable through the services.
    ax3 = Axentra.from_settings(make_settings(pg_urls, security={"master_keys": f"t2:{new_key}"}))
    ax3.start()
    try:
        app3 = create_app(axentra=ax3, start=False)
        admin3 = Browser(app3)
        admin3.client.cookies = world.admin.client.cookies
        got = admin3.get(f"/v1/products/{pid}/notify/messages/{msg['id']}").json()
        assert got["content"]["text"] == "Hello <Bob & Co>" and got["subject"] == "Hi <Bob & Co>"
        box = admin3.get(f"/v1/products/{pid}/notify/mailbox").json()["items"]
        assert len(box) == 1 and box[0]["html"] == "<p>Hello &lt;Bob &amp; Co&gt;</p>"
        with ax3.db.transaction(DbScope.platform()) as tx:
            ep = tx.one("SELECT * FROM axentra_webhook_endpoints WHERE id = %s", (wid,))
            state = tx.one("SELECT * FROM axentra_login_states WHERE state_hash = 'hash1'")
        assert ax3.webhooks._secrets_of(ep) == [second_secret, first_secret]
        assert ax3.secrets.decrypt(state["nonce"], ctx + ":nonce") == "nonce-1"
        assert ax3.secrets.decrypt(state["code_verifier"], ctx + ":code_verifier") == "verifier-1"
        assert ax3.secrets.decrypt(state["invitation_token"], ctx + ":invitation") == "invite-1"
        assert ax3.secrets.decrypt(state["host_context"], ctx + ":host_context") == '{"k": "v"}'
        assert ax3.notify is not None
        inbox = ax3.notify.list_inbox(Principal(actor=Actor(ActorKind.USER, bob, "bob")), pid, tid).items
        assert [(i.subject, i.text) for i in inbox] == [("Run R1 failed", "The run R1 failed.")]
    finally:
        ax3.close()

    # CLI: dry run reports nothing pending under the new key.
    from axentra.cli import main

    cfg = _write_config(tmp_path / "ax.toml", pg_urls, f"t2:{new_key}")
    capsys.readouterr()
    assert main(["--config", str(cfg), "secrets", "reencrypt", "--dry-run"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["dry_run"] is True and out["pending"] == 0 and _kids(out) == {"t2"}


def test_reencrypt_covers_product_registered_columns(ax, pg_urls, tmp_path, capsys, monkeypatch):
    from axentra.data.reencrypt import EncryptedColumn

    with psycopg.connect(pg_urls["owner"], autocommit=True) as owner:  # the product's migration
        owner.execute(
            "CREATE TABLE IF NOT EXISTS hard_product_secrets (id integer PRIMARY KEY, token_enc text)"
        )
        owner.execute("TRUNCATE hard_product_secrets")
    with ax.db.transaction(DbScope.platform()) as tx:
        for i in range(1, 6):
            tx.execute(
                "INSERT INTO hard_product_secrets VALUES (%s, %s)",
                (i, ax.secrets.encrypt(f"tok{i}", f"hard_product_secrets:{i}")),
            )
    old = ax.settings.security.master_keys
    ax2 = Axentra.from_settings(
        make_settings(pg_urls, security={"master_keys": f"n1:{generate_key()},{old}"})
    )
    ax2.register_encrypted_column(
        EncryptedColumn(
            "hard_product_secrets", "token_enc", "id", lambda r: f"hard_product_secrets:{r['id']}"
        )
    )
    ax2.db.open()
    try:
        report = ax2.reencrypt_secrets(batch_size=2)
        col = report.columns["hard_product_secrets.token_enc"]
        assert (col.pending, col.reencrypted, col.failed) == (5, 5, 0)
        with ax2.db.transaction(DbScope.platform()) as tx:
            rows = tx.all("SELECT * FROM hard_product_secrets ORDER BY id")
        assert [ax2.secrets.decrypt(r["token_enc"], f"hard_product_secrets:{r['id']}") for r in rows] == [
            f"tok{i}" for i in range(1, 6)
        ]
        assert all(r["token_enc"].startswith("axs1.n1.") for r in rows)
    finally:
        ax2.close()
    # CLI: --load MODULE runs setup(ax), which registers the product column.
    from axentra.cli import main

    (tmp_path / "hard_setup_mod.py").write_text(
        "from axentra.data.reencrypt import EncryptedColumn\n"
        "def setup(ax):\n"
        "    ax.register_encrypted_column(EncryptedColumn('hard_product_secrets', 'token_enc', 'id',"
        " lambda r: f\"hard_product_secrets:{r['id']}\"))\n",
        encoding="utf-8",
    )
    monkeypatch.syspath_prepend(str(tmp_path))
    cfg = _write_config(
        tmp_path / "ax.toml", pg_urls, f"n2:{generate_key()},{ax2.settings.security.master_keys}"
    )
    capsys.readouterr()
    assert main(["--config", str(cfg), "secrets", "reencrypt", "--dry-run", "--load", "hard_setup_mod"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["columns"]["hard_product_secrets.token_enc"]["by_kid"] == {"n1": 5}


def test_encrypted_column_rejects_bad_identifiers():
    from axentra.data.reencrypt import EncryptedColumn

    with pytest.raises(ValueError):
        EncryptedColumn("t; DROP TABLE x", "c", "id", lambda r: "")


# -- records audit --------------------------------------------------------------------------------


def test_record_create_replace_delete_are_audited(world: World):
    pid = _product(world)
    tid = _tenant(world, pid)
    base = f"/v1/products/{pid}/tenants/{tid}/records/invoices"
    rec = world.admin.post(base, json={"total": 42, "secret": "do-not-log"}).json()
    r = world.admin.put(f"{base}/{rec['id']}", json={"total": 43}, headers={"If-Match": '"1"'})
    assert r.status_code == 200, r.text
    assert world.admin.delete(f"{base}/{rec['id']}").status_code == 204
    events = world.admin.get("/v1/audit", params={"product_id": pid, "action": "data.record.*"}).json()[
        "items"
    ]
    by_action = {e["action"]: e for e in events}
    assert set(by_action) == {"data.record.create", "data.record.replace", "data.record.delete"}
    for e in events:
        assert (
            e["target_id"] == rec["id"] and e["tenant_id"] == tid and e["details"]["collection"] == "invoices"
        )
    assert by_action["data.record.create"]["details"]["version"] == 1
    assert by_action["data.record.replace"]["details"]["version"] == 2
    assert "do-not-log" not in json.dumps(events)
    # A refused replace (wrong version) writes nothing.
    rec2 = world.admin.post(base, json={"n": 1}).json()
    r = world.admin.put(f"{base}/{rec2['id']}", json={"n": 2}, headers={"If-Match": '"7"'})
    assert r.status_code == 412
    events = world.admin.get("/v1/audit", params={"product_id": pid, "action": "data.record.replace"}).json()[
        "items"
    ]
    assert [e["target_id"] for e in events] == [rec["id"]]


# -- body size and rate limits --------------------------------------------------------------------


def test_body_size_limit_returns_413_problem(ax_factory):
    ax = ax_factory(security={"max_body_bytes": 2048}, storage={"max_file_bytes": 64 * 1024})
    app = create_app(axentra=ax, start=False)
    from tests.integration.conftest import bootstrap_admin

    admin = bootstrap_admin(ax, app)
    pid = admin.post("/v1/products", json={"slug": "crm", "name": "CRM"}).json()["id"]
    tid = admin.post(f"/v1/products/{pid}/tenants", json={"slug": "acme", "name": "Acme"}).json()["id"]
    base = f"/v1/products/{pid}/tenants/{tid}/records/items"
    assert admin.post(base, json={"x": "a" * 1000}).status_code == 201
    big = json.dumps({"x": "a" * 4000})
    r = admin.post(base, content=big, headers={"Content-Type": "application/json"})
    assert r.status_code == 413 and r.headers["content-type"] == "application/problem+json"
    assert r.json()["code"] == "payload_too_large" and r.json()["request_id"] == r.headers["x-request-id"]

    # Chunked (no Content-Length): counted while reading.
    def chunks():  # type: ignore[no-untyped-def]
        for _ in range(8):
            yield b" " * 512
        yield b"{}"

    r = admin.post(base, content=chunks(), headers={"Content-Type": "application/json"})
    assert r.status_code == 413 and r.json()["code"] == "payload_too_large"
    # File uploads use storage.max_file_bytes, not the general limit.
    files = {"file": ("big.txt", io.BytesIO(b"x" * 20_000), "text/plain")}
    r = admin.post(f"/v1/products/{pid}/tenants/{tid}/files", files=files)
    assert r.status_code == 201, r.text
    files = {"file": ("huge.txt", io.BytesIO(b"x" * 70_000), "text/plain")}
    r = admin.post(f"/v1/products/{pid}/tenants/{tid}/files", files=files)
    assert r.status_code == 413


def test_rate_limit_per_credential_and_ip(ax_factory):
    ax = ax_factory(security={"rate_limit_per_minute": 3, "rate_limit_ip_per_minute": 8})
    app = create_app(axentra=ax, start=False)
    from fastapi.testclient import TestClient

    from tests.integration.conftest import bootstrap_admin

    admin = bootstrap_admin(ax, app)  # 1 request (setup) on the anonymous/IP budget
    statuses = [admin.get("/v1/products").status_code for _ in range(4)]
    assert statuses == [200, 200, 200, 429]
    r = admin.get("/v1/products")
    assert r.status_code == 429 and r.json()["code"] == "rate_limited"
    assert r.headers["content-type"] == "application/problem+json"
    assert 1 <= int(r.headers["retry-after"]) <= 20
    # Another credential has its own budget ...
    other = TestClient(app)
    assert other.get("/v1/products", headers={"Authorization": "Bearer axk_unknown"}).status_code == 401
    # ... but the per-IP budget (8) covers every request from this client.
    codes = [other.get("/v1/meta").status_code for _ in range(3)]
    assert codes[-1] == 429
    # Health endpoints are never limited.
    assert other.get("/v1/health/live").status_code == 200


def test_rate_limit_database_store_is_shared_by_processes(ax_factory):
    """Two API apps (standing for two processes) over one database share the budget."""
    from fastapi.testclient import TestClient

    from tests.integration.conftest import bootstrap_admin

    ax = ax_factory(security={"rate_limit_per_minute": 4, "rate_limit_store": "database"})
    first = create_app(axentra=ax, start=False)
    second = create_app(axentra=ax, start=False)
    admin = bootstrap_admin(ax, first)
    other = TestClient(second, headers={"Origin": "http://studio.test"})
    other.cookies.update(admin.client.cookies)
    codes = [admin.get("/v1/products").status_code, other.get("/v1/products").status_code]
    codes += [admin.get("/v1/products").status_code, other.get("/v1/products").status_code]
    codes += [other.get("/v1/products").status_code]
    assert codes == [200, 200, 200, 200, 429]
    r = admin.get("/v1/products")
    assert r.status_code == 429 and r.json()["code"] == "rate_limited"
    assert 1 <= int(r.headers["retry-after"]) <= 60
    with ax.db.transaction(DbScope.platform()) as tx:
        buckets = [row["bucket"] for row in tx.all("SELECT bucket FROM axentra_rate_limits")]
    assert any(b.startswith("req:cred:") for b in buckets)
    assert not any(ADMIN_PASSWORD in b or "axs_" in b for b in buckets)  # hashed keys only
    # The memory store keeps a budget per app.
    ax2 = ax_factory(security={"rate_limit_per_minute": 4})
    a1, a2 = create_app(axentra=ax2, start=False), create_app(axentra=ax2, start=False)
    admin2 = bootstrap_admin(ax2, a1)
    other2 = TestClient(a2, headers={"Origin": "http://studio.test"})
    other2.cookies.update(admin2.client.cookies)
    assert [other2.get("/v1/products").status_code for _ in range(4)] == [200] * 4
    # A database failure lets requests through instead of answering 429 or 500.
    from axentra.api.limits import DatabaseWindows

    class Down:
        def transaction(self, *args, **kwargs):
            raise psycopg.OperationalError("connection refused")

    assert DatabaseWindows(Down(), 1).take("ip:1.2.3.4") == 0.0  # type: ignore[arg-type]


def test_rate_limit_is_off_by_default(world: World):
    assert world.ax.settings.security.rate_limit_per_minute is None
    assert all(world.admin.get("/v1/products").status_code == 200 for _ in range(30))


# -- storage: blocked types stored as inert attachments (opt-in) ----------------------------------


def test_store_blocked_as_inert(ax_factory):
    from tests.integration.conftest import bootstrap_admin

    for inert in (False, True):
        ax = ax_factory(storage={"store_blocked_as_inert": inert})
        app = create_app(axentra=ax, start=False)
        admin = bootstrap_admin(ax, app)
        pid = admin.post("/v1/products", json={"slug": "crm", "name": "CRM"}).json()["id"]
        tid = admin.post(f"/v1/products/{pid}/tenants", json={"slug": "acme", "name": "Acme"}).json()["id"]
        files = {"file": ("page.html", io.BytesIO(b"<html><script>alert(1)</script>"), "text/html")}
        r = admin.post(f"/v1/products/{pid}/tenants/{tid}/files", files=files)
        if not inert:
            assert r.status_code == 415
            continue
        assert r.status_code == 201, r.text
        assert r.json()["content_type"] == "application/octet-stream" and r.json()["name"] == "page.html"
        got = admin.get(f"/v1/products/{pid}/tenants/{tid}/files/{r.json()['id']}/content")
        assert got.headers["content-type"] == "application/octet-stream"
        assert got.headers["content-disposition"].startswith("attachment")
        assert got.headers["x-content-type-options"] == "nosniff"


# -- migration discovery --------------------------------------------------------------------------


@pytest.fixture
def fixture_packages(tmp_path):  # type: ignore[no-untyped-def]
    """Two importable packages with migrations; one published through an entry point."""
    root = tmp_path / "site"
    for pkg, ns in (("hardfix_cfg", "hardfix_cfg"), ("hardfix_ep", "hardfix_ep")):
        sql = root / pkg / "sql"
        sql.mkdir(parents=True)
        (root / pkg / "__init__.py").write_text(
            textwrap.dedent(
                f"""
                from axentra.data.migrations import package_migrations

                def migrations():
                    return package_migrations({ns!r}, "{pkg}.sql")
                """
            ),
            encoding="utf-8",
        )
        (sql / "__init__.py").write_text("", encoding="utf-8")
        (sql / "0001_init.sql").write_text(
            f"CREATE TABLE {ns}_items (id text PRIMARY KEY);\n", encoding="utf-8"
        )
        (sql / "0002_more.sql").write_text(
            f"ALTER TABLE {ns}_items ADD COLUMN n integer;\n", encoding="utf-8"
        )
    dist = root / "hardfix_ep-0.1.dist-info"
    dist.mkdir()
    (dist / "METADATA").write_text(
        "Metadata-Version: 2.1\nName: hardfix-ep\nVersion: 0.1\n", encoding="utf-8"
    )
    (dist / "entry_points.txt").write_text(
        "[axentra.migrations]\nhardfix = hardfix_ep:migrations\n", encoding="utf-8"
    )
    sys.path.insert(0, str(root))
    try:
        yield root
    finally:
        sys.path.remove(str(root))
        for name in list(sys.modules):
            if name.startswith(("hardfix_cfg", "hardfix_ep")):
                del sys.modules[name]


def test_migrate_applies_configured_and_entry_point_namespaces(fixture_packages, pg_urls, tmp_path, capsys):
    from axentra.cli import main

    url_file = tmp_path / "migration-url"
    url_file.write_text(pg_urls["owner"] + "\n", encoding="utf-8")
    cfg = _write_config(
        tmp_path / "ax.toml",
        pg_urls,
        f"k1:{generate_key()}",
        extra_migrations=["hardfix_cfg:migrations"],
        # The application URL is wrong on purpose: migrations must use migration_url_ref.
        migration_url="postgresql://nobody@127.0.0.1:1/none",
        migration_url_ref=f"file:{url_file}",
    )
    capsys.readouterr()
    assert main(["--config", str(cfg), "migrate"]) == 0
    applied = json.loads(capsys.readouterr().out)["applied"]
    assert applied == [
        "hardfix_cfg:0001_init",
        "hardfix_cfg:0002_more",
        "hardfix_ep:0001_init",
        "hardfix_ep:0002_more",
    ]
    assert main(["--config", str(cfg), "migrate"]) == 0
    assert json.loads(capsys.readouterr().out)["applied"] == []
    assert main(["--config", str(cfg), "migrate", "--status"]) == 0
    status = json.loads(capsys.readouterr().out)
    assert {s["namespace"] for s in status} >= {"axentra", "hardfix_cfg", "hardfix_ep"}
    assert all(s["applied"] and s["checksum_ok"] for s in status)

    # Entry points can be switched off; a source registered twice is applied once.
    from axentra.config.settings import load_settings

    settings = load_settings(cfg, environ={}, database={"migration_entry_points": False})
    ax = Axentra.from_settings(settings)
    from hardfix_cfg import migrations  # type: ignore[import-not-found]

    ax.register_migrations(migrations())
    namespaces = {m.namespace for m in ax.migration_runner().migrations}
    assert "hardfix_ep" not in namespaces and "hardfix_cfg" in namespaces
    assert ax.migration_runner().migrate() == []


def test_migration_source_errors(fixture_packages):
    from axentra.data.migrations import Migration, MigrationRunner, load_migration_source

    with pytest.raises(ValueError, match=r"package\.module:attribute"):
        load_migration_source("hardfix_cfg")
    with pytest.raises(TypeError):
        load_migration_source("hardfix_cfg:__name__")
    runner = MigrationRunner("postgresql://unused")
    runner.register([Migration("x", 1, "a", "SELECT 1")])
    runner.register([Migration("x", 1, "a", "SELECT 1")])  # identical: ignored
    with pytest.raises(ValueError, match="two different migrations"):
        runner.register([Migration("x", 1, "a", "SELECT 2")])


# -- API docs -------------------------------------------------------------------------------------


def test_api_docs_authenticated_mode(ax_factory):
    from fastapi.testclient import TestClient

    from axentra.api.app import check_routes
    from tests.integration.conftest import bootstrap_admin

    ax = ax_factory(security={"api_docs": "authenticated"})
    app = create_app(axentra=ax, start=False)
    anon = TestClient(app)
    assert anon.get("/v1/openapi.json").status_code == 401
    assert anon.get("/v1/docs").status_code == 401
    admin = bootstrap_admin(ax, app)
    doc = admin.get("/v1/openapi.json")
    assert doc.status_code == 200 and doc.json()["info"]["title"] == "Axentra API"
    assert "/v1/openapi.json" not in doc.json()["paths"]
    assert admin.get("/v1/docs").status_code == 200
    assert check_routes(app) > 30
