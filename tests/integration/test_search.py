"""Search module against real PostgreSQL (RLS enforced): isolation, permissions, ranking, paging."""

from __future__ import annotations

from fastapi.testclient import TestClient
import psycopg
import pytest

from axentra.api.app import create_app
from axentra.core.context import Principal
from axentra.core.errors import Forbidden, NotFound, ValidationFailed
from axentra.data.database import DbScope
from axentra.search import SearchService
from tests.integration.conftest import World, bootstrap_admin


def _product(world, slug="crm"):
    r = world.admin.post("/v1/products", json={"slug": slug, "name": slug.upper()})
    assert r.status_code == 201, r.text
    return r.json()["id"]


def _tenant(world, pid, slug="acme"):
    r = world.admin.post(f"/v1/products/{pid}/tenants", json={"slug": slug, "name": slug.title()})
    assert r.status_code == 201, r.text
    return r.json()["id"]


def _member(world, pid, tid, email, role):
    world.user(email)
    r = world.admin.post(f"/v1/products/{pid}/tenants/{tid}/members", json={"email": email, "role": role})
    assert r.status_code == 201, r.text
    return world.login_as(email)


def _base(pid, tid):
    return f"/v1/products/{pid}/tenants/{tid}/search"


def _put(client, pid, tid, kind, ref, title="", body="", metadata=None):
    return client.put(
        f"{_base(pid, tid)}/documents/{kind}/{ref}",
        json={"title": title, "body": body, "metadata": metadata or {}},
    )


def _search(client, pid, tid, q, **params):
    return client.get(_base(pid, tid), params={"q": q, **params})


@pytest.fixture
def two_tenants(world):
    pid = _product(world)
    return world, pid, _tenant(world, pid, "acme"), _tenant(world, pid, "globex")


def test_index_query_highlight_and_audit(two_tenants):
    world, pid, t1, _ = two_tenants
    r = _put(
        world.admin,
        pid,
        t1,
        "invoice",
        "inv_1",
        title="Invoice for <Acme> roadmap",
        body="Quarterly roadmap review & planning for the platform team.",
        metadata={"amount": 42},
    )
    assert r.status_code == 201, r.text
    doc = r.json()
    assert doc["id"].startswith("sdoc_") and doc["version"] == 1 and doc["language"] == "simple"
    assert "search_vector" not in doc

    r = _search(world.admin, pid, t1, "roadmap")
    assert r.status_code == 200, r.text
    page = r.json()
    assert page["next_cursor"] is None and len(page["items"]) == 1
    hit = page["items"][0]
    assert hit["ref_id"] == "inv_1" and hit["kind"] == "invoice" and hit["metadata"] == {"amount": 42}
    assert hit["rank"] > 0 and "body" not in hit
    # Highlights are HTML-escaped text with <mark> around matches only.
    assert hit["title_highlight"] == "Invoice for &lt;Acme&gt; <mark>roadmap</mark>"
    assert "<mark>roadmap</mark>" in hit["body_highlight"] and "&amp;" in hit["body_highlight"]

    # Replace: same id, new version, 200; old words no longer match.
    r = _put(world.admin, pid, t1, "invoice", "inv_1", title="Invoice paid", body="settled")
    assert r.status_code == 200 and r.json()["id"] == doc["id"] and r.json()["version"] == 2
    assert _search(world.admin, pid, t1, "roadmap").json()["items"] == []
    assert len(_search(world.admin, pid, t1, "settled").json()["items"]) == 1

    got = world.admin.get(f"{_base(pid, t1)}/documents/invoice/inv_1")
    assert got.status_code == 200 and got.json()["body"] == "settled"

    with world.ax.db.transaction(DbScope.platform()) as tx:
        events = tx.all(
            "SELECT action, target_id, details FROM axentra_audit_events"
            " WHERE action LIKE 'search.%%' ORDER BY occurred_at, id"
        )
    assert [e["action"] for e in events] == ["search.document.upsert", "search.document.upsert"]
    assert events[0]["details"] == {"kind": "invoice", "ref_id": "inv_1", "version": 1}
    assert "roadmap" not in str(events)  # the audit trail never copies document content


def test_ranking_title_beats_body_and_frequency_counts(two_tenants):
    world, pid, t1, _ = two_tenants
    _put(world.admin, pid, t1, "note", "body-once", title="Misc", body="alpha beta gamma")
    _put(world.admin, pid, t1, "note", "title", title="Gamma rays", body="physics")
    _put(world.admin, pid, t1, "note", "body-often", title="Misc", body="gamma gamma gamma gamma")
    _put(world.admin, pid, t1, "note", "unrelated", title="Other", body="delta")
    items = _search(world.admin, pid, t1, "gamma").json()["items"]
    assert [i["ref_id"] for i in items] == ["title", "body-often", "body-once"]
    ranks = [i["rank"] for i in items]
    assert ranks == sorted(ranks, reverse=True)


def test_query_syntax_kind_filter_and_validation(two_tenants):
    world, pid, t1, _ = two_tenants
    _put(world.admin, pid, t1, "invoice", "i1", title="Blue invoice")
    _put(world.admin, pid, t1, "contact", "c1", title="Blue contact")
    _put(world.admin, pid, t1, "task", "k1", title="Blue sky task")
    refs = lambda r: sorted(i["ref_id"] for i in r.json()["items"])  # noqa: E731
    assert refs(_search(world.admin, pid, t1, "blue")) == ["c1", "i1", "k1"]
    assert refs(_search(world.admin, pid, t1, "blue", kind="invoice")) == ["i1"]
    assert refs(_search(world.admin, pid, t1, "blue", kind=["invoice", "task"])) == ["i1", "k1"]
    assert refs(_search(world.admin, pid, t1, "blue -sky")) == ["c1", "i1"]
    assert refs(_search(world.admin, pid, t1, '"sky task"')) == ["k1"]
    assert refs(_search(world.admin, pid, t1, "invoice or contact")) == ["c1", "i1"]
    assert refs(_search(world.admin, pid, t1, "BLUE")) == ["c1", "i1", "k1"]  # case-insensitive
    # Operators are never interpreted as tsquery syntax; punctuation-only queries match nothing.
    assert _search(world.admin, pid, t1, "blue & !(:*").status_code == 200
    assert _search(world.admin, pid, t1, "!!!").json() == {"items": [], "next_cursor": None}
    for bad in (
        {"q": ""},
        {"q": "x" * 501},
        {"q": "blue", "kind": "Bad Kind"},
        {"q": "blue", "cursor": "zz"},
    ):
        r = world.admin.get(_base(pid, t1), params=bad)
        assert r.status_code == 422, (bad, r.text)
        assert r.headers["content-type"].startswith("application/problem+json")
    assert world.admin.get(_base(pid, t1)).status_code == 422  # q is required


def test_pagination_is_stable_and_bounded(world: World, ax_factory):
    pid = _product(world)
    tid = _tenant(world, pid)
    for n in range(7):
        # More occurrences rank higher: d6 > d5 > ... > d0.
        _put(world.admin, pid, tid, "note", f"d{n}", title=f"Doc {n}", body=" ".join(["needle"] * (n + 1)))
    seen: list[str] = []
    cursor = None
    pages = 0
    while True:
        params = {"limit": 3, **({"cursor": cursor} if cursor else {})}
        page = _search(world.admin, pid, tid, "needle", **params).json()
        seen += [i["ref_id"] for i in page["items"]]
        pages += 1
        cursor = page["next_cursor"]
        if not cursor:
            break
    assert pages == 3 and seen == [f"d{n}" for n in range(6, -1, -1)]
    assert _search(world.admin, pid, tid, "needle", limit=201).status_code == 422

    # search.max_offset bounds deep paging.
    ax = ax_factory(search={"max_offset": 4})
    app = create_app(axentra=ax, start=False)
    admin = bootstrap_admin(ax, app)
    w2 = World(ax=ax, app=app, admin=admin)
    pid = _product(w2)
    tid = _tenant(w2, pid)
    for n in range(10):
        _put(admin, pid, tid, "note", f"d{n}", title="needle")
    first = _search(admin, pid, tid, "needle", limit=4).json()
    assert len(first["items"]) == 4 and first["next_cursor"]
    second = _search(admin, pid, tid, "needle", limit=4, cursor=first["next_cursor"]).json()
    assert len(second["items"]) == 4 and second["next_cursor"] is None


def test_delete_and_tenant_deletion_cascade(two_tenants):
    world, pid, t1, t2 = two_tenants
    _put(world.admin, pid, t1, "invoice", "inv_1", title="Orange")
    _put(world.admin, pid, t2, "invoice", "inv_1", title="Orange")
    url = f"{_base(pid, t1)}/documents/invoice/inv_1"
    assert world.admin.delete(url).status_code == 204
    assert world.admin.delete(url).status_code == 404
    assert world.admin.get(url).status_code == 404
    assert _search(world.admin, pid, t1, "orange").json()["items"] == []
    # The same kind/ref in the other tenant is untouched.
    assert len(_search(world.admin, pid, t2, "orange").json()["items"]) == 1
    assert world.admin.delete(f"/v1/products/{pid}/tenants/{t2}").status_code == 204
    with world.ax.db.transaction(DbScope.platform()) as tx:
        assert tx.scalar("SELECT count(*) FROM axentra_search_documents") == 0
        actions = [
            r["action"]
            for r in tx.all("SELECT action FROM axentra_audit_events WHERE action LIKE 'search.%%'")
        ]
    assert sorted(actions) == ["search.document.delete", "search.document.upsert", "search.document.upsert"]


def test_cross_tenant_isolation_api_and_rls(two_tenants, pg_urls):
    world, pid, t1, t2 = two_tenants
    _put(world.admin, pid, t1, "note", "a", title="secret apple plan")
    _put(world.admin, pid, t2, "note", "b", title="secret banana plan")
    alice = _member(world, pid, t1, "alice@example.com", "member")
    # Alice sees her tenant's document only, and the other tenant does not exist for her.
    assert [i["ref_id"] for i in _search(alice, pid, t1, "secret").json()["items"]] == ["a"]
    assert _search(alice, pid, t1, "banana").json()["items"] == []
    assert _search(alice, pid, t2, "secret").status_code == 404
    assert alice.get(f"{_base(pid, t2)}/documents/note/b").status_code == 404
    assert _put(alice, pid, t2, "note", "x", title="planted").status_code == 404
    assert alice.delete(f"{_base(pid, t2)}/documents/note/b").status_code == 404

    # RLS: a tenant-scoped transaction cannot see, change or plant rows of the other tenant even
    # without any WHERE clause.
    db = world.ax.db
    with db.transaction(DbScope.tenant(pid, t1)) as tx:
        rows = tx.all("SELECT tenant_id, title FROM axentra_search_documents")
        assert [(r["tenant_id"], r["title"]) for r in rows] == [(t1, "secret apple plan")]
        hits = tx.all(
            "SELECT ref_id FROM axentra_search_documents"
            " WHERE search_vector @@ websearch_to_tsquery('simple', 'banana')"
        )
        assert hits == []
        assert tx.execute("UPDATE axentra_search_documents SET title = 'x' WHERE tenant_id = %s", (t2,)) == 0
        assert tx.execute("DELETE FROM axentra_search_documents WHERE tenant_id = %s", (t2,)) == 0
    with pytest.raises(psycopg.errors.InsufficientPrivilege), db.transaction(DbScope.tenant(pid, t1)) as tx:
        tx.execute(
            "INSERT INTO axentra_search_documents (id, product_id, tenant_id, kind, ref_id, title)"
            " VALUES ('sdoc_x', %s, %s, 'note', 'x', 'planted')",
            (pid, t2),
        )
    with db.transaction(DbScope.tenant(pid, t2)) as tx:
        assert [r["title"] for r in tx.all("SELECT title FROM axentra_search_documents")] == [
            "secret banana plan"
        ]
    # Without a scope the application role sees nothing at all.
    with psycopg.connect(pg_urls["app"]) as conn:
        assert conn.execute("SELECT count(*) FROM axentra_search_documents").fetchone()[0] == 0
    with psycopg.connect(pg_urls["admin"]) as conn:
        row = conn.execute(
            "SELECT relrowsecurity, relforcerowsecurity FROM pg_class WHERE relname = 'axentra_search_documents'"
        ).fetchone()
        assert row == (True, True)


def test_product_namespace_separation(world):
    p1 = _product(world, "crm")
    p2 = _product(world, "books")
    t1 = _tenant(world, p1, "acme")
    t2 = _tenant(world, p2, "acme")
    # The same kind and ref_id in two products are two independent documents.
    d1 = _put(world.admin, p1, t1, "invoice", "inv_1", title="Kiwi from CRM").json()
    d2 = _put(world.admin, p2, t2, "invoice", "inv_1", title="Kiwi from Books").json()
    assert d1["id"] != d2["id"] and d1["product_id"] == p1 and d2["product_id"] == p2
    assert [i["title"] for i in _search(world.admin, p1, t1, "kiwi").json()["items"]] == ["Kiwi from CRM"]
    assert [i["title"] for i in _search(world.admin, p2, t2, "kiwi").json()["items"]] == ["Kiwi from Books"]
    # A tenant id of product 2 under product 1 is not found.
    assert _search(world.admin, p1, t2, "kiwi").status_code == 404

    key = world.admin.post(
        f"/v1/products/{p1}/api-keys",
        json={"name": "indexer", "permissions": ["search:index", "search:query"]},
    ).json()["secret"]
    c = TestClient(world.app, headers={"Authorization": f"Bearer {key}"})
    assert _put(c, p1, t1, "invoice", "inv_2", title="Kiwi two").status_code == 201
    assert _put(c, p2, t2, "invoice", "inv_2", title="Kiwi two").status_code == 404
    assert _search(c, p2, t2, "kiwi").status_code == 404
    with world.ax.db.transaction(DbScope.product(p1)) as tx:
        assert {r["product_id"] for r in tx.all("SELECT product_id FROM axentra_search_documents")} == {p1}


def test_permissions(two_tenants):
    world, pid, t1, _ = two_tenants
    _put(world.admin, pid, t1, "note", "n1", title="Lemon")
    viewer = _member(world, pid, t1, "viewer@example.com", "viewer")
    member = _member(world, pid, t1, "member@example.com", "member")
    admin = _member(world, pid, t1, "tadmin@example.com", "tenant_admin")
    for who in (viewer, member, admin):
        assert len(_search(who, pid, t1, "lemon").json()["items"]) == 1
    # Writing to the index needs search:index (tenant admins/owners, product admins/owners, keys).
    for who in (viewer, member):
        r = _put(who, pid, t1, "note", "n2", title="Forged")
        assert r.status_code == 403 and r.json()["code"] == "forbidden"
        assert r.headers["content-type"].startswith("application/problem+json")
        assert who.delete(f"{_base(pid, t1)}/documents/note/n1").status_code == 403
    assert _put(admin, pid, t1, "note", "n2", title="Lemon two").status_code == 201

    # Product viewers may query in every tenant, but not index.
    world.user("pview@example.com")
    r = world.admin.post(
        f"/v1/products/{pid}/members", json={"email": "pview@example.com", "role": "product_viewer"}
    )
    assert r.status_code == 201, r.text
    pview = world.login_as("pview@example.com")
    assert len(_search(pview, pid, t1, "lemon").json()["items"]) == 2
    assert _put(pview, pid, t1, "note", "n3", title="x").status_code == 403

    # API keys carry exactly the permissions they were given.
    key = world.admin.post(
        f"/v1/products/{pid}/api-keys",
        json={"name": "reader", "permissions": ["records:read"], "tenant_id": t1},
    ).json()["secret"]
    c = TestClient(world.app, headers={"Authorization": f"Bearer {key}"})
    assert _search(c, pid, t1, "lemon").status_code == 403
    assert _put(c, pid, t1, "note", "n4", title="x").status_code == 403

    # Unauthenticated: 401.
    anon = TestClient(world.app)
    assert anon.get(_base(pid, t1), params={"q": "lemon"}).status_code == 401
    assert anon.put(f"{_base(pid, t1)}/documents/note/n1", json={"title": "x"}).status_code == 401


def test_library_service_and_input_limits(two_tenants):
    world, pid, t1, t2 = two_tenants
    svc = world.ax.search
    assert isinstance(svc, SearchService)
    system = Principal.system("indexer")
    res = svc.upsert(system, pid, t1, "ticket", "T-1", title="Printer\x00 on fire", body="toner  smell")
    assert res.created and res.document.title == "Printer on fire" and "" not in res.document.body
    assert not svc.upsert(system, pid, t1, "ticket", "T-1", title="Printer on fire").created
    page = svc.query(system, pid, t1, "printer")
    assert [h.ref_id for h in page.items] == ["T-1"]
    for kwargs in (
        {"kind": "Bad"},
        {"ref_id": "../etc"},
        {"title": "", "body": "  "},
        {"title": "x" * 1001},
        {"metadata": {"a": "\x00"}},
    ):
        args = {"kind": "ticket", "ref_id": "T-2", "title": "ok", **kwargs}
        with pytest.raises(ValidationFailed):
            svc.upsert(system, pid, t1, args.pop("kind"), args.pop("ref_id"), **args)
    r = _put(world.admin, pid, t1, "ticket", "T-3", body="x" * 100_001)
    assert r.status_code == 413
    assert _put(world.admin, pid, t1, "ticket", "bad%20ref", title="x").status_code == 422
    with pytest.raises(NotFound):
        svc.delete(system, pid, t1, "ticket", "missing")
    _member(world, pid, t1, "m2@example.com", "member")
    with world.ax.db.transaction(DbScope.platform()) as tx:
        uid = tx.scalar("SELECT id FROM axentra_users WHERE email = 'm2@example.com'")
    from axentra.core.context import Actor, ActorKind

    principal = Principal(actor=Actor(ActorKind.USER, uid, "m2"))
    with pytest.raises(Forbidden):
        svc.upsert(principal, pid, t1, "ticket", "T-9", title="x")
    with pytest.raises(NotFound):
        svc.query(principal, pid, t2, "printer")


def test_language_setting_and_disabled_module(ax_factory):
    ax = ax_factory(search={"language": "english"})
    app = create_app(axentra=ax, start=False)
    admin = bootstrap_admin(ax, app)
    w = World(ax=ax, app=app, admin=admin)
    pid = _product(w)
    tid = _tenant(w, pid)
    doc = _put(admin, pid, tid, "note", "n1", title="Running the meetings").json()
    assert doc["language"] == "english"
    # Stemming: "run" and "meeting" match "Running ... meetings".
    assert len(_search(admin, pid, tid, "run meeting").json()["items"]) == 1

    ax = ax_factory(search={"language": "no_such_config"})
    app = create_app(axentra=ax, start=False)
    admin = bootstrap_admin(ax, app)
    pid = _product(World(ax=ax, app=app, admin=admin))
    tid = _tenant(World(ax=ax, app=app, admin=admin), pid)
    r = _put(admin, pid, tid, "note", "n1", title="x")
    assert r.status_code == 500 and "no_such_config" not in r.text

    ax = ax_factory(modules=[m for m in ax.settings.modules if m != "search"])
    assert ax.search is None
    app = create_app(axentra=ax, start=False)
    admin = bootstrap_admin(ax, app)
    w = World(ax=ax, app=app, admin=admin)
    pid = _product(w)
    tid = _tenant(w, pid)
    assert _search(admin, pid, tid, "x").status_code == 404
    assert "search" not in admin.get("/v1/meta").json()["modules"]


def test_concurrent_upserts_of_one_document(two_tenants):
    from concurrent.futures import ThreadPoolExecutor

    world, pid, t1, _ = two_tenants
    svc = world.ax.search
    assert svc is not None
    system = Principal.system("indexer")

    def write(n: int) -> bool:
        return svc.upsert(system, pid, t1, "note", "same", title=f"Version {n}").created

    with ThreadPoolExecutor(max_workers=5) as pool:
        created = list(pool.map(write, range(10)))
    assert created.count(True) == 1
    doc = svc.get(system, pid, t1, "note", "same")
    assert doc.version == 10
    with world.ax.db.transaction(DbScope.platform()) as tx:
        assert tx.scalar("SELECT count(*) FROM axentra_search_documents") == 1
