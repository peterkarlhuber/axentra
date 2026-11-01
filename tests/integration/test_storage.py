"""Storage module against real PostgreSQL (RLS enforced) and the local backend."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
import hashlib
import json
import os
from pathlib import Path
import time

from fastapi.testclient import TestClient
import pytest

from axentra.api.app import create_app
from axentra.core.context import Principal
from axentra.core.errors import PayloadTooLarge, QuotaExceeded
from axentra.data.database import DbScope
from axentra.storage.tokens import DownloadClaims
from tests.integration.conftest import World, bootstrap_admin


def _product(world, slug="crm", settings=None):
    r = world.admin.post(
        "/v1/products", json={"slug": slug, "name": slug.upper(), "settings": settings or {}}
    )
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


def _files(pid, tid):
    return f"/v1/products/{pid}/tenants/{tid}/files"


def _upload(browser, pid, tid, content=b"hello world", name="hello.txt", ctype="text/plain", **data):
    form = {k: (json.dumps(v) if isinstance(v, dict) else v) for k, v in data.items()}
    return browser.post(_files(pid, tid), files={"file": (name, content, ctype)}, data=form)


def _root(world) -> Path:
    return Path(world.ax.settings.storage.local_path)


def _objects(world) -> list[str]:
    root = _root(world)
    if not root.exists():
        return []
    return sorted(str(p.relative_to(root)) for p in root.rglob("*") if p.is_file())


@pytest.fixture
def small_world(ax_factory):  # type: ignore[no-untyped-def]
    ax = ax_factory(storage={"max_file_bytes": 1000})
    app = create_app(axentra=ax, start=False)
    return World(ax=ax, app=app, admin=bootstrap_admin(ax, app))


def test_upload_download_roundtrip(world):
    pid = _product(world)
    tid = _tenant(world, pid)
    body = os.urandom(200_000)
    r = _upload(
        world.admin,
        pid,
        tid,
        body,
        name="report.bin",
        ctype="application/x-custom",
        metadata={"kind": "report"},
    )
    assert r.status_code == 201, r.text
    f = r.json()
    assert f["id"].startswith("fil_") and f["status"] == "active" and f["size"] == len(body)
    assert f["sha256"] == hashlib.sha256(body).hexdigest()
    assert f["metadata"] == {"kind": "report"} and f["content_type"] == "application/x-custom"
    assert "storage_key" not in f
    # The object key is derived from ids only.
    assert _objects(world) == [f"{pid}/{tid}/{f['id']}"]
    assert oct(os.stat(_root(world) / pid / tid / f["id"]).st_mode & 0o777) == "0o600"

    r = world.admin.get(f"{_files(pid, tid)}/{f['id']}/content")
    assert r.status_code == 200 and r.content == body
    assert r.headers["content-disposition"].startswith('attachment; filename="report.bin"')
    assert r.headers["x-content-type-options"] == "nosniff"
    assert r.headers["content-type"] == "application/x-custom"
    assert r.headers["etag"] == f'"{f["sha256"]}"'

    meta = world.admin.get(f"{_files(pid, tid)}/{f['id']}")
    assert meta.status_code == 200 and meta.headers["etag"] == '"1"'
    page = world.admin.get(_files(pid, tid)).json()
    assert [x["id"] for x in page["items"]] == [f["id"]]

    r = world.admin.patch(
        f"{_files(pid, tid)}/{f['id']}",
        json={"name": "Q3 report.bin", "metadata": {"kind": "q3"}},
        headers={"If-Match": "1"},
    )
    assert r.status_code == 200 and r.json()["name"] == "Q3 report.bin" and r.json()["version"] == 2
    assert (
        world.admin.patch(
            f"{_files(pid, tid)}/{f['id']}", json={"name": "x"}, headers={"If-Match": "1"}
        ).status_code
        == 412
    )
    assert world.admin.patch(f"{_files(pid, tid)}/{f['id']}", json={"name": "evil.html"}).status_code == 415


def test_list_filters_sorting_and_pagination(world):
    pid = _product(world)
    tid = _tenant(world, pid)
    for i in range(5):
        _upload(
            world.admin,
            pid,
            tid,
            b"x" * (i + 1),
            name=f"doc{i}.txt",
            metadata={"n": i, "kind": "a" if i % 2 else "b"},
        )
    _upload(world.admin, pid, tid, b"\x89PNG\r\n\x1a\n" + b"0" * 20, name="pic.png", ctype="image/png")
    base = _files(pid, tid)
    seen, cursor = [], None
    while True:
        r = world.admin.get(
            base, params={"limit": 2, "sort": "size", **({"cursor": cursor} if cursor else {})}
        ).json()
        seen += [x["size"] for x in r["items"]]
        cursor = r["next_cursor"]
        if not cursor:
            break
    assert seen == sorted(seen) and len(seen) == 6
    assert len(world.admin.get(base, params={"content_type": "image/*"}).json()["items"]) == 1
    assert len(world.admin.get(base, params={"q": "DOC"}).json()["items"]) == 5
    assert len(world.admin.get(base, params={"metadata": json.dumps({"kind": "a"})}).json()["items"]) == 2
    names = [x["name"] for x in world.admin.get(base, params={"sort": "-name"}).json()["items"]]
    assert names == sorted(names, reverse=True)
    assert world.admin.get(base, params={"metadata": "[1]"}).status_code == 422


def test_size_limit_is_enforced_while_streaming(small_world):
    world = small_world
    pid = _product(world)
    tid = _tenant(world, pid)
    assert _upload(world.admin, pid, tid, b"a" * 1000).status_code == 201
    r = _upload(world.admin, pid, tid, b"a" * 1001)
    assert r.status_code == 413 and r.json()["code"] == "payload_too_large"

    # Chunked body without Content-Length: the parser stops reading once the limit is passed.
    boundary = "xyzBOUNDARY"
    sent = {"bytes": 0}

    def body():
        yield (f'--{boundary}\r\nContent-Disposition: form-data; name="file"; filename="big.bin"\r\n'
               "Content-Type: application/octet-stream\r\n\r\n").encode()  # fmt: skip
        for _ in range(1000):
            sent["bytes"] += 100
            yield b"b" * 100
        yield f"\r\n--{boundary}--\r\n".encode()

    r = world.admin.post(
        _files(pid, tid),
        content=body(),
        headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
    )
    assert r.status_code == 413
    # A lying Content-Length larger than allowed is refused up front.
    r = world.admin.post(
        _files(pid, tid),
        content=b"--x--",
        headers={"Content-Type": "multipart/form-data; boundary=x", "Content-Length": str(10**9)},
    )
    assert r.status_code in (400, 413)

    # Library use: a never-ending generator is cut off at the limit.
    produced = {"n": 0}

    def endless():
        while True:
            produced["n"] += 1
            yield b"z" * 64

    with pytest.raises(PayloadTooLarge):
        world.ax.storage.upload(Principal.system(), pid, tid, endless(), name="endless.bin")
    assert produced["n"] * 64 <= 1000 + 64 * 2
    # Nothing is left behind: one object, one active row, usage counts only the good file.
    assert len(_objects(world)) == 1
    with world.ax.db.transaction(DbScope.platform()) as tx:
        assert tx.scalar("SELECT count(*) FROM axentra_files") == 1
    usage = world.admin.get(f"/v1/products/{pid}/tenants/{tid}/storage/usage").json()
    assert usage["bytes_used"] == 1000 and usage["files_used"] == 1


def test_empty_file_and_missing_part_are_refused(world):
    pid = _product(world)
    tid = _tenant(world, pid)
    assert _upload(world.admin, pid, tid, b"").status_code == 422
    r = world.admin.post(
        _files(pid, tid), data={"metadata": "{}"}, files={"other": ("a", b"x", "text/plain")}
    )
    assert r.status_code == 422
    assert world.admin.post(_files(pid, tid), json={"file": "x"}).status_code == 415
    assert _upload(world.admin, pid, tid, metadata="not json").status_code == 422
    assert _upload(world.admin, pid, tid, metadata={"k" * 100: 1}).status_code == 422
    assert _upload(world.admin, pid, tid, metadata={"big": "x" * 2000}).status_code == 422
    assert _upload(world.admin, pid, tid, expires_at="2001-01-01T00:00:00Z").status_code == 422


def test_quota_files_bytes_and_product_default(world):
    pid = _product(world, settings={"storage": {"quota_files": 2}})
    tid = _tenant(world, pid)
    assert _upload(world.admin, pid, tid, b"1").status_code == 201
    assert _upload(world.admin, pid, tid, b"2").status_code == 201
    r = _upload(world.admin, pid, tid, b"3")
    assert r.status_code == 429 and r.json()["code"] == "quota_exceeded"
    u = world.admin.get(f"/v1/products/{pid}/tenants/{tid}/storage/usage").json()
    assert u["quota_files"] == 2 and u["quota_files_override"] is None and u["quota_version"] == 0

    q = f"/v1/products/{pid}/tenants/{tid}/storage/quota"
    r = world.admin.put(q, json={"quota_bytes": 10, "quota_files": 100}, headers={"If-Match": "0"})
    assert r.status_code == 200, r.text
    assert r.json()["quota_bytes"] == 10 and r.json()["quota_files"] == 100 and r.json()["quota_version"] == 1
    assert world.admin.put(q, json={"quota_bytes": 1}, headers={"If-Match": "0"}).status_code == 412
    assert _upload(world.admin, pid, tid, b"x" * 8).status_code == 201  # 10 bytes used
    assert _upload(world.admin, pid, tid, b"y").status_code == 429
    assert world.admin.put(q, json={"quota_bytes": None, "quota_files": None}).json()["quota_files"] == 2

    total = world.admin.get(f"/v1/products/{pid}/storage/usage").json()
    assert total["bytes_used"] == 10 and total["files_used"] == 3 and total["default_quota_files"] == 2
    assert [t["tenant_id"] for t in total["tenants"]] == [tid]
    with world.ax.db.transaction(DbScope.platform()) as tx:
        actions = [
            r["action"]
            for r in tx.all("SELECT action FROM axentra_audit_events WHERE action LIKE 'storage.%'")
        ]
    assert actions.count("storage.file.upload") == 3 and actions.count("storage.quota.update") == 2


def test_quota_is_exact_under_concurrent_uploads(world):
    pid = _product(world)
    tid = _tenant(world, pid)
    world.ax.storage.set_quota(Principal.system(), pid, tid, quota_bytes=1000, quota_files=None)
    svc = world.ax.storage

    def attempt(i):
        try:
            svc.upload(Principal.system(), pid, tid, os.urandom(300), name=f"f{i}.bin")
            return "ok"
        except QuotaExceeded:
            return "quota"

    with ThreadPoolExecutor(max_workers=5) as pool:
        results = list(pool.map(attempt, range(12)))
    assert results.count("ok") == 3, results
    usage = svc.tenant_usage(Principal.system(), pid, tid)
    assert usage.bytes_used == 900 and usage.files_used == 3
    assert len(_objects(world)) == 3
    with world.ax.db.transaction(DbScope.platform()) as tx:
        assert tx.scalar("SELECT count(*) FROM axentra_files WHERE status = 'active'") == 3
        assert tx.scalar("SELECT count(*) FROM axentra_files WHERE status = 'pending'") == 0

    # Files quota under concurrency too.
    tid2 = _tenant(world, pid, "globex")
    svc.set_quota(Principal.system(), pid, tid2, quota_bytes=None, quota_files=2)

    def attempt2(i):
        try:
            svc.upload(Principal.system(), pid, tid2, b"abc", name=f"g{i}.txt")
            return "ok"
        except QuotaExceeded:
            return "quota"

    with ThreadPoolExecutor(max_workers=5) as pool:
        assert list(pool.map(attempt2, range(8))).count("ok") == 2


def test_path_traversal_names_and_header_safety(world):
    pid = _product(world)
    tid = _tenant(world, pid)
    for evil in (
        "../../etc/passwd",
        "..\\..\\boot.ini",
        "/abs/path.txt",
        "..",
        "a\r\nX-Injected: 1.txt",
        'q"uote;.txt',
    ):
        r = _upload(world.admin, pid, tid, b"data", name=evil)
        assert r.status_code == 201, (evil, r.text)
        f = r.json()
        assert (
            "/" not in f["name"] and "\\" not in f["name"] and "\r" not in f["name"] and "\n" not in f["name"]
        )
        assert f["name"] not in ("..", ".")
        d = world.admin.get(f"{_files(pid, tid)}/{f['id']}/content")
        assert d.status_code == 200
        cd = d.headers["content-disposition"]
        assert cd.startswith("attachment;") and "\r" not in cd and "\n" not in cd
        assert "x-injected" not in {k.lower() for k in d.headers}
    # Every object sits under the tenant prefix with an id-derived name; nothing escaped the root.
    for key in _objects(world):
        assert key.startswith(f"{pid}/{tid}/fil_")
    assert not (_root(world).parent / "etc").exists()
    r = world.admin.get(f"{_files(pid, tid)}/{'..%2F..%2Fetc%2Fpasswd'}/content")
    assert r.status_code == 404
    r = _upload(world.admin, pid, tid, b"data", name="résumé ✓.pdf")
    d = world.admin.get(f"{_files(pid, tid)}/{r.json()['id']}/content")
    assert "filename*=UTF-8''r%C3%A9sum%C3%A9%20%E2%9C%93.pdf" in d.headers["content-disposition"]


def test_dangerous_types_are_refused_and_served_safely(ax_factory):
    ax = ax_factory(
        storage={"allowed_content_types": ["image/*", "text/plain", "application/pdf", "application/xml"]}
    )
    app = create_app(axentra=ax, start=False)
    world = World(ax=ax, app=app, admin=bootstrap_admin(ax, app))
    pid = _product(world)
    tid = _tenant(world, pid)
    cases = [
        (b"<!DOCTYPE html><script>alert(1)</script>", "note.txt", "text/plain"),
        (b"  <html><body>x</body></html>", "note.txt", "text/plain"),
        (b'<?xml version="1.0"?><svg xmlns="http://www.w3.org/2000/svg"/>', "img.png", "image/png"),
        (b"<svg onload=alert(1)>", "img.txt", "text/plain"),
        (b"MZ\x90\x00" + b"\x00" * 60, "setup.txt", "text/plain"),
        (b"\x7fELF\x02\x01", "a.txt", "text/plain"),
        (b"#!/bin/sh\nrm -rf /", "a.txt", "text/plain"),
        (b"plain", "a.html", "text/plain"),
        (b"plain", "a.svg", "image/png"),
        (b"plain", "a.txt", "text/html"),
        (b"plain", "a.txt", "image/svg+xml"),
        (b"plain", "a.dat", "application/octet-stream"),  # not on the allow-list
    ]
    for content, name, ctype in cases:
        r = _upload(world.admin, pid, tid, content, name=name, ctype=ctype)
        assert r.status_code == 415, (content, name, ctype, r.text)
        assert r.json()["code"] == "unsupported_media_type"
    # Sniffed type wins over a wrong top-level declaration.
    r = _upload(world.admin, pid, tid, b"%PDF-1.7 ...", name="doc.pdf", ctype="image/png")
    assert r.status_code == 201 and r.json()["content_type"] == "application/pdf"
    # Stored but risky types are served as octet-stream attachments.
    r = _upload(world.admin, pid, tid, b"<?xml version='1.0'?><a/>", name="a.xml", ctype="application/xml")
    assert r.status_code == 201, r.text
    d = world.admin.get(f"{_files(pid, tid)}/{r.json()['id']}/content")
    assert d.headers["content-type"] == "application/octet-stream"
    assert d.headers["x-content-type-options"] == "nosniff"
    assert "sandbox" in d.headers["content-security-policy"]
    assert d.headers["content-disposition"].startswith("attachment")


def test_signed_download_urls(world):
    pid = _product(world)
    t1 = _tenant(world, pid)
    t2 = _tenant(world, pid, "globex")
    f = _upload(world.admin, pid, t1, b"signed content", name="s.txt").json()
    r = world.admin.post(f"{_files(pid, t1)}/{f['id']}/download-url", json={"ttl_seconds": 60})
    assert r.status_code == 200, r.text
    u = r.json()
    assert (
        u["kind"] == "signed" and u["path"].startswith("/v1/files/download/") and u["url"].endswith(u["path"])
    )
    anon = TestClient(world.app)
    d = anon.get(u["path"])
    assert d.status_code == 200 and d.content == b"signed content"
    assert (
        d.headers["content-disposition"].startswith("attachment")
        and d.headers["referrer-policy"] == "no-referrer"
    )
    # Default TTL works without a body; too long a TTL is refused.
    assert world.admin.post(f"{_files(pid, t1)}/{f['id']}/download-url").status_code == 200
    assert (
        world.admin.post(f"{_files(pid, t1)}/{f['id']}/download-url", json={"ttl_seconds": 3600}).status_code
        == 422
    )

    token = u["path"].rsplit("/", 1)[1]
    head, kid, payload, mac = token.split(".")
    flipped = payload[:-2] + ("A" if payload[-2] != "A" else "B") + payload[-1]
    for bad in (
        f"{head}.{kid}.{flipped}.{mac}",
        f"{head}.{kid}.{payload}.{mac[:-2]}xx",
        "garbage",
        "d1.zz.a.b",
        "x" * 2000,
    ):
        assert anon.get(f"/v1/files/download/{bad}").status_code == 404

    signer = world.ax.storage.signer
    expired = signer.sign(DownloadClaims(f["id"], pid, t1, int(time.time()) - 1))
    assert anon.get(f"/v1/files/download/{expired}").status_code == 404
    # Validly signed but for a foreign scope (the file belongs to t1, not t2): not found.
    foreign = signer.sign(DownloadClaims(f["id"], pid, t2, int(time.time()) + 60))
    assert anon.get(f"/v1/files/download/{foreign}").status_code == 404
    p2 = _product(world, "books")
    t3 = _tenant(world, p2, "other")
    cross = signer.sign(DownloadClaims(f["id"], p2, t3, int(time.time()) + 60))
    assert anon.get(f"/v1/files/download/{cross}").status_code == 404
    # A token signed with another installation's key is useless.
    from axentra.config.secrets import Keyring, generate_key
    from axentra.storage.tokens import DownloadSigner

    other = DownloadSigner(Keyring.parse(f"{kid}:{generate_key()}"))
    assert (
        anon.get(
            f"/v1/files/download/{other.sign(DownloadClaims(f['id'], pid, t1, int(time.time()) + 60))}"
        ).status_code
        == 404
    )
    # Suspended tenant: link stops working; deleted file: link stops working.
    world.admin.patch(f"/v1/products/{pid}/tenants/{t1}", json={"status": "suspended"})
    assert anon.get(u["path"]).status_code == 404
    world.admin.patch(f"/v1/products/{pid}/tenants/{t1}", json={"status": "active"})
    assert anon.get(u["path"]).status_code == 200
    assert world.admin.delete(f"{_files(pid, t1)}/{f['id']}").status_code == 204
    assert anon.get(u["path"]).status_code == 404


def test_cross_tenant_and_cross_product_isolation(world):
    p1 = _product(world)
    t1 = _tenant(world, p1)
    t2 = _tenant(world, p1, "globex")
    p2 = _product(world, "books")
    t3 = _tenant(world, p2, "other")
    a = _member(world, p1, t1, "a@example.com", "member")
    b = _member(world, p1, t2, "b@example.com", "member")
    f = _upload(a, p1, t1, b"acme secret").json()
    fid = f["id"]
    assert b.get(_files(p1, t1)).status_code == 404
    for path in (f"{_files(p1, t1)}/{fid}", f"{_files(p1, t1)}/{fid}/content"):
        assert b.get(path).status_code == 404
    for path in (f"{_files(p1, t2)}/{fid}", f"{_files(p1, t2)}/{fid}/content"):
        assert b.get(path).status_code == 404
    assert b.patch(f"{_files(p1, t2)}/{fid}", json={"name": "x"}).status_code == 404
    assert b.delete(f"{_files(p1, t2)}/{fid}").status_code == 404
    assert b.post(f"{_files(p1, t2)}/{fid}/download-url").status_code == 404
    assert _upload(b, p1, t1).status_code == 404
    assert b.get(_files(p1, t2)).json()["items"] == []
    # Cross product: even the platform admin cannot reach the file under another product's path.
    assert world.admin.get(f"{_files(p2, t3)}/{fid}").status_code == 404
    assert world.admin.get(f"{_files(p2, t1)}/{fid}").status_code == 404
    assert world.admin.get(f"{_files(p1, t1)}/{fid}").status_code == 200
    # RLS: an unfiltered query in another tenant's scope sees nothing.
    with world.ax.db.transaction(DbScope.tenant(p1, t2)) as tx:
        assert tx.all("SELECT id FROM axentra_files") == []
        assert tx.all("SELECT * FROM axentra_storage_usage") == []
    with world.ax.db.transaction(DbScope.product(p2)) as tx:
        assert tx.all("SELECT id FROM axentra_files") == []


def test_permissions(world):
    pid = _product(world)
    tid = _tenant(world, pid)
    viewer = _member(world, pid, tid, "v@example.com", "viewer")
    owner = _member(world, pid, tid, "o@example.com", "tenant_owner")
    f = _upload(world.admin, pid, tid, b"data").json()
    base = _files(pid, tid)
    assert viewer.get(base).status_code == 200
    assert viewer.get(f"{base}/{f['id']}").status_code == 200
    assert viewer.get(f"{base}/{f['id']}/content").content == b"data"
    assert viewer.post(f"{base}/{f['id']}/download-url").status_code == 200
    assert viewer.get(f"/v1/products/{pid}/tenants/{tid}/storage/usage").status_code == 200
    assert _upload(viewer, pid, tid).status_code == 403
    assert viewer.patch(f"{base}/{f['id']}", json={"name": "x"}).status_code == 403
    assert viewer.delete(f"{base}/{f['id']}").status_code == 403
    # Tenant roles cannot see product-wide usage or change quotas.
    assert owner.get(f"/v1/products/{pid}/storage/usage").status_code == 403
    assert (
        owner.put(f"/v1/products/{pid}/tenants/{tid}/storage/quota", json={"quota_bytes": 1}).status_code
        == 403
    )
    assert _upload(owner, pid, tid).status_code == 201
    # Unauthenticated: 401; unrelated user: 404.
    anon = TestClient(world.app)
    assert anon.get(base).status_code == 401
    assert anon.post(base, files={"file": ("a.txt", b"x", "text/plain")}).status_code == 401
    world.user("x@example.com")
    stranger = world.login_as("x@example.com")
    assert stranger.get(base).status_code == 404
    assert stranger.get(f"/v1/products/{pid}/storage/usage").status_code == 404
    # A product viewer reads usage but cannot change quotas.
    world.user("pv@example.com")
    world.admin.post(
        f"/v1/products/{pid}/members", json={"email": "pv@example.com", "role": "product_viewer"}
    )
    pv = world.login_as("pv@example.com")
    assert pv.get(f"/v1/products/{pid}/storage/usage").status_code == 200
    assert (
        pv.put(f"/v1/products/{pid}/tenants/{tid}/storage/quota", json={"quota_bytes": 1}).status_code == 403
    )
    assert _upload(pv, pid, tid).status_code == 403
    # API key with files:read only.
    r = world.admin.post(
        f"/v1/products/{pid}/api-keys",
        json={"name": "reader", "tenant_id": tid, "permissions": ["files:read"]},
    )
    assert r.status_code == 201, r.text
    key = TestClient(world.app, headers={"Authorization": f"Bearer {r.json()['secret']}"})
    assert key.get(base).status_code == 200
    assert key.post(base, files={"file": ("a.txt", b"x", "text/plain")}).status_code == 403


def test_delete_and_purge(world):
    pid = _product(world)
    tid = _tenant(world, pid)
    svc = world.ax.storage
    f = _upload(world.admin, pid, tid, b"to be deleted").json()
    keep = _upload(world.admin, pid, tid, b"keep").json()
    assert world.admin.delete(f"{_files(pid, tid)}/{f['id']}", headers={"If-Match": "9"}).status_code == 412
    assert world.admin.delete(f"{_files(pid, tid)}/{f['id']}").status_code == 204
    assert world.admin.get(f"{_files(pid, tid)}/{f['id']}").status_code == 404
    assert world.admin.delete(f"{_files(pid, tid)}/{f['id']}").status_code == 404
    assert _objects(world) == [f"{pid}/{tid}/{keep['id']}"]
    usage = svc.tenant_usage(Principal.system(), pid, tid)
    assert usage.files_used == 1 and usage.bytes_used == 4
    with world.ax.db.transaction(DbScope.platform()) as tx:
        row = tx.one(
            "SELECT status, deleted_at, object_deleted_at FROM axentra_files WHERE id = %s", (f["id"],)
        )
        assert row["status"] == "deleted" and row["object_deleted_at"] is not None
        assert (
            tx.scalar("SELECT count(*) FROM axentra_audit_events WHERE action = 'storage.file.delete'") == 1
        )

    # Backend failure during delete: the purge retries.
    real_delete = svc.backend.delete
    g = _upload(world.admin, pid, tid, b"sticky").json()
    svc.backend.delete = lambda key: (_ for _ in ()).throw(OSError("disk on fire"))  # type: ignore[method-assign]
    assert world.admin.delete(f"{_files(pid, tid)}/{g['id']}").status_code == 204
    svc.backend.delete = real_delete  # type: ignore[method-assign]
    assert f"{pid}/{tid}/{g['id']}" in _objects(world)

    # Orphans: an object without metadata (e.g. its tenant was deleted) and an abandoned pending upload.
    orphan = f"{pid}/{tid}/fil_{'0' * 26}"
    svc.backend.put(orphan, [b"orphan"], content_type="text/plain")
    svc.backend.put("not-an-axentra-key", [b"foreign"], content_type="text/plain")
    stale_id = f"fil_{'1' * 26}"
    with world.ax.db.transaction(DbScope.tenant(pid, tid)) as tx:
        tx.execute(
            "INSERT INTO axentra_files (id, product_id, tenant_id, name, content_type, storage_key, backend, status,"
            " created_at) VALUES (%s, %s, %s, 'x', 'text/plain', %s, 'local', 'pending', now() - interval '2 hours')",
            (stale_id, pid, tid, f"{pid}/{tid}/{stale_id}"),
        )
    svc.backend.put(f"{pid}/{tid}/{stale_id}", [b"half"], content_type="text/plain")
    tmp = _root(world) / pid / tid / ".tmp-deadbeef"
    tmp.write_bytes(b"partial")
    os.utime(tmp, (time.time() - 7200, time.time() - 7200))

    report = svc.purge()
    assert report.abandoned_pending == 1
    assert report.orphans_deleted == 1
    assert report.objects_deleted >= 2  # sticky + stale pending
    assert report.temp_files_removed == 1 and report.errors == 0
    assert sorted(_objects(world)) == sorted([f"{pid}/{tid}/{keep['id']}", "not-an-axentra-key"])
    # Idempotent.
    again = svc.purge()
    assert again.orphans_deleted == 0 and again.objects_deleted == 0
    # Old deleted rows are removed after the retention period.
    later = svc.purge(now=datetime.now(UTC) + timedelta(days=31))
    assert later.rows_removed == 3
    # Tenant deletion cascades metadata; the purge then removes the objects.
    assert world.admin.delete(f"/v1/products/{pid}/tenants/{tid}").status_code == 204
    assert svc.purge().orphans_deleted == 1
    assert _objects(world) == ["not-an-axentra-key"]


def test_expiry(world):
    pid = _product(world)
    tid = _tenant(world, pid)
    soon = (datetime.now(UTC) + timedelta(hours=1)).isoformat()
    f = _upload(world.admin, pid, tid, b"temporary", expires_at=soon).json()
    assert f["expires_at"] is not None
    other = _upload(world.admin, pid, tid, b"permanent").json()
    url = world.admin.post(f"{_files(pid, tid)}/{f['id']}/download-url").json()["path"]
    with world.ax.db.transaction(DbScope.tenant(pid, tid)) as tx:
        tx.execute(
            "UPDATE axentra_files SET expires_at = now() - interval '1 second' WHERE id = %s", (f["id"],)
        )
    # Expired files are gone for readers at once, even before the purge ran.
    assert world.admin.get(f"{_files(pid, tid)}/{f['id']}").status_code == 404
    assert world.admin.get(f"{_files(pid, tid)}/{f['id']}/content").status_code == 404
    assert [x["id"] for x in world.admin.get(_files(pid, tid)).json()["items"]] == [other["id"]]
    assert TestClient(world.app).get(url).status_code == 404
    report = world.ax.storage.purge()
    assert report.expired == 1 and report.objects_deleted == 1
    assert _objects(world) == [f"{pid}/{tid}/{other['id']}"]
    usage = world.ax.storage.tenant_usage(Principal.system(), pid, tid)
    assert usage.files_used == 1 and usage.bytes_used == len(b"permanent")
    with world.ax.db.transaction(DbScope.platform()) as tx:
        ev = tx.one(
            "SELECT actor_kind, details FROM axentra_audit_events WHERE action = 'storage.file.expire'"
        )
    assert ev["actor_kind"] == "system"


def test_module_can_be_disabled(ax_factory):
    from axentra.config.settings import MODULES

    ax = ax_factory(modules=[m for m in MODULES if m != "storage"])
    assert ax.storage is None
    app = create_app(axentra=ax, start=False)
    assert not [r for r in app.routes if "/files" in getattr(r, "path", "")]
