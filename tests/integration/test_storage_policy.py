"""Per-product storage content-type policy (blocked types refused or stored inert)."""

from __future__ import annotations

from axentra.api.app import create_app
from tests.integration.conftest import World, bootstrap_admin
from tests.integration.test_storage import _files, _member, _product, _tenant, _upload

DANGEROUS = [
    (b"<!DOCTYPE html><script>alert(1)</script>", "page.html", "text/html"),
    (b"<svg onload=alert(1)>", "img.svg", "image/svg+xml"),
    (b"alert(1)", "app.js", "text/javascript"),
    (b"#!/bin/sh\nrm -rf /", "run.sh", "application/x-sh"),
    (b"#!/usr/bin/env python3\nprint(1)", "tool.py", "text/x-python"),  # shebang sniff
    (b"<?php echo 1;", "x.php", "application/x-httpd-php"),
    (b"MZ\x90\x00" + b"\x00" * 60, "setup.bat", "application/octet-stream"),
]


def _policy(world, pid):
    return f"/v1/products/{pid}/storage/policy"


def _assert_safe_download(world, pid, tid, fid):
    d = world.admin.get(f"{_files(pid, tid)}/{fid}/content")
    assert d.status_code == 200
    assert d.headers["content-type"] == "application/octet-stream"
    assert d.headers["x-content-type-options"] == "nosniff"
    assert d.headers["content-disposition"].startswith("attachment")
    assert "sandbox" in d.headers["content-security-policy"]


def test_default_policy_is_the_installation_setting(world):
    pid = _product(world)
    r = world.admin.get(_policy(world, pid))
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["blocked_types"] == "refuse"
    assert body["blocked_types_source"] == "installation"
    assert body["installation_blocked_types"] == "refuse"
    assert (
        "html" in body["builtin_blocked_extensions"] and "text/html" in body["builtin_blocked_content_types"]
    )
    tid = _tenant(world, pid)
    for content, name, ctype in DANGEROUS:
        assert _upload(world.admin, pid, tid, content, name=name, ctype=ctype).status_code == 415, name


def test_store_inert_keeps_original_type_and_never_serves_inline(world):
    pid = _product(world, settings={"storage": {"blocked_types": "store_inert"}})
    tid = _tenant(world, pid)
    for content, name, ctype in DANGEROUS:
        r = _upload(world.admin, pid, tid, content, name=name, ctype=ctype)
        assert r.status_code == 201, (name, r.text)
        f = r.json()
        assert f["content_type"] == "application/octet-stream"
        assert f["stored_inert"] is True
        assert f["name"] == name
        _assert_safe_download(world, pid, tid, f["id"])
    files = {f["name"]: f for f in world.admin.get(_files(pid, tid)).json()["items"]}
    assert files["page.html"]["original_content_type"] == "text/html"
    assert files["img.svg"]["original_content_type"] == "image/svg+xml"
    assert files["tool.py"]["original_content_type"] == "text/x-python"
    # A signed URL serves the same safe headers.
    fid = files["page.html"]["id"]
    url = world.admin.post(f"{_files(pid, tid)}/{fid}/download-url", json={}).json()["path"]
    d = world.browser().client.get(url)
    assert d.status_code == 200
    assert d.headers["content-type"] == "application/octet-stream"
    assert d.headers["content-disposition"].startswith("attachment")
    # Harmless files are unaffected.
    r = _upload(world.admin, pid, tid, b"hello", name="a.txt", ctype="text/plain")
    assert r.json()["content_type"] == "text/plain" and r.json()["stored_inert"] is False
    assert r.json()["original_content_type"] is None


def test_policy_of_one_product_does_not_affect_another(world):
    inert = _product(world, "crm", settings={"storage": {"blocked_types": "store_inert"}})
    strict = _product(world, "erp")
    t1, t2 = _tenant(world, inert), _tenant(world, strict)
    assert _upload(world.admin, inert, t1, b"<html>", name="a.html", ctype="text/html").status_code == 201
    assert _upload(world.admin, strict, t2, b"<html>", name="a.html", ctype="text/html").status_code == 415


def test_inert_extensions_and_extra_blocks(world):
    pid = _product(world)
    r = world.admin.put(
        _policy(world, pid),
        json={
            "blocked_types": None,
            "blocked_extensions": [".PY", "rb"],
            "blocked_content_types": ["text/x-ruby"],
            "inert_extensions": ["sh", "html"],
        },
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["blocked_extensions"] == ["py", "rb"] and body["inert_extensions"] == ["html", "sh"]
    assert body["blocked_types"] == "refuse" and body["blocked_types_source"] == "installation"
    tid = _tenant(world, pid)
    # Explicitly allowed as inert under "refuse": by extension, and a shebang script named .sh.
    r = _upload(world.admin, pid, tid, b"<html>", name="a.html", ctype="text/html")
    assert r.status_code == 201 and r.json()["stored_inert"] is True
    r = _upload(world.admin, pid, tid, b"#!/bin/sh\necho", name="run.sh", ctype="text/plain")
    assert r.status_code == 201 and r.json()["stored_inert"] is True
    _assert_safe_download(world, pid, tid, r.json()["id"])
    # The same shebang content under a name that is not allowed as inert is refused.
    assert (
        _upload(world.admin, pid, tid, b"#!/bin/sh\necho", name="run.txt", ctype="text/plain").status_code
        == 415
    )
    # Tightened: .py, .rb and text/x-ruby are blocked (and refused) now.
    assert _upload(world.admin, pid, tid, b"print(1)", name="a.py", ctype="text/plain").status_code == 415
    assert _upload(world.admin, pid, tid, b"puts 1", name="a.txt", ctype="text/x-ruby").status_code == 415
    # Built-in blocks cannot be removed: .js stays refused.
    assert _upload(world.admin, pid, tid, b"alert(1)", name="a.js", ctype="text/plain").status_code == 415
    # Renaming to a blocked extension follows the same policy.
    f = _upload(world.admin, pid, tid, b"hello", name="a.txt", ctype="text/plain").json()
    assert world.admin.patch(f"{_files(pid, tid)}/{f['id']}", json={"name": "a.js"}).status_code == 415
    r = world.admin.patch(f"{_files(pid, tid)}/{f['id']}", json={"name": "a.html"})
    assert r.status_code == 200, r.text
    assert r.json()["stored_inert"] is True and r.json()["content_type"] == "application/octet-stream"
    assert r.json()["original_content_type"] == "text/plain"
    _assert_safe_download(world, pid, tid, f["id"])


def test_policy_update_keeps_quotas_validates_and_needs_product_manage(world):
    pid = _product(world, settings={"storage": {"quota_files": 7}, "other": 1})
    tid = _tenant(world, pid)
    version = world.admin.get(f"/v1/products/{pid}").json()["version"]
    r = world.admin.put(
        _policy(world, pid), json={"blocked_types": "store_inert"}, headers={"If-Match": f'"{version + 5}"'}
    )
    assert r.status_code == 412
    r = world.admin.put(
        _policy(world, pid), json={"blocked_types": "store_inert"}, headers={"If-Match": f'"{version}"'}
    )
    assert r.status_code == 200, r.text
    assert r.json()["product_version"] == version + 1
    settings = world.admin.get(f"/v1/products/{pid}").json()["settings"]
    assert settings == {"storage": {"quota_files": 7, "blocked_types": "store_inert"}, "other": 1}
    # Invalid values are refused by the policy route and by product updates.
    assert world.admin.put(_policy(world, pid), json={"blocked_types": "allow"}).status_code == 422
    assert world.admin.put(_policy(world, pid), json={"inert_extensions": ["../x"]}).status_code == 422
    r = world.admin.patch(f"/v1/products/{pid}", json={"settings": {"storage": {"blocked_types": "inline"}}})
    assert r.status_code == 422
    r = world.admin.patch(f"/v1/products/{pid}", json={"settings": {"storage": {"inert_extensions": "html"}}})
    assert r.status_code == 422
    # Tenant members may read the policy (upload dialogs) but not change it.
    member = _member(world, pid, tid, "m@example.com", "tenant_owner")
    assert member.get(_policy(world, pid)).status_code == 200
    assert member.put(_policy(world, pid), json={}).status_code == 403
    actions = [e["action"] for e in world.admin.get(f"/v1/audit?product_id={pid}").json()["items"]]
    assert "storage.policy.update" in actions


def test_installation_inert_setting_still_applies_and_can_be_overridden(ax_factory):
    ax = ax_factory(storage={"store_blocked_as_inert": True})
    app = create_app(axentra=ax, start=False)
    world = World(ax=ax, app=app, admin=bootstrap_admin(ax, app))
    default = _product(world, "crm")
    strict = _product(world, "erp", settings={"storage": {"blocked_types": "refuse"}})
    t1, t2 = _tenant(world, default), _tenant(world, strict)
    r = _upload(world.admin, default, t1, b"<html>", name="a.html", ctype="text/html")
    assert r.status_code == 201 and r.json()["stored_inert"] is True
    assert _upload(world.admin, strict, t2, b"<html>", name="a.html", ctype="text/html").status_code == 415
    assert world.admin.get(_policy(world, default)).json()["blocked_types"] == "store_inert"
