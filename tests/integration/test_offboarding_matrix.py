"""Offboarding matrix (audit round 3): callers who HAD access to a product or tenant and lost it.

Each attacker first gets valid access and credentials, then loses the access: a tenant_admin removed
from the tenant (session kept), a product_admin whose user is disabled, a tenant_admin of a suspended
tenant, a product_admin of an archived product, a revoked key, an expired key, and a key whose
creator (a product_admin) was removed from the product (bounded by the creator's current access,
AX3-01). Every OpenAPI route under ``/v1/products/{product_id}`` plus the caller's own routes is
called on the attacker's former scope; apart from self-service routes nothing may succeed. A key
rotated with a grace period keeps working until the grace ends (that is its purpose).
"""

from __future__ import annotations

import collections
import json
from pathlib import Path
import re
from typing import Any

from fastapi.testclient import TestClient

from axentra.access.permissions import PRODUCT, TENANT
from tests.integration.conftest import World


def _ok(r: Any, code: int = 201) -> dict[str, Any]:
    assert r.status_code == code, r.text
    return r.json() if r.content else {}


def _victim(world: World, pid: str, tid: str, tag: str) -> dict[str, str]:
    a = world.admin
    base = f"/v1/products/{pid}/tenants/{tid}"
    ids: dict[str, str] = {}
    ids["collection"] = "notes"
    ids["record_id"] = _ok(a.post(f"{base}/records/notes", json={"data": {"secret": tag}}))["id"]
    f = a.post(f"{base}/files", files={"file": (f"{tag}.txt", b"secret " + tag.encode(), "text/plain")})
    ids["file_id"] = _ok(f)["id"]
    ids["job_id"] = _ok(
        a.post(
            f"/v1/products/{pid}/jobs", json={"kind": "demo.bola", "payload": {"t": tag}, "tenant_id": tid}
        )
    )["id"]
    ids["schedule_id"] = _ok(
        a.post(
            f"/v1/products/{pid}/schedules",
            json={"name": tag, "kind": "demo.bola", "interval_seconds": 3600, "tenant_id": tid},
        )
    )["id"]
    ids["webhook_id"] = _ok(
        a.post(
            f"/v1/products/{pid}/webhooks",
            json={"url": "https://hooks.example.com/x", "event_types": ["*"], "tenant_id": tid},
        )
    )["endpoint"]["id"]
    ids["invitation_id"] = _ok(a.post(f"{base}/invitations", json={"email": f"{tag}@victim.example"}))[
        "invitation"
    ]["id"]
    ids["key_id"] = _ok(
        a.post(
            f"/v1/products/{pid}/api-keys",
            json={"name": tag, "permissions": ["records:read"], "tenant_id": tid},
        )
    )["key"]["id"]
    ids["user_id"] = world.user(f"{tag}-member@victim.example")
    _ok(a.post(f"{base}/members", json={"email": f"{tag}-member@victim.example", "role": "member"}))
    ids["kind"] = "notes"
    ids["ref_id"] = "doc1"
    assert a.put(
        f"{base}/search/documents/notes/doc1", json={"title": tag, "body": "secret " + tag}
    ).status_code in (200, 201)
    ids["meter"] = "calls"
    ids["event_id"] = _ok(a.post(f"{base}/events", json={"type": "demo.happened", "data": {"t": tag}}))["id"]
    ids["role_id"] = _ok(
        a.post(
            f"/v1/products/{pid}/roles",
            json={"key": f"r{tag}", "name": tag, "scope": "tenant", "permissions": ["records:read"]},
        )
    )["id"]
    ids["plan_id"] = "pln_none"
    ids["delivery_id"] = "dlv_none"
    ids["message_id"] = "msg_none"
    ids["reservation_id"] = "rsv_none"
    ids["meter_id"] = _ok(a.post(f"/v1/products/{pid}/usage/meters", json={"key": f"m{tag}", "unit": "u"}))[
        "id"
    ]
    ids["key"] = "tpl"
    ids["name"] = "crm.x:y"
    ids["provider"] = "stripe"
    ids["token"] = "x"
    ids["session_id"] = "ses_none"
    return ids


BODIES: dict[tuple[str, str], dict[str, Any]] = {
    ("POST", "/api-keys"): {"name": "x", "permissions": ["records:read"], "tenant_id": "{T}"},
    ("POST", "/billing/plans"): {"key": "x", "name": "x"},
    ("POST", "/jobs"): {"kind": "demo.bola", "tenant_id": "{T}"},
    ("POST", "/members"): {"role": "member", "email": "tadmin@example.com"},
    ("PATCH", "/members/{user_id}"): {"role": "viewer"},
    ("POST", "/notify/templates"): {"key": "x", "variants": {"en": {"subject": "s", "text": "t"}}},
    ("POST", "/notify/templates/preview"): {"variants": {"en": {"subject": "s", "text": "t"}}},
    ("PUT", "/permissions/{name}"): {"scope": "tenant"},
    ("POST", "/roles"): {"key": "x", "name": "x", "scope": "tenant", "permissions": ["records:read"]},
    ("POST", "/schedules"): {"name": "x", "kind": "demo.bola", "interval_seconds": 60, "tenant_id": "{T}"},
    ("POST", "/tenants"): {"slug": "evil", "name": "x"},
    ("PATCH", "/tenants/{tenant_id}"): {"status": "suspended"},
    ("POST", "/billing/checkout"): {
        "plan": "x",
        "success_url": "https://a.example",
        "cancel_url": "https://a.example",
    },
    ("PUT", "/billing/entitlements/overrides"): {"entitlements": {}},
    ("POST", "/billing/subscription"): {"plan": "x"},
    ("POST", "/billing/subscription/change-plan"): {"plan": "x"},
    ("POST", "/billing/subscription/status"): {"status": "canceled"},
    ("POST", "/events"): {"type": "demo.x"},
    ("POST", "/invitations"): {"email": "evil@example.com", "role": "member"},
    ("POST", "/notify/send"): {"template_key": "x", "to": {"email": "evil@example.com"}},
    ("PUT", "/usage/quotas/{meter}"): {"limit": 1},
    ("POST", "/usage/events"): {"meter": "calls", "quantity": 1},
    ("POST", "/usage/reservations"): {"meter": "calls", "quantity": 1},
    ("POST", "/usage/meters"): {"key": "evil"},
    ("POST", "/webhooks"): {"url": "https://hooks.example.com/z", "event_types": ["*"], "tenant_id": "{T}"},
    ("PATCH", "/webhooks/{webhook_id}"): {"url": "https://evil.example.com/z"},
    ("PATCH", "/files/{file_id}"): {"name": "pwned.txt"},
    ("PUT", "/records/{collection}/{record_id}"): {"pwned": True},
    ("PUT", "/search/documents/{kind}/{ref_id}"): {"title": "pwned", "body": "pwned"},
    ("PUT", "/storage/quota"): {"quota_bytes": 1},
    ("PATCH", "/schedules/{schedule_id}"): {"enabled": False},
    ("PATCH", "/roles/{role_id}"): {"permissions": ["records:write"]},
    ("PATCH", "/usage/meters/{meter_id}"): {"active": False},
}


def _body(method: str, path: str, tid: str) -> dict[str, Any]:
    for (m, suffix), body in BODIES.items():
        if m == method and path.endswith(suffix):
            return json.loads(json.dumps(body).replace("{T}", tid))
    return {}


EXPECTED_TO_WORK = {"old_rotated_key"}


def _key(world: World, client: Any, pid: str, name: str, tid: str | None = None) -> tuple[str, str]:
    body: dict[str, Any] = {"name": name, "permissions": sorted(PRODUCT | TENANT if tid is None else TENANT)}
    if tid:
        body["tenant_id"] = tid
    r = client.post(f"/v1/products/{pid}/api-keys", json=body)
    if r.status_code == 403 and "do not hold:" in r.text:
        # A non-owner creator: drop what it cannot grant (role ceiling) and retry.
        held_not = {p.strip() for p in r.json()["detail"].split("do not hold:", 1)[1].split(",")}
        body["permissions"] = [p for p in body["permissions"] if p not in held_not]
        r = client.post(f"/v1/products/{pid}/api-keys", json=body)
    j = _ok(r)
    return j["key"]["id"], j["secret"]


def test_offboarded_callers_reach_nothing(world: World) -> None:
    world.ax.jobs.register("demo.bola", lambda ctx: None)
    a = world.admin
    p1 = _ok(a.post("/v1/products", json={"slug": "pone", "name": "P1"}))["id"]
    p1a = _ok(a.post("/v1/products", json={"slug": "parch", "name": "P1a"}))["id"]
    t1 = _ok(a.post(f"/v1/products/{p1}/tenants", json={"slug": "t-one", "name": "T1"}))["id"]
    t1s = _ok(a.post(f"/v1/products/{p1}/tenants", json={"slug": "t-susp", "name": "T1s"}))["id"]
    t1a = _ok(a.post(f"/v1/products/{p1a}/tenants", json={"slug": "t-arch", "name": "T1a"}))["id"]
    for pid in (p1, p1a):
        _ok(a.post(f"/v1/products/{pid}/usage/meters", json={"key": "calls", "unit": "calls"}))
    objs = {
        p1: {t1: _victim(world, p1, t1, "vone"), t1s: _victim(world, p1, t1s, "vsusp")},
        p1a: {t1a: _victim(world, p1a, t1a, "varch")},
    }

    def member(email: str, url: str, role: str) -> str:
        uid = world.user(email)
        _ok(a.post(url, json={"email": email, "role": role}))
        return uid

    u_rt = member("rt@example.com", f"/v1/products/{p1}/tenants/{t1}/members", "tenant_admin")
    u_dp = member("dp@example.com", f"/v1/products/{p1}/members", "product_admin")
    member("st@example.com", f"/v1/products/{p1}/tenants/{t1s}/members", "tenant_admin")
    member("ap@example.com", f"/v1/products/{p1a}/members", "product_admin")
    u_kp = member("kp@example.com", f"/v1/products/{p1}/members", "product_admin")

    sessions = {
        n: world.login_as(e)
        for n, e in (
            ("removed_tadmin", "rt@example.com"),
            ("disabled_padmin", "dp@example.com"),
            ("susp_tadmin", "st@example.com"),
            ("archived_padmin", "ap@example.com"),
        )
    }
    kp = world.login_as("kp@example.com")
    _, kp_secret = _key(world, kp, p1, "kp-key")
    rk_id, rk_secret = _key(world, a, p1, "revoked")
    ek_id, ek_secret = _key(world, a, p1, "expired")
    ok_id, ok_secret = _key(world, a, p1, "rotated")

    # Now take the access away.
    assert a.delete(f"/v1/products/{p1}/tenants/{t1}/members/{u_rt}").status_code == 204
    assert a.patch(f"/v1/users/{u_dp}", json={"status": "disabled"}).status_code == 200
    assert a.patch(f"/v1/products/{p1}/tenants/{t1s}", json={"status": "suspended"}).status_code == 200
    assert a.post(f"/v1/products/{p1a}/archive").status_code == 200
    assert a.delete(f"/v1/products/{p1}/members/{u_kp}").status_code == 204
    assert a.post(f"/v1/products/{p1}/api-keys/{rk_id}/revoke").status_code in (200, 204)
    from axentra.data.database import DbScope

    with world.ax.db.transaction(DbScope.platform()) as tx:
        tx.execute(
            "UPDATE axentra_api_keys SET expires_at = now() - interval '1 minute' WHERE id = %s", (ek_id,)
        )
    rot = a.post(f"/v1/products/{p1}/api-keys/{ok_id}/rotate", json={"grace_seconds": 3600})
    assert rot.status_code == 200, rot.text

    attackers: dict[str, Any] = dict(sessions)
    for name, secret in (
        ("revoked_key", rk_secret),
        ("expired_key", ek_secret),
        ("removed_padmin_key", kp_secret),
        ("old_rotated_key", ok_secret),
    ):
        attackers[name] = TestClient(world.app, headers={"Authorization": f"Bearer {secret}"})

    # Scope per attacker: (product, tenant) of the access it used to have.
    scope = {
        "removed_tadmin": (p1, t1),
        "disabled_padmin": (p1, t1),
        "susp_tadmin": (p1, t1s),
        "archived_padmin": (p1a, t1a),
        "revoked_key": (p1, t1),
        "expired_key": (p1, t1),
        "removed_padmin_key": (p1, t1),
        "old_rotated_key": (p1, t1),
    }
    spec = json.loads(Path("openapi/axentra-v1.json").read_text())
    hits: list[dict[str, Any]] = []
    dist: dict[str, collections.Counter[str]] = {n: collections.Counter() for n in attackers}
    for path, methods in spec["paths"].items():
        if not path.startswith("/v1/products/{product_id}") and not path.startswith(
            ("/v1/me", "/v1/users", "/v1/audit", "/v1/auth/sessions")
        ):
            continue
        if path.endswith("/stream"):
            continue
        for method in methods:
            for who, client in attackers.items():
                pid, tid = scope[who]
                ids = objs[pid][tid]
                url = path.replace("{product_id}", pid).replace("{tenant_id}", tid)
                url = re.sub(r"\{(\w+)\}", lambda m, ids=ids: ids.get(m.group(1), "zz"), url)
                kw: dict[str, Any] = {}
                if method.upper() in ("POST", "PUT", "PATCH"):
                    kw["json"] = _body(method.upper(), path, tid)
                r = client.request(method.upper(), url, **kw)
                dist[who][str(r.status_code)] += 1
                if r.status_code < 400 or r.status_code >= 500:
                    hits.append(
                        {
                            "who": who,
                            "m": method.upper(),
                            "path": path,
                            "status": r.status_code,
                            "body": r.text[:200],
                        }
                    )
    # The caller's own state. Marking one's own inbox read product-wide leaves the messages of a tenant that
    # is not active unchanged (tests/integration/test_inbox_api.py::test_suspended_tenant_messages_stay_unread).
    self_service = (
        "/v1/me",
        "/v1/products/{product_id}/notify/preferences/me",
        "/v1/products/{product_id}/notify/inbox/me/read",
    )
    unexpected = [
        h
        for h in hits
        if h["who"] not in EXPECTED_TO_WORK
        and h["path"] not in self_service
        and (h["m"] != "GET" or h["status"] >= 500)
    ]
    assert not unexpected, unexpected
    # The key of a removed creator reaches nothing at all (reads included), only who-am-I routes.
    key_hits = [
        h for h in hits if h["who"] == "removed_padmin_key" and h["path"] not in ("/v1/me", "/v1/meta")
    ]
    assert not key_hits, key_hits
    assert dist["removed_padmin_key"]["403"] > 0
    # Revoked, expired and disabled credentials are not authenticated at all.
    for who in ("revoked_key", "expired_key", "disabled_padmin"):
        assert set(dist[who]) <= {"401", "200"}, (who, dist[who])
