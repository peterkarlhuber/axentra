"""Webhooks (signed delivery to a local HTTP server, retries, SSRF), HTTP API, permissions and SSE."""

from __future__ import annotations

from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import threading
import time
from typing import Any

import pytest

from axentra.api.app import create_app
from axentra.core.context import Principal
from axentra.core.errors import ValidationFailed
from axentra.events import JobWorker, verify_signature
from tests.integration.conftest import World, bootstrap_admin

SYS = Principal.system("test")
ALLOW_LOCAL = {
    "events": {
        "webhook_allow_private_targets": True,
        "webhook_allow_http": True,
        "backoff_base_seconds": 0.01,
        "backoff_max_seconds": 0.02,
        "listen_notify": False,
        "webhook_timeout_seconds": 3,
        "webhook_max_attempts": 3,
        "sse_poll_seconds": 0.05,
        "sse_max_seconds": 1.5,
        "sse_reauth_seconds": 0.2,
    }
}


class Receiver:
    def __init__(self) -> None:
        self.requests: list[dict[str, Any]] = []
        self.statuses: list[int] = []
        outer = self

        class H(BaseHTTPRequestHandler):
            def do_POST(self) -> None:
                body = self.rfile.read(int(self.headers["Content-Length"]))
                outer.requests.append({"headers": dict(self.headers), "body": body, "path": self.path})
                code = outer.statuses.pop(0) if outer.statuses else 200
                self.send_response(code)
                self.end_headers()
                self.wfile.write(b"x" * 10_000)

            def log_message(self, *a: Any) -> None:
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.server.server_address[1]}/hook?x=1"

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()


@pytest.fixture
def receiver() -> Iterator[Receiver]:
    r = Receiver()
    yield r
    r.close()


@pytest.fixture
def lworld(ax_factory) -> Iterator[World]:
    ax = ax_factory(**ALLOW_LOCAL)
    app = create_app(axentra=ax, start=False)
    yield World(ax=ax, app=app, admin=bootstrap_admin(ax, app))


def _product(world, slug="crm"):
    r = world.admin.post("/v1/products", json={"slug": slug, "name": slug.upper()})
    assert r.status_code == 201, r.text
    pid = r.json()["id"]
    tids = []
    for t in ("acme", "globex"):
        r = world.admin.post(f"/v1/products/{pid}/tenants", json={"slug": t, "name": t})
        assert r.status_code == 201, r.text
        tids.append(r.json()["id"])
    return pid, tids[0], tids[1]


def _drain(ax, rounds=10):
    w = JobWorker(ax, scheduler=False)
    for _ in range(rounds):
        if w.run_once() == 0:
            time.sleep(0.05)
            if w.run_once() == 0:
                return


def test_webhook_signed_delivery_and_secret_shown_once(lworld, receiver):
    w, ax = lworld, lworld.ax
    pid, t1, t2 = _product(w)
    r = w.admin.post(
        f"/v1/products/{pid}/webhooks",
        json={"url": receiver.url, "event_types": ["invoice.*"], "tenant_id": t1},
    )
    assert r.status_code == 201, r.text
    secret = r.json()["secret"]
    wid = r.json()["endpoint"]["id"]
    assert secret.startswith("whsec_")
    got = w.admin.get(f"/v1/products/{pid}/webhooks/{wid}").json()
    assert "secret" not in json.dumps(got).replace("has_previous_secret", "").replace(
        "previous_secret_expires_at", ""
    )
    # Event of the filtered tenant: delivered and signed; other tenant/type: not delivered.
    assert (
        w.admin.post(
            f"/v1/products/{pid}/tenants/{t1}/events", json={"type": "invoice.paid", "data": {"a": 1}}
        ).status_code
        == 201
    )
    w.admin.post(f"/v1/products/{pid}/tenants/{t2}/events", json={"type": "invoice.paid", "data": {}})
    w.admin.post(f"/v1/products/{pid}/tenants/{t1}/events", json={"type": "user.created", "data": {}})
    _drain(ax)
    assert len(receiver.requests) == 1
    req = receiver.requests[0]
    assert req["path"] == "/hook?x=1"
    assert verify_signature(secret, req["headers"]["Axentra-Signature"], req["body"])
    assert not verify_signature("whsec_wrong", req["headers"]["Axentra-Signature"], req["body"])
    body = json.loads(req["body"])
    assert body["type"] == "invoice.paid" and body["data"] == {"a": 1} and body["tenant_id"] == t1
    assert req["headers"]["Axentra-Event-Id"] == body["id"]
    dl = w.admin.get(f"/v1/products/{pid}/webhooks/{wid}/deliveries").json()["items"]
    assert len(dl) == 1 and dl[0]["status"] == "succeeded" and dl[0]["response_code"] == 200
    assert len(dl[0]["response_body"]) == 4096  # truncated
    # Rotation with grace: both signatures accepted; the old one alone afterwards is not.
    r = w.admin.post(f"/v1/products/{pid}/webhooks/{wid}/rotate-secret", json={"grace_seconds": 60})
    new_secret = r.json()["secret"]
    assert new_secret != secret and r.json()["endpoint"]["has_previous_secret"] is True
    ping = w.admin.post(f"/v1/products/{pid}/webhooks/{wid}/test")
    assert ping.status_code == 200 and ping.json()["status"] == "succeeded", ping.text
    last = receiver.requests[-1]
    assert verify_signature(new_secret, last["headers"]["Axentra-Signature"], last["body"])
    assert verify_signature(secret, last["headers"]["Axentra-Signature"], last["body"])
    assert json.loads(last["body"])["type"] == "axentra.ping"
    # The stored secret is encrypted.
    from axentra.data.database import DbScope

    with ax.db.transaction(DbScope.platform()) as tx:
        enc = tx.scalar("SELECT secret_enc FROM axentra_webhook_endpoints WHERE id = %s", (wid,))
    assert enc.startswith("axs1.") and new_secret not in enc


def test_webhook_retries_then_dead_and_redeliver(lworld, receiver):
    w, ax = lworld, lworld.ax
    pid, t1, _ = _product(w)
    receiver.statuses = [500, 503, 500]
    wid = w.admin.post(
        f"/v1/products/{pid}/webhooks", json={"url": receiver.url, "event_types": ["*"]}
    ).json()["endpoint"]["id"]
    ax.events.publish(SYS, pid, t1, "order.created", {"n": 1})
    _drain(ax, rounds=20)
    dl = w.admin.get(f"/v1/products/{pid}/webhooks/{wid}/deliveries").json()["items"][0]
    assert dl["status"] == "dead" and dl["attempts"] == 3 and dl["response_code"] == 500
    assert len(receiver.requests) == 3
    job = w.admin.get(f"/v1/products/{pid}/jobs/{dl['job_id']}").json()
    assert job["status"] == "dead"
    r = w.admin.post(f"/v1/products/{pid}/webhooks/{wid}/deliveries/{dl['id']}/redeliver")
    assert r.status_code == 202 and r.json()["status"] == "pending"
    assert (
        w.admin.post(f"/v1/products/{pid}/webhooks/{wid}/deliveries/{dl['id']}/redeliver").status_code == 409
    )
    _drain(ax)
    dl = w.admin.get(f"/v1/products/{pid}/webhooks/{wid}/deliveries/{dl['id']}").json()
    assert dl["status"] == "succeeded" and dl["attempts"] == 4
    # All four requests carried the same event id (receivers deduplicate on it).
    assert len({r["headers"]["Axentra-Event-Id"] for r in receiver.requests}) == 1


def test_ssrf_refusals(ax_factory, receiver, monkeypatch):
    ax = ax_factory(events={"webhook_allow_http": True})
    p = ax.tenancy.create_product(SYS, slug="crm", name="CRM")
    for url in (
        "http://127.0.0.1:8080/x",
        "https://localhost/x",
        "https://10.0.0.5/x",
        "https://169.254.169.254/latest/meta-data",
        "https://[::1]/x",
        "https://[::ffff:127.0.0.1]/x",
        "ftp://example.com/x",
        "https://user:pw@example.com/x",
    ):
        with pytest.raises(ValidationFailed):
            ax.webhooks.create(SYS, p.id, url=url, event_types=["*"])
    # A host name that resolves to a private address passes the static check but is refused at
    # delivery, before any connection is made (every resolved address is checked).
    import socket

    from axentra.events.http_client import parse_target

    created = ax.webhooks.create(
        SYS, p.id, url=f"http://hooks.example.test:{receiver.server.server_address[1]}/", event_types=["*"]
    )
    real = socket.getaddrinfo

    def fake(host, port, *a, **kw):
        if host == "hooks.example.test":
            return [
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", port)),
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", port)),
            ]
        return real(host, port, *a, **kw)

    monkeypatch.setattr(socket, "getaddrinfo", fake)
    d = ax.webhooks.test(SYS, p.id, created.endpoint.id)
    assert d.status == "dead" and "refused" in (d.last_error or "") and receiver.requests == []
    # https only in production, whatever the settings say.
    with pytest.raises(ValidationFailed):
        parse_target("http://example.com/", ax.settings.events, production=True)


def test_ssrf_disallows_loopback_delivery_without_setting(ax_factory, receiver):
    ax = ax_factory(events={"webhook_allow_http": True, "webhook_allow_private_targets": True})
    p = ax.tenancy.create_product(SYS, slug="crm", name="CRM")
    ep = ax.webhooks.create(SYS, p.id, url=receiver.url, event_types=["*"])
    ax.settings.events.webhook_allow_private_targets = False
    d = ax.webhooks.test(SYS, p.id, ep.endpoint.id)
    assert d.status == "dead" and "refused" in (d.last_error or "")
    assert receiver.requests == []


def test_api_jobs_permissions_and_isolation(lworld):
    w = lworld
    pid, t1, t2 = _product(w)
    opid, _, _ = _product(w, "erp")
    r = w.admin.post(
        f"/v1/products/{pid}/jobs",
        json={"kind": "demo.x", "payload": {"a": 1}, "tenant_id": t1},
        headers={"Idempotency-Key": "k-1"},
    )
    assert r.status_code == 201, r.text
    jid = r.json()["id"]
    again = w.admin.post(
        f"/v1/products/{pid}/jobs",
        json={"kind": "demo.x", "tenant_id": t1},
        headers={"Idempotency-Key": "k-1"},
    )
    assert again.json()["id"] == jid
    assert (
        w.admin.post(f"/v1/products/{pid}/jobs", json={"kind": "axentra.webhook.deliver"}).status_code == 422
    )
    lst = w.admin.get(f"/v1/products/{pid}/jobs", params={"status": "queued", "tenant_id": t1}).json()
    assert [j["id"] for j in lst["items"]] == [jid]
    assert w.admin.get(f"/v1/products/{opid}/jobs/{jid}").status_code == 404
    stats = w.admin.get(f"/v1/products/{pid}/jobs/stats").json()
    assert stats["counts"]["queued"] == 1 and stats["by_kind"][0]["kind"] == "demo.x"
    assert w.admin.post(f"/v1/products/{pid}/jobs/{jid}/retry").status_code == 409
    assert w.admin.post(f"/v1/products/{pid}/jobs/{jid}/cancel").json()["status"] == "cancelled"

    # A tenant member: may publish events in their tenant, cannot read jobs or manage webhooks.
    w.user("m@example.com")
    w.admin.post(
        f"/v1/products/{pid}/tenants/{t1}/members", json={"email": "m@example.com", "role": "member"}
    )
    m = w.login_as("m@example.com")
    assert (
        m.post(f"/v1/products/{pid}/tenants/{t1}/events", json={"type": "note.added", "data": {}}).status_code
        == 201
    )
    assert (
        m.post(f"/v1/products/{pid}/tenants/{t2}/events", json={"type": "note.added", "data": {}}).status_code
        == 404
    )
    assert m.get(f"/v1/products/{pid}/jobs").status_code == 403
    assert m.get(f"/v1/products/{pid}/webhooks").status_code == 403
    assert (
        m.post(
            f"/v1/products/{pid}/webhooks", json={"url": "https://example.com/h", "event_types": ["*"]}
        ).status_code
        == 403
    )
    # A viewer operator reads but cannot manage.
    w.user("v@example.com")
    w.admin.post(f"/v1/products/{pid}/members", json={"email": "v@example.com", "role": "product_viewer"})
    v = w.login_as("v@example.com")
    assert v.get(f"/v1/products/{pid}/jobs").status_code == 200
    assert v.get(f"/v1/products/{pid}/events").status_code == 200
    assert v.post(f"/v1/products/{pid}/jobs", json={"kind": "demo.x"}).status_code == 403
    assert v.post(f"/v1/products/{pid}/jobs/{jid}/retry").status_code == 403
    assert (
        v.post(
            f"/v1/products/{pid}/schedules", json={"name": "s", "kind": "demo.x", "interval_seconds": 60}
        ).status_code
        == 403
    )
    # Strangers get 404 everywhere.
    w.user("s@example.com")
    s = w.login_as("s@example.com")
    assert s.get(f"/v1/products/{pid}/jobs/{jid}").status_code == 404
    assert s.get(f"/v1/products/{pid}/events").status_code == 404
    assert s.get(f"/v1/products/{pid}/events/stream").status_code == 404
    assert w.browser().get(f"/v1/products/{pid}/jobs").status_code == 401


def test_api_schedules_and_events_crud(lworld):
    w = lworld
    pid, t1, _ = _product(w)
    r = w.admin.post(
        f"/v1/products/{pid}/schedules", json={"name": "s", "kind": "demo.x", "cron": "*/5 * * * *"}
    )
    assert r.status_code == 201, r.text
    sid = r.json()["id"]
    assert w.admin.get(f"/v1/products/{pid}/schedules").json()["items"][0]["id"] == sid
    assert (
        w.admin.patch(
            f"/v1/products/{pid}/schedules/{sid}", json={"enabled": False}, headers={"If-Match": "9"}
        ).status_code
        == 412
    )
    u = w.admin.patch(
        f"/v1/products/{pid}/schedules/{sid}", json={"enabled": False}, headers={"If-Match": "1"}
    )
    assert u.status_code == 200 and u.json()["enabled"] is False
    assert w.admin.delete(f"/v1/products/{pid}/schedules/{sid}").status_code == 204
    assert w.admin.get(f"/v1/products/{pid}/schedules/{sid}").status_code == 404
    e = w.admin.post(
        f"/v1/products/{pid}/tenants/{t1}/events",
        json={"type": "a.b", "data": {"x": 1}},
        headers={"Idempotency-Key": "e1"},
    ).json()
    e2 = w.admin.post(
        f"/v1/products/{pid}/tenants/{t1}/events",
        json={"type": "a.b", "data": {"x": 2}},
        headers={"Idempotency-Key": "e1"},
    ).json()
    assert e["id"] == e2["id"]
    assert w.admin.get(f"/v1/products/{pid}/events/{e['id']}").json()["data"] == {"x": 1}
    assert [
        x["id"] for x in w.admin.get(f"/v1/products/{pid}/events", params={"type": "a.*"}).json()["items"]
    ] == [e["id"]]
    assert (
        w.admin.post(f"/v1/products/{pid}/tenants/{t1}/events", json={"type": "axentra.x"}).status_code == 422
    )


def _parse_sse(text: str) -> list[dict[str, str]]:
    out = []
    for block in text.split("\n\n"):
        msg: dict[str, str] = {}
        for line in block.splitlines():
            if line.startswith(":"):
                continue
            k, _, v = line.partition(": ")
            msg[k] = v
        if "event" in msg:
            out.append(msg)
    return out


def test_sse_event_stream_resume_and_revocation(lworld):
    w, ax = lworld, lworld.ax
    pid, t1, t2 = _product(w)
    e1 = ax.events.publish(SYS, pid, t1, "a.one", {"n": 1})
    e2 = ax.events.publish(SYS, pid, t2, "a.two", {"n": 2})
    r = w.admin.get(f"/v1/products/{pid}/events/stream", headers={"Last-Event-ID": "0"})
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/event-stream")
    msgs = _parse_sse(r.text)
    assert [json.loads(m["data"])["id"] for m in msgs] == [e1.id, e2.id]
    # Resume after the first event; tenant filter and type filter.
    r = w.admin.get(f"/v1/products/{pid}/events/stream", headers={"Last-Event-ID": msgs[0]["id"]})
    assert [json.loads(m["data"])["id"] for m in _parse_sse(r.text)] == [e2.id]
    r = w.admin.get(
        f"/v1/products/{pid}/events/stream", params={"tenant_id": t1}, headers={"Last-Event-ID": "0"}
    )
    assert [json.loads(m["data"])["id"] for m in _parse_sse(r.text)] == [e1.id]
    r = w.admin.get(
        f"/v1/products/{pid}/events/stream", params={"types": "a.t*"}, headers={"Last-Event-ID": "0"}
    )
    assert [m["event"] for m in _parse_sse(r.text)] == ["a.two"]
    assert (
        w.admin.get(f"/v1/products/{pid}/events/stream", headers={"Last-Event-ID": "nope"}).status_code == 422
    )
    # New events published while streaming arrive; without Last-Event-ID old ones do not.
    threading.Timer(0.4, lambda: ax.events.publish(SYS, pid, t1, "a.live", {})).start()
    r = w.admin.get(f"/v1/products/{pid}/events/stream")
    assert [m["event"] for m in _parse_sse(r.text)] == ["a.live"]
    # Jobs stream.
    r = w.admin.get(f"/v1/products/{pid}/jobs/stream", headers={"Last-Event-ID": "0"})
    assert {m["event"] for m in _parse_sse(r.text)} == {"job.queued"}
    # Session revoked mid-stream: an error event ends the stream before sse_max_seconds.
    w.user("op@example.com")
    w.admin.post(f"/v1/products/{pid}/members", json={"email": "op@example.com", "role": "product_viewer"})
    op = w.login_as("op@example.com")
    from axentra.data.database import DbScope

    def revoke() -> None:
        with ax.db.transaction(DbScope.platform()) as tx:
            tx.execute(
                "UPDATE axentra_sessions SET revoked_at = now() WHERE user_id ="
                " (SELECT id FROM axentra_users WHERE email = 'op@example.com')"
            )

    threading.Timer(0.3, revoke).start()
    t0 = time.monotonic()
    r = op.get(f"/v1/products/{pid}/events/stream")
    assert time.monotonic() - t0 < 1.4
    assert _parse_sse(r.text)[-1]["event"] == "error"
