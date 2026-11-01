from __future__ import annotations

import logging
import threading
import time
from typing import Any

import pytest

from axentra.api.app import create_app
from axentra.data.database import DbScope
from axentra.notify.providers import OutgoingMessage, ProviderError
from tests.integration.conftest import World, bootstrap_admin

EN = {"subject": "Hi {{ name }}", "text": "Hello {{ name }}", "html": "<p>Hello {{ name }}</p>"}
DE = {"subject": "Hallo {{ name }}", "text": "Hallo {{ name }}"}


def _product(world: World, slug: str = "crm", settings: dict[str, Any] | None = None) -> str:
    r = world.admin.post(
        "/v1/products", json={"slug": slug, "name": slug.upper(), "settings": settings or {}}
    )
    assert r.status_code == 201, r.text
    return str(r.json()["id"])


def _tenant(world: World, pid: str, slug: str = "acme") -> str:
    r = world.admin.post(f"/v1/products/{pid}/tenants", json={"slug": slug, "name": slug.title()})
    assert r.status_code == 201, r.text
    return str(r.json()["id"])


def _member(world: World, pid: str, tid: str, email: str, role: str = "member") -> str:
    uid = world.user(email)
    r = world.admin.post(f"/v1/products/{pid}/tenants/{tid}/members", json={"email": email, "role": role})
    assert r.status_code == 201, r.text
    return uid


def _template(
    world: World, pid: str, key: str = "welcome", category: str = "transactional", **kw: Any
) -> dict:
    body = {
        "key": key,
        "category": category,
        "variables": ["name"],
        "sample_data": {"name": "Sample"},
        "variants": {"en": EN, "de": DE},
        **kw,
    }
    r = world.admin.post(f"/v1/products/{pid}/notify/templates", json=body)
    assert r.status_code == 201, r.text
    return dict(r.json())


def _send(
    browser: Any, pid: str, tid: str, to: dict, key: str = "welcome", idem: str | None = None, **kw: Any
):  # type: ignore[no-untyped-def]
    headers = {"Idempotency-Key": idem} if idem else {}
    return browser.post(
        f"/v1/products/{pid}/tenants/{tid}/notify/send",
        json={"template_key": key, "to": to, "variables": {"name": "<Bob & Co>"}, **kw},
        headers=headers,
    )


class FakeProvider:
    name = "fake"

    def __init__(self, fail_times: int = 0, permanent: bool = False, delay: float = 0.0) -> None:
        self.fail_times = fail_times
        self.permanent = permanent
        self.delay = delay
        self.sent: list[OutgoingMessage] = []
        self.calls = 0
        self._lock = threading.Lock()

    def send(self, message: OutgoingMessage) -> str:
        with self._lock:
            self.calls += 1
            fail = self.calls <= self.fail_times
        if self.delay:
            time.sleep(self.delay)
        if fail:
            raise ProviderError("boom token=axinv_" + "x" * 20, permanent=self.permanent)
        with self._lock:
            self.sent.append(message)
        return f"fake-{message.message_id}"

    def check(self) -> bool:
        return True


# -- templates ------------------------------------------------------------------------------------


def test_template_crud_versioning_and_preview(world):
    pid = _product(world)
    listed = world.admin.get(f"/v1/products/{pid}/notify/templates").json()
    assert [t["key"] for t in listed] == ["invitation"] and listed[0]["builtin"] and listed[0]["version"] == 0
    t = _template(world, pid)
    assert t["version"] == 1 and not t["builtin"]
    r = world.admin.patch(
        f"/v1/products/{pid}/notify/templates/welcome", json={"name": "Welcome"}, headers={"If-Match": "1"}
    )
    assert r.status_code == 200 and r.json()["version"] == 2
    r = world.admin.patch(
        f"/v1/products/{pid}/notify/templates/welcome", json={"name": "Stale"}, headers={"If-Match": "1"}
    )
    assert r.status_code == 412
    assert (
        world.admin.post(
            f"/v1/products/{pid}/notify/templates",
            json={"key": "welcome", "variants": {"en": EN}, "variables": ["name"]},
        ).status_code
        == 409
    )
    # Preview with sample data, locale fallback de-AT -> de, HTML escaping.
    r = world.admin.post(f"/v1/products/{pid}/notify/templates/welcome/preview", json={"locale": "de-AT"})
    assert r.json() == {"locale": "de", "subject": "Hallo Sample", "text": "Hallo Sample", "html": None}
    r = world.admin.post(
        f"/v1/products/{pid}/notify/templates/welcome/preview",
        json={"locale": "fr", "variables": {"name": "<i>"}},
    )
    assert r.json()["locale"] == "en" and r.json()["html"] == "<p>Hello &lt;i&gt;</p>"
    r = world.admin.post(
        f"/v1/products/{pid}/notify/templates/preview",
        json={"variants": {"en": {"subject": "S {{ x }}", "text": "T"}}, "variables": ["x"], "values": {}},
    )
    assert r.status_code == 422 and "missing" in r.text
    # Built-in invitation preview works for de and en.
    r = world.admin.post(f"/v1/products/{pid}/notify/templates/invitation/preview", json={"locale": "de"})
    assert r.status_code == 200 and "eingeladen" in r.json()["subject"]
    # Override and restore the built-in default.
    assert world.admin.delete(f"/v1/products/{pid}/notify/templates/invitation").status_code == 404
    assert (
        world.admin.delete(
            f"/v1/products/{pid}/notify/templates/welcome", headers={"If-Match": "1"}
        ).status_code
        == 412
    )
    assert world.admin.delete(f"/v1/products/{pid}/notify/templates/welcome").status_code == 204
    assert world.admin.get(f"/v1/products/{pid}/notify/templates/welcome").status_code == 404


@pytest.mark.parametrize(
    ("body", "fragment"),
    [
        ({"variants": {"en": {"subject": "{{ x }}", "text": "t"}}}, "undeclared"),
        ({"variants": {"de": {"subject": "s", "text": "t"}}}, "'en'"),
        ({"channel": "sms", "variants": {"en": {"subject": "s", "text": "t"}}}, "not available"),
        ({"variants": {"en": {"subject": "s", "text": "{{ a.b }}"}}, "variables": ["a"]}, "placeholder"),
        ({"variants": {"en": {"subject": "s", "text": "{% if x %}"}}}, None),
        ({"category": "Bad Category", "variants": {"en": {"subject": "s", "text": "t"}}}, "category"),
        ({"variants": {"EN_us!": {"subject": "s", "text": "t"}}}, "locale"),
    ],
)
def test_template_validation(world, body, fragment):
    pid = _product(world)
    r = world.admin.post(f"/v1/products/{pid}/notify/templates", json={"key": "bad", **body})
    if fragment is None:  # not a placeholder: plain text is fine
        assert r.status_code == 201
        return
    assert r.status_code == 422, r.text
    assert fragment in r.text


# -- sending --------------------------------------------------------------------------------------


def test_send_idempotent_dispatch_and_local_mailbox(world):
    pid = _product(world)
    tid = _tenant(world, pid)
    _template(world, pid)
    uid = _member(world, pid, tid, "bob@example.com")
    _member(world, pid, tid, "alice@example.com")
    alice = world.login_as("alice@example.com")
    r = _send(alice, pid, tid, {"user_id": uid}, idem="k-1")
    assert r.status_code == 202, r.text
    msg = r.json()
    assert msg["status"] == "queued" and msg["recipient"] == "bob@example.com" and msg["locale"] == "en"
    assert msg["subject"] == "Hi <Bob & Co>" and msg["content_state"] == "available"
    again = _send(alice, pid, tid, {"user_id": uid}, idem="k-1")
    assert again.status_code == 200 and again.headers["Idempotent-Replayed"] == "true"
    assert again.json()["id"] == msg["id"]
    assert _send(alice, pid, tid, {"email": "other@example.com"}, idem="k-1").status_code == 409
    # Missing variables / unknown template / bad recipient.
    r = alice.post(
        f"/v1/products/{pid}/tenants/{tid}/notify/send",
        json={"template_key": "welcome", "to": {"email": "x@example.com"}},
    )
    assert r.status_code == 422 and "name" in r.text
    assert _send(alice, pid, tid, {"email": "x@example.com"}, key="nope").status_code == 404
    assert _send(alice, pid, tid, {"email": "not-an-email"}).status_code == 422
    assert _send(alice, pid, tid, {"email": "a@example.com", "user_id": uid}).status_code == 422
    # A user outside the tenant cannot be targeted by id (no oracle on global users).
    stranger = world.user("stranger@example.com")
    assert _send(alice, pid, tid, {"user_id": stranger}).status_code == 404
    # Locale choice: explicit wins.
    r = _send(alice, pid, tid, {"email": "carl@example.com"}, locale="de")
    assert r.json()["locale"] == "de"

    res = world.ax.notify.dispatcher().run_once(10)
    assert (res.claimed, res.sent, res.failed) == (2, 2, 0)
    got = world.admin.get(f"/v1/products/{pid}/notify/messages/{msg['id']}").json()
    assert got["status"] == "sent" and got["attempts"] == 1 and got["provider"] == "local"
    assert (
        got["provider_message_id"].startswith("<")
        and got["content"]["html"] == "<p>Hello &lt;Bob &amp; Co&gt;</p>"
    )
    box = world.admin.get(
        f"/v1/products/{pid}/notify/mailbox", params={"recipient": "BOB@example.com"}
    ).json()
    assert len(box["items"]) == 1 and box["items"][0]["text"] == "Hello <Bob & Co>"
    assert box["items"][0]["sender"] == "Axentra <no-reply@localhost>" or "@" in box["items"][0]["sender"]
    assert world.ax.notify.dispatcher().run_once(10).claimed == 0

    stats = world.admin.get(f"/v1/products/{pid}/notify/stats").json()
    assert stats["total"]["sent"] == 2 and stats["last_24h"]["sent"] == 2 and stats["provider"] == "local"
    lst = world.admin.get(f"/v1/products/{pid}/notify/messages", params={"status": "sent", "limit": 1}).json()
    assert len(lst["items"]) == 1 and lst["next_cursor"] and lst["items"][0]["content"] is None
    nxt = world.admin.get(
        f"/v1/products/{pid}/notify/messages", params={"status": "sent", "cursor": lst["next_cursor"]}
    )
    assert len(nxt.json()["items"]) == 1
    # Rendered content is encrypted at rest.
    with world.ax.db.transaction(DbScope.platform()) as tx:
        row = tx.one("SELECT subject_enc FROM axentra_notify_messages WHERE id = %s", (msg["id"],))
    assert row["subject_enc"].startswith("axs1.") and "Bob" not in row["subject_enc"]


def test_preferences_suppress_except_locked_categories(world):
    pid = _product(world)
    tid = _tenant(world, pid)
    _template(world, pid, "news", category="marketing")
    _template(world, pid, "reset", category="security")
    uid = _member(world, pid, tid, "bob@example.com")
    bob = world.login_as("bob@example.com")
    base = f"/v1/products/{pid}/notify/preferences/me"
    p = bob.get(base).json()
    assert p["opted_out"] == [] and p["version"] == 0 and "marketing" in p["available_categories"]
    assert set(p["locked_categories"]) == {"transactional", "security"}
    assert bob.put(base, json={"opted_out": ["security"]}).status_code == 422
    r = bob.put(base, json={"opted_out": ["marketing"]}, headers={"If-Match": "0"})
    assert r.status_code == 200 and r.json()["version"] == 1
    assert bob.put(base, json={"opted_out": []}, headers={"If-Match": "0"}).status_code == 412

    m = _send(world.admin, pid, tid, {"user_id": uid}, key="news").json()
    assert m["status"] == "suppressed" and m["content_state"] == "none"
    # By email too (the address belongs to the user).
    assert (
        _send(world.admin, pid, tid, {"email": "bob@example.com"}, key="news").json()["status"]
        == "suppressed"
    )
    assert _send(world.admin, pid, tid, {"user_id": uid}, key="reset").json()["status"] == "queued"
    assert (
        _send(world.admin, pid, tid, {"email": "else@example.com"}, key="news").json()["status"] == "queued"
    )
    assert world.ax.notify.dispatcher().run_once(10).sent == 2

    # Tenant-level preferences apply only in that tenant.
    bob.put(base, json={"opted_out": []})
    tid2 = _tenant(world, pid, "beta")
    world.admin.post(
        f"/v1/products/{pid}/tenants/{tid2}/members", json={"email": "bob@example.com", "role": "member"}
    )
    r = bob.put(base, params={"tenant_id": tid}, json={"opted_out": ["marketing"]})
    assert r.status_code == 200 and r.json()["tenant_id"] == tid
    assert _send(world.admin, pid, tid, {"user_id": uid}, key="news").json()["status"] == "suppressed"
    assert _send(world.admin, pid, tid2, {"user_id": uid}, key="news").json()["status"] == "queued"
    # Viewers lack notify:preferences in the tenant; unrelated users get 404.
    _member(world, pid, tid, "viewer@example.com", role="viewer")
    viewer = world.login_as("viewer@example.com")
    assert viewer.get(base, params={"tenant_id": tid}).status_code == 403
    assert viewer.get(base).status_code == 200
    world.user("nobody@example.com")
    assert world.login_as("nobody@example.com").get(base).status_code == 404


# -- dispatcher -----------------------------------------------------------------------------------


def test_dispatcher_retries_with_backoff_then_fails(ax_factory):
    ax = ax_factory(notify={"max_attempts": 3, "backoff_base_seconds": 60, "backoff_max_seconds": 600})
    app = create_app(axentra=ax, start=False)
    world = World(ax=ax, app=app, admin=bootstrap_admin(ax, app))
    pid = _product(world)
    tid = _tenant(world, pid)
    _template(world, pid)
    mid = _send(world.admin, pid, tid, {"email": "bob@example.com"}).json()["id"]
    fake = FakeProvider(fail_times=100)
    ax.notify.set_provider(fake)
    d = ax.notify.dispatcher(jitter=0)
    assert d.backoff_seconds(1) == 60 and d.backoff_seconds(2) == 120 and d.backoff_seconds(10) == 600

    def due_now() -> None:
        with ax.db.transaction(DbScope.platform()) as tx:
            tx.execute("UPDATE axentra_notify_messages SET next_attempt_at = now() WHERE id = %s", (mid,))

    res = d.run_once()
    assert (res.claimed, res.retried) == (1, 1)
    m = world.admin.get(f"/v1/products/{pid}/notify/messages/{mid}").json()
    assert m["status"] == "queued" and m["attempts"] == 1
    assert "[redacted]" in m["last_error"] and "axinv_" not in m["last_error"]
    with ax.db.transaction(DbScope.platform()) as tx:
        delay = tx.scalar(
            "SELECT extract(epoch FROM next_attempt_at - now()) FROM axentra_notify_messages WHERE id = %s",
            (mid,),
        )
    assert 50 < float(delay) <= 60
    assert d.run_once().claimed == 0  # not due yet
    due_now()
    assert d.run_once().retried == 1
    due_now()
    res = d.run_once()
    assert res.failed == 1
    m = world.admin.get(f"/v1/products/{pid}/notify/messages/{mid}").json()
    assert m["status"] == "failed" and m["attempts"] == 3 and m["next_attempt_at"] is None
    # Manual retry re-queues; this time delivery works.
    fake.fail_times = 0
    r = world.admin.post(f"/v1/products/{pid}/notify/messages/{mid}/retry")
    assert r.status_code == 200 and r.json()["status"] == "queued" and r.json()["attempts"] == 0
    assert world.admin.post(f"/v1/products/{pid}/notify/messages/{mid}/retry").status_code == 409
    assert d.run_once().sent == 1
    assert len(fake.sent) == 1 and fake.sent[0].subject == "Hi <Bob & Co>"
    # Permanent failures are not retried.
    mid2 = _send(world.admin, pid, tid, {"email": "carl@example.com"}).json()["id"]
    ax.notify.set_provider(FakeProvider(fail_times=1, permanent=True))
    assert ax.notify.dispatcher().run_once().failed == 1
    assert world.admin.get(f"/v1/products/{pid}/notify/messages/{mid2}").json()["attempts"] == 1
    m = world.admin.get(f"/v1/products/{pid}/notify/stats").json()
    assert m["total"]["failed"] == 1 and m["total"]["sent"] == 1
    metrics = ax.metrics.render()
    assert 'axentra_notify_deliveries_total{outcome="retried",provider="fake"}' not in metrics  # label order
    assert 'axentra_notify_deliveries_total{provider="fake",outcome="retried"} 2' in metrics


def test_expired_lease_is_reclaimed_and_exhausted_lease_fails(world):
    pid = _product(world)
    tid = _tenant(world, pid)
    _template(world, pid)
    mid = _send(world.admin, pid, tid, {"email": "bob@example.com"}).json()["id"]
    with world.ax.db.transaction(DbScope.platform()) as tx:  # a dispatcher died mid-send
        tx.execute(
            "UPDATE axentra_notify_messages SET status = 'sending', attempts = 1, claim_token = 'dead',"
            " lease_until = now() - interval '1 second' WHERE id = %s",
            (mid,),
        )
    fake = FakeProvider()
    world.ax.notify.set_provider(fake)
    assert world.ax.notify.dispatcher().run_once().sent == 1
    assert world.admin.get(f"/v1/products/{pid}/notify/messages/{mid}").json()["attempts"] == 2
    with world.ax.db.transaction(DbScope.platform()) as tx:
        tx.execute(
            "UPDATE axentra_notify_messages SET status = 'sending', attempts = max_attempts,"
            " lease_until = now() - interval '1 second' WHERE id = %s",
            (mid,),
        )
    assert world.ax.notify.dispatcher().run_once().failed == 1
    assert world.admin.get(f"/v1/products/{pid}/notify/messages/{mid}").json()["status"] == "failed"
    assert len(fake.sent) == 1


def test_concurrent_dispatchers_never_double_send(world):
    pid = _product(world)
    tid = _tenant(world, pid)
    _template(world, pid)
    ids = {
        _send(world.admin, pid, tid, {"email": f"u{i}@example.com"}, idem=f"bulk-{i}").json()["id"]
        for i in range(30)
    }
    fake = FakeProvider(delay=0.01)
    world.ax.notify.set_provider(fake)
    errors: list[BaseException] = []

    def worker() -> None:
        d = world.ax.notify.dispatcher()
        try:
            for _ in range(50):
                if d.run_once(3).claimed == 0:
                    break
        except BaseException as exc:
            errors.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(5)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(60)
    assert not errors
    sent_ids = [m.message_id for m in fake.sent]
    assert len(sent_ids) == len(set(sent_ids)) == 30
    assert set(sent_ids) == ids


# -- invitation hook ------------------------------------------------------------------------------


def test_invitation_hook_enqueues_sensitive_message(world, caplog):
    pid = _product(
        world, settings={"invitation_accept_url": "https://app.example.com/join", "default_locale": "de"}
    )
    tid = _tenant(world, pid)
    caplog.set_level(logging.DEBUG)
    r = world.admin.post(f"/v1/products/{pid}/tenants/{tid}/invitations", json={"email": "dave@example.com"})
    assert r.status_code == 201, r.text
    token = r.json()["token"]
    assert r.json()["accept_url"] == f"https://app.example.com/join?token={token}"
    msgs = world.admin.get(
        f"/v1/products/{pid}/notify/messages", params={"template_key": "invitation"}
    ).json()
    (m,) = msgs["items"]
    assert m["recipient"] == "dave@example.com" and m["locale"] == "de" and m["tenant_id"] == tid
    assert (
        m["content_state"] == "redacted"
        and m["subject"] is None
        and m["idempotency_key"].startswith("invitation:")
    )
    full = world.admin.get(f"/v1/products/{pid}/notify/messages/{m['id']}").json()
    assert full["content"] is None and token not in str(full)
    assert world.ax.notify.dispatcher().run_once().sent == 1
    box = world.admin.get(f"/v1/products/{pid}/notify/mailbox").json()["items"]
    assert token in box[0]["text"] and "eingeladen" in box[0]["subject"]
    assert f'href="https://app.example.com/join?token={token}"' in box[0]["html"]
    with world.ax.db.transaction(DbScope.platform()) as tx:
        row = tx.one(
            "SELECT subject_enc, body_text_enc, content_purged_at FROM axentra_notify_messages WHERE id = %s",
            (m["id"],),
        )
    assert row["subject_enc"] is None and row["body_text_enc"] is None and row["content_purged_at"]
    assert (
        world.admin.get(f"/v1/products/{pid}/notify/messages/{m['id']}").json()["content_state"] == "purged"
    )
    assert token not in caplog.text


def test_invitation_default_accept_url_and_user_locale(world):
    pid = _product(world)
    tid = _tenant(world, pid)
    url = world.ax.notify.invitation_accept_url({}, "axinv_abc/+")
    assert url == "http://127.0.0.1:8080/accept-invitation?token=axinv_abc%2F%2B"
    assert (
        world.ax.notify.invitation_accept_url({"invitation_accept_url": "https://x.test/a?b=1"}, "t")
        == "https://x.test/a?b=1&token=t"
    )
    assert world.ax.notify.invitation_accept_url(
        {"invitation_accept_url": "javascript:alert(1)"}, "t"
    ).startswith("http://127.0.0.1")
    r = world.admin.post(f"/v1/products/{pid}/tenants/{tid}/invitations", json={"email": "erin@example.com"})
    assert r.json()["accept_url"].startswith("http://127.0.0.1:8080/accept-invitation?token=axinv_")
    (m,) = world.admin.get(f"/v1/products/{pid}/notify/messages").json()["items"]
    assert m["locale"] == "en"


# -- isolation & permissions ------------------------------------------------------------------------


def test_isolation_and_permissions(world):
    pid = _product(world)
    tid_a = _tenant(world, pid, "alpha")
    tid_b = _tenant(world, pid, "beta")
    other = _product(world, "erp")
    _template(world, pid)
    _member(world, pid, tid_a, "alice@example.com")
    _member(world, pid, tid_b, "bert@example.com")
    _member(world, pid, tid_a, "viewer@example.com", role="viewer")
    alice = world.login_as("alice@example.com")
    bert = world.login_as("bert@example.com")
    viewer = world.login_as("viewer@example.com")
    mid = _send(alice, pid, tid_a, {"email": "x@example.com"}).json()["id"]

    # Tenant senders see their tenant's messages only.
    assert alice.get(f"/v1/products/{pid}/notify/messages/{mid}").status_code == 200
    assert (
        len(alice.get(f"/v1/products/{pid}/notify/messages", params={"tenant_id": tid_a}).json()["items"])
        == 1
    )
    assert bert.get(f"/v1/products/{pid}/notify/messages/{mid}").status_code == 404
    assert bert.post(f"/v1/products/{pid}/notify/messages/{mid}/retry").status_code == 404
    assert bert.get(f"/v1/products/{pid}/notify/messages", params={"tenant_id": tid_a}).status_code == 404
    assert (
        alice.get(f"/v1/products/{pid}/notify/messages").status_code == 403
    )  # product-wide needs notify:manage
    assert alice.get(f"/v1/products/{pid}/notify/templates").status_code == 403
    assert alice.get(f"/v1/products/{pid}/notify/stats").status_code == 403
    assert alice.get(f"/v1/products/{pid}/notify/mailbox").status_code == 403
    assert _send(alice, pid, tid_b, {"email": "x@example.com"}).status_code == 404
    assert _send(viewer, pid, tid_a, {"email": "x@example.com"}).status_code == 403
    # Another product: the message does not exist there, templates are not shared.
    assert world.admin.get(f"/v1/products/{other}/notify/messages/{mid}").status_code == 404
    assert world.admin.get(f"/v1/products/{other}/notify/templates/welcome").status_code == 404
    tid_o = _tenant(world, other, "omega")
    assert _send(world.admin, other, tid_o, {"email": "x@example.com"}).status_code == 404
    # Same idempotency key in another product is independent.
    _template(world, other)
    assert _send(world.admin, other, tid_o, {"email": "x@example.com"}, idem="same").status_code == 202
    assert _send(world.admin, pid, tid_a, {"email": "x@example.com"}, idem="same").status_code == 202
    # Unauthenticated.
    assert world.browser().get(f"/v1/products/{pid}/notify/messages").status_code == 401

    # API keys: tenant-bound key with notify:send only.
    r = world.admin.post(
        f"/v1/products/{pid}/api-keys", json={"name": "k", "permissions": ["notify:send"], "tenant_id": tid_a}
    )
    key = r.json()["secret"]
    c = world.browser().client
    h = {"Authorization": f"Bearer {key}"}
    assert (
        c.post(
            f"/v1/products/{pid}/tenants/{tid_a}/notify/send",
            headers=h,
            json={"template_key": "welcome", "to": {"email": "k@example.com"}, "variables": {"name": "K"}},
        ).status_code
        == 202
    )
    assert (
        c.post(
            f"/v1/products/{pid}/tenants/{tid_b}/notify/send",
            headers=h,
            json={"template_key": "welcome", "to": {"email": "k@example.com"}, "variables": {"name": "K"}},
        ).status_code
        == 404
    )
    assert c.get(f"/v1/products/{pid}/notify/messages/{mid}", headers=h).status_code == 200
    assert c.get(f"/v1/products/{pid}/notify/preferences/me", headers=h).status_code == 403

    # RLS: a tenant-scoped transaction cannot see other tenants' messages even without filters.
    with world.ax.db.transaction(DbScope.tenant(pid, tid_b), read_only=True) as tx:
        assert tx.scalar("SELECT count(*) FROM axentra_notify_messages") == 0
    with world.ax.db.transaction(DbScope.product(other), read_only=True) as tx:
        assert tx.scalar("SELECT count(*) FROM axentra_notify_messages WHERE product_id = %s", (pid,)) == 0


def test_mailbox_requires_local_provider(ax_factory):
    ax = ax_factory(notify={"provider": "smtp", "smtp_host": "127.0.0.1"})
    app = create_app(axentra=ax, start=False)
    world = World(ax=ax, app=app, admin=bootstrap_admin(ax, app))
    pid = _product(world)
    assert world.admin.get(f"/v1/products/{pid}/notify/mailbox").status_code == 409


def test_notify_module_can_be_disabled(ax_factory):
    from axentra.config.settings import MODULES

    ax = ax_factory(modules=[m for m in MODULES if m != "notify"])
    app = create_app(axentra=ax, start=False)
    world = World(ax=ax, app=app, admin=bootstrap_admin(ax, app))
    assert ax.notify is None and not hasattr(ax, "on_invitation")
    pid = _product(world)
    tid = _tenant(world, pid)
    assert world.admin.get(f"/v1/products/{pid}/notify/templates").status_code == 404
    r = world.admin.post(f"/v1/products/{pid}/tenants/{tid}/invitations", json={"email": "z@example.com"})
    assert r.status_code == 201 and r.json()["accept_url"] is None


def test_retention_purge(world):
    from axentra.observability.maintenance import run_maintenance

    pid = _product(world)
    tid = _tenant(world, pid)
    _template(world, pid)
    old = _send(world.admin, pid, tid, {"email": "a@example.com"}).json()["id"]
    older = _send(world.admin, pid, tid, {"email": "b@example.com"}).json()["id"]
    fresh = _send(world.admin, pid, tid, {"email": "c@example.com"}).json()["id"]
    queued = _send(world.admin, pid, tid, {"email": "d@example.com"}).json()["id"]
    world.ax.notify.dispatcher().run_once(3)
    with world.ax.db.transaction(DbScope.platform()) as tx:
        tx.execute(
            "UPDATE axentra_notify_messages SET created_at = now() - interval '40 days' WHERE id IN (%s, %s)",
            (old, queued),
        )
        tx.execute(
            "UPDATE axentra_notify_messages SET created_at = now() - interval '400 days' WHERE id = %s",
            (older,),
        )
        tx.execute("UPDATE axentra_notify_mailbox SET created_at = now() - interval '40 days'")
    report = run_maintenance(world.ax)
    assert report["notify"] == {"content_erased": 2, "messages_deleted": 1, "mailbox_deleted": 3}
    assert "audit_events_deleted" in report and "sessions_deleted" in report and "errors" not in report
    assert world.admin.get(f"/v1/products/{pid}/notify/messages/{old}").json()["content_state"] == "purged"
    assert world.admin.get(f"/v1/products/{pid}/notify/messages/{older}").status_code == 404
    assert (
        world.admin.get(f"/v1/products/{pid}/notify/messages/{fresh}").json()["content_state"] == "available"
    )
    assert (
        world.admin.get(f"/v1/products/{pid}/notify/messages/{queued}").json()["content_state"] == "available"
    )


def test_cli_notify_dispatch_and_maintenance_purge(pg_urls, ax_factory, tmp_path, capsys):
    import json

    from axentra.cli import main
    from axentra.config.secrets import generate_key

    keys = f"c1:{generate_key()}"
    ax = ax_factory(security={"master_keys": keys})
    app = create_app(axentra=ax, start=False)
    world = World(ax=ax, app=app, admin=bootstrap_admin(ax, app))
    pid = _product(world)
    tid = _tenant(world, pid)
    _template(world, pid)
    _send(world.admin, pid, tid, {"email": "cli@example.com"})
    cfg = tmp_path / "axentra.toml"
    cfg.write_text(
        f'environment = "test"\nmode = "multi"\n[database]\nurl = "{pg_urls["app"]}"\n'
        f'[security]\nmaster_keys = "{keys}"\n[observability]\nlog_format = "text"\n',
        encoding="utf-8",
    )
    capsys.readouterr()
    assert main(["--config", str(cfg), "notify-dispatch", "--once", "--batch", "5"]) == 0
    out = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    assert out["claimed"] == 1 and out["sent"] == 1
    assert main(["--config", str(cfg), "maintenance", "purge"]) == 0
    report = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    assert set(report) >= {"audit_events_deleted", "sessions_deleted", "notify"}
