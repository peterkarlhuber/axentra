"""Unit tests with httpx.MockTransport: no server, no network."""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from decimal import Decimal
import io
import json
from pathlib import Path
import subprocess
import sys
from typing import Any

import httpx
import pytest

from axentra_client import (
    API_VERSION,
    CLIENT_HEADER,
    AsyncAxentraClient,
    AxentraApiError,
    AxentraClient,
    IncompatibleApiError,
    __version__,
    assert_compatible,
)
from axentra_client.models import Record, Tenant

SDK_ROOT = Path(__file__).resolve().parents[2]
REPO_ROOT = SDK_ROOT.parents[1]
NOW = "2026-11-01T12:00:00Z"

Handler = Callable[[httpx.Request], httpx.Response]


class Recorder:
    def __init__(self, handler: Handler) -> None:
        self.handler = handler
        self.requests: list[httpx.Request] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        request.read()
        self.requests.append(request)
        return self.handler(request)

    @property
    def last(self) -> httpx.Request:
        return self.requests[-1]


def client(handler: Handler, **kw: Any) -> tuple[AxentraClient, Recorder]:
    rec = Recorder(handler)
    return AxentraClient("http://api.test/", transport=httpx.MockTransport(rec), **kw), rec


def aclient(handler: Handler, **kw: Any) -> tuple[AsyncAxentraClient, Recorder]:
    rec = Recorder(handler)
    return AsyncAxentraClient("http://api.test", transport=httpx.MockTransport(rec), **kw), rec


def problem(status: int, code: str, **extra: Any) -> httpx.Response:
    body = {
        "type": f"urn:axentra:problem:{code}",
        "title": code,
        "status": status,
        "code": code,
        "detail": f"detail {code}",
        "request_id": "req_1",
        **extra,
    }
    return httpx.Response(status, json=body, headers={"content-type": "application/problem+json"})


def tenant(tid: str, **extra: Any) -> dict[str, Any]:
    return {
        "id": tid,
        "product_id": "prd_1",
        "slug": tid,
        "name": tid,
        "status": "active",
        "settings": {},
        "version": 1,
        "created_at": NOW,
        "updated_at": NOW,
        **extra,
    }


def record(rid: str, version: int = 1) -> dict[str, Any]:
    return {
        "id": rid,
        "product_id": "prd_1",
        "tenant_id": "ten_1",
        "collection": "notes",
        "data": {"a": 1},
        "version": version,
        "created_by": None,
        "updated_by": None,
        "created_at": NOW,
        "updated_at": NOW,
    }


def user() -> dict[str, Any]:
    return {
        "id": "usr_1",
        "email": "a@example.com",
        "name": "A",
        "locale": "en",
        "status": "active",
        "created_at": NOW,
        "updated_at": NOW,
    }


def meta(major: Any = API_VERSION[0], minor: Any = API_VERSION[1]) -> dict[str, Any]:
    return {
        "name": "axentra",
        "version": "0.1.0",
        "api_version": {"major": major, "minor": minor},
        "mode": "multi",
        "environment": "test",
        "modules": ["identity"],
        "product": None,
        "auth": {"password": True, "oidc": []},
        "setup_required": False,
    }


# -- packaging -----------------------------------------------------------------------------------


def test_sync_client_is_generated_from_the_async_source() -> None:
    out = subprocess.run(
        [sys.executable, str(SDK_ROOT / "scripts/unasync.py"), "--check"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert out.returncode == 0, out.stderr


def test_the_client_never_imports_the_server_package() -> None:
    code = "import sys, axentra_client; print(any(m == 'axentra' or m.startswith('axentra.') for m in sys.modules))"
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, check=True)
    assert out.stdout.strip() == "False"
    for path in (SDK_ROOT / "src").rglob("*.py"):
        text = path.read_text(encoding="utf-8")
        assert (
            "import axentra\n" not in text and "from axentra." not in text and "from axentra " not in text
        ), path


def test_api_version_matches_the_committed_contract() -> None:
    spec_path = REPO_ROOT / "openapi/axentra-v1.json"
    if not spec_path.exists():
        pytest.skip("not running inside the Axentra repository")
    spec = json.loads(spec_path.read_text(encoding="utf-8"))
    assert f"{API_VERSION[0]}.{API_VERSION[1]}" == spec["info"]["version"]


def test_every_client_path_exists_in_the_contract() -> None:
    """The literal path segments used by the client must be documented operations."""
    spec_path = REPO_ROOT / "openapi/axentra-v1.json"
    if not spec_path.exists():
        pytest.skip("not running inside the Axentra repository")
    spec = json.loads(spec_path.read_text(encoding="utf-8"))
    seen: list[tuple[str, str]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append((request.method, request.url.path))
        return httpx.Response(599)

    ax, _ = client(handler, api_key="axk_a_b")
    calls: list[Callable[[], Any]] = [
        lambda: ax.meta(),
        lambda: ax.me.get(),
        lambda: ax.me.update(name="x"),
        lambda: ax.auth.session(),
        lambda: ax.auth.sessions(),
        lambda: ax.auth.logout(),
        lambda: ax.auth.login_password("a", "b"),
        lambda: ax.auth.setup("t", "a", "b"),
        lambda: ax.products.list(),
        lambda: ax.products.get("P"),
        lambda: ax.products.create("s", "n"),
        lambda: ax.products.update("P", name="n"),
        lambda: ax.tenants.list("P"),
        lambda: ax.tenants.get("P", "T"),
        lambda: ax.tenants.create("P", "s", "n"),
        lambda: ax.tenants.update("P", "T", name="n"),
        lambda: ax.tenants.delete("P", "T"),
        lambda: ax.operators.list("P"),
        lambda: ax.operators.add("P", "r", email="e"),
        lambda: ax.operators.change("P", "U", "r"),
        lambda: ax.operators.remove("P", "U"),
        lambda: ax.members.list("P", "T"),
        lambda: ax.members.add("P", "T", "r", email="e"),
        lambda: ax.members.change("P", "T", "U", "r"),
        lambda: ax.members.remove("P", "T", "U"),
        lambda: ax.invitations.list("P", "T"),
        lambda: ax.invitations.create("P", "T", "e"),
        lambda: ax.invitations.revoke("P", "T", "I"),
        lambda: ax.invitations.accept("tok"),
        lambda: ax.roles.list("P"),
        lambda: ax.roles.create("P", "k", "n", "tenant", []),
        lambda: ax.roles.update("P", "R", name="n"),
        lambda: ax.roles.delete("P", "R"),
        lambda: ax.api_keys.list("P"),
        lambda: ax.api_keys.get("P", "K"),
        lambda: ax.api_keys.create("P", "n", []),
        lambda: ax.api_keys.revoke("P", "K"),
        lambda: ax.api_keys.rotate("P", "K"),
        lambda: ax.records.list("P", "T", "c"),
        lambda: ax.records.get("P", "T", "c", "R"),
        lambda: ax.records.create("P", "T", "c", {}),
        lambda: ax.records.replace("P", "T", "c", "R", {}),
        lambda: ax.records.delete("P", "T", "c", "R"),
        lambda: ax.files.upload("P", "T", b"x"),
        lambda: ax.files.get("P", "T", "F"),
        lambda: ax.files.list("P", "T"),
        lambda: ax.files.update("P", "T", "F", name="n"),
        lambda: ax.files.delete("P", "T", "F"),
        lambda: ax.files.download("P", "T", "F"),
        lambda: ax.files.download_url("P", "T", "F"),
        lambda: ax.usage.record("P", "T", "m", 1),
        lambda: ax.usage.events("P", "T"),
        lambda: ax.usage.summary("P", "T"),
        lambda: ax.usage.quotas("P", "T"),
        lambda: ax.usage.set_quota("P", "T", "m", 1),
        lambda: ax.usage.delete_quota("P", "T", "m"),
        lambda: ax.usage.meters("P"),
        lambda: ax.usage.create_meter("P", "k"),
        lambda: ax.billing.plans("P"),
        lambda: ax.billing.tenant_plans("P", "T"),
        lambda: ax.billing.create_plan("P", "k", "n"),
        lambda: ax.billing.subscriptions("P"),
        lambda: ax.billing.subscription("P", "T"),
        lambda: ax.billing.subscribe("P", "T", "p"),
        lambda: ax.billing.change_plan("P", "T", "p"),
        lambda: ax.billing.cancel("P", "T"),
        lambda: ax.billing.resume("P", "T"),
        lambda: ax.billing.entitlements("P", "T"),
        lambda: ax.notify.send("P", "T", "k", to_email="e"),
        lambda: ax.notify.messages("P"),
        lambda: ax.notify.message("P", "M"),
        lambda: ax.audit.list(),
        lambda: ax.audit.get("A"),
        lambda: ax.events.publish("P", "T", "x.y"),
        lambda: ax.events.list("P"),
        lambda: ax.events.get("P", "E"),
        lambda: ax.jobs.enqueue("P", "k"),
        lambda: ax.jobs.list("P"),
        lambda: ax.jobs.get("P", "J"),
        lambda: ax.jobs.retry("P", "J"),
        lambda: ax.jobs.cancel("P", "J"),
        lambda: ax.jobs.stats("P"),
        lambda: ax.jobs.kinds("P"),
        lambda: ax.schedules.create("P", "n", "k", interval_seconds=60),
        lambda: ax.schedules.list("P"),
        lambda: ax.schedules.get("P", "S"),
        lambda: ax.schedules.update("P", "S", name="n"),
        lambda: ax.schedules.delete("P", "S"),
        lambda: ax.webhooks.create("P", "https://h", ["*"]),
        lambda: ax.webhooks.list("P"),
        lambda: ax.webhooks.get("P", "W"),
        lambda: ax.webhooks.update("P", "W", enabled=False),
        lambda: ax.webhooks.delete("P", "W"),
        lambda: ax.webhooks.rotate_secret("P", "W"),
        lambda: ax.webhooks.test("P", "W"),
        lambda: ax.webhooks.deliveries("P", "W"),
        lambda: ax.webhooks.delivery("P", "W", "D"),
        lambda: ax.webhooks.redeliver("P", "W", "D"),
        lambda: ax.search.query("P", "T", "q"),
        lambda: ax.search.index("P", "T", "k", "R", title="t"),
        lambda: ax.search.document("P", "T", "k", "R"),
        lambda: ax.search.remove("P", "T", "k", "R"),
        lambda: ax.search.kinds("P", "T"),
    ]
    for call in calls:
        with pytest.raises(AxentraApiError):
            call()
    templates = {(m.upper(), p) for p, ops in spec["paths"].items() for m in ops}

    def matches(method: str, path: str) -> bool:
        parts = path.strip("/").split("/")
        for m, tpl in templates:
            tparts = tpl.strip("/").split("/")
            if (
                m == method
                and len(tparts) == len(parts)
                and all(t.startswith("{") or t == p for t, p in zip(tparts, parts, strict=True))
            ):
                return True
        return False

    missing = [(m, p) for m, p in seen if not matches(m, p)]
    assert not missing, missing
    assert len(seen) == len(calls)


# -- authentication ------------------------------------------------------------------------------


def test_api_key_is_sent_as_bearer_with_client_header() -> None:
    ax, rec = client(lambda r: httpx.Response(200, json=tenant("ten_1")), api_key="axk_k_s")
    t = ax.tenants.get("prd_1", "ten_1")
    assert isinstance(t, Tenant) and t.id == "ten_1"
    assert rec.last.url == "http://api.test/v1/products/prd_1/tenants/ten_1"
    assert rec.last.headers["authorization"] == "Bearer axk_k_s"
    assert rec.last.headers["axentra-client"] == CLIENT_HEADER
    assert f"axentra-client-python/{__version__}; api={API_VERSION[0]}.{API_VERSION[1]}" == CLIENT_HEADER
    assert "x-axentra-csrf" not in rec.last.headers


def test_ids_are_percent_encoded() -> None:
    ax, rec = client(lambda r: httpx.Response(200, json=tenant("x")), api_key="axk_k_s")
    ax.tenants.get("prd_1", "../admin")
    assert rec.last.url.raw_path == b"/v1/products/prd_1/tenants/..%2Fadmin"


def test_password_login_uses_the_session_cookie_as_bearer_and_logout_forgets_it() -> None:
    session = {
        "user": user(),
        "session_id": "ses_1",
        "csrf_token": "c",
        "expires_at": NOW,
        "platform_role": None,
    }

    def handler(r: httpx.Request) -> httpx.Response:
        if r.url.path == "/v1/auth/login/password":
            return httpx.Response(
                200,
                json=session,
                headers={"set-cookie": "axentra-session=tok_secret; HttpOnly; Path=/; SameSite=lax"},
            )
        if r.url.path == "/v1/auth/logout":
            return httpx.Response(204)
        return httpx.Response(200, json={"actor_kind": "user", "user": user()})

    ax, rec = client(handler)
    info = ax.auth.login_password("a@example.com", "pw")
    assert info.session_id == "ses_1"
    assert json.loads(rec.last.content) == {"email": "a@example.com", "password": "pw"}
    assert ax.token == "tok_secret"
    me = ax.me.get()
    assert me.user is not None and me.user.email == "a@example.com"
    assert rec.last.headers["authorization"] == "Bearer tok_secret"
    assert "cookie" not in rec.last.headers  # the bearer is used, never the cookie jar
    ax.auth.logout()
    assert ax.token is None


def test_secure_cookie_name_is_recognized() -> None:
    session = {"user": user(), "session_id": "s", "csrf_token": "c", "expires_at": NOW, "platform_role": None}
    ax, _ = client(
        lambda r: httpx.Response(
            200, json=session, headers={"set-cookie": "__Host-axentra-session=tok2; Secure; HttpOnly; Path=/"}
        )
    )
    ax.auth.login_password("a", "b")
    assert ax.token == "tok2"


def test_login_without_cookie_is_an_error() -> None:
    ax, _ = client(lambda r: httpx.Response(200, json={}))
    with pytest.raises(RuntimeError):
        ax.auth.login_password("a", "b")


def test_api_key_and_session_token_are_exclusive() -> None:
    with pytest.raises(ValueError):
        AxentraClient("http://x", api_key="a", session_token="b")


# -- errors --------------------------------------------------------------------------------------


def test_problem_details_become_axentra_api_error() -> None:
    ax, _ = client(
        lambda r: problem(422, "validation_failed", errors=[{"loc": ["body", "slug"], "msg": "bad"}])
    )
    with pytest.raises(AxentraApiError) as ei:
        ax.tenants.create("prd_1", "BAD", "x")
    e = ei.value
    assert (e.status, e.code, e.detail, e.request_id) == (
        422,
        "validation_failed",
        "detail validation_failed",
        "req_1",
    )
    assert e.errors == [{"loc": ["body", "slug"], "msg": "bad"}]
    assert "422 validation_failed" in str(e)


def test_non_problem_errors_fall_back_to_status_and_header() -> None:
    ax, _ = client(lambda r: httpx.Response(502, text="bad gateway", headers={"x-request-id": "req_h"}))
    with pytest.raises(AxentraApiError) as ei:
        ax.meta()
    assert (ei.value.status, ei.value.code, ei.value.detail, ei.value.request_id) == (
        502,
        "internal",
        "bad gateway",
        "req_h",
    )


def test_rate_limit_exposes_retry_after() -> None:
    def handler(r: httpx.Request) -> httpx.Response:
        resp = problem(429, "quota_exceeded")
        resp.headers["retry-after"] = "60"
        return resp

    ax, _ = client(handler, api_key="k")
    with pytest.raises(AxentraApiError) as ei:
        ax.usage.record("p", "t", "m", 1, idempotency_key="k1")
    assert ei.value.code == "quota_exceeded" and ei.value.retry_after == 60


# -- compatibility -------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("major", "minor", "reason"),
    [
        (API_VERSION[0] + 1, 0, "major_mismatch"),
        (API_VERSION[0], "x", "unparseable"),
    ],
)
def test_incompatible_servers_are_refused(major: Any, minor: Any, reason: str) -> None:
    ax, _ = client(lambda r: httpx.Response(200, json=meta(major, minor)))
    if reason == "unparseable":
        with pytest.raises(Exception) as ei:  # pydantic refuses a non-int minor before the check
            ax.check_compatibility()
        with pytest.raises(IncompatibleApiError):
            assert_compatible({"major": 1, "minor": "x"})
        return
    with pytest.raises(IncompatibleApiError) as ei:
        ax.check_compatibility()
    assert ei.value.reason == reason
    assert "Incompatible Axentra API" in str(ei.value)


def test_compatible_servers_are_accepted() -> None:
    for minor in (API_VERSION[1], API_VERSION[1] + 2):
        body = meta(API_VERSION[0], minor)
        ax, _ = client(lambda r, b=body: httpx.Response(200, json=b))  # type: ignore[misc]
        assert ax.check_compatibility().api_version.minor == minor
    assert assert_compatible({"major": 1, "minor": 5}, required=(1, 2)) == (1, 5)
    with pytest.raises(IncompatibleApiError) as ei:
        assert_compatible({"major": 1, "minor": 1}, required=(1, 2))
    assert ei.value.reason == "minor_too_low"
    with pytest.raises(IncompatibleApiError):
        assert_compatible({"major": True, "minor": 0})


# -- pagination ----------------------------------------------------------------------------------


def _paged(r: httpx.Request) -> httpx.Response:
    pages = {None: (["t1", "t2"], "c2"), "c2": (["t3"], None)}
    items, nxt = pages[r.url.params.get("cursor")]
    return httpx.Response(200, json={"items": [tenant(i) for i in items], "next_cursor": nxt})


def test_iterator_follows_cursors() -> None:
    ax, rec = client(_paged, api_key="k")
    assert [t.id for t in ax.tenants.iter("prd_1", q="x", page_size=2)] == ["t1", "t2", "t3"]
    assert [dict(r.url.params) for r in rec.requests] == [
        {"q": "x", "limit": "2"},
        {"q": "x", "limit": "2", "cursor": "c2"},
    ]
    page = ax.tenants.list("prd_1", limit=2)
    assert page.next_cursor == "c2" and len(page.items) == 2


def test_iterator_refuses_a_repeated_cursor() -> None:
    ax, _ = client(lambda r: httpx.Response(200, json={"items": [], "next_cursor": "same"}), api_key="k")
    with pytest.raises(RuntimeError, match="twice"):
        list(ax.records.iter("p", "t", "c"))


@pytest.mark.anyio
async def test_async_iterator_and_client() -> None:
    ax, rec = aclient(_paged, api_key="k")
    async with ax:
        ids = [t.id async for t in ax.tenants.iter("prd_1")]
    assert ids == ["t1", "t2", "t3"]
    assert rec.last.headers["authorization"] == "Bearer k"


# -- records, usage, notify ----------------------------------------------------------------------


def test_records_send_if_match_and_json_where() -> None:
    def handler(r: httpx.Request) -> httpx.Response:
        if r.method == "GET":
            return httpx.Response(200, json={"items": [record("rec_1")], "next_cursor": None})
        if r.method == "DELETE":
            return httpx.Response(204)
        return httpx.Response(200, json=record("rec_1", 2))

    ax, rec = client(handler, api_key="k")
    out = ax.records.replace("p", "t", "notes", "rec_1", {"a": 2}, version=1)
    assert isinstance(out, Record) and out.version == 2
    assert rec.last.method == "PUT" and rec.last.headers["if-match"] == "1"
    assert json.loads(rec.last.content) == {"a": 2}
    ax.records.list("p", "t", "notes", where={"status": "open"}, sort="-created_at")
    assert (
        rec.last.url.params["where"] == '{"status":"open"}' and rec.last.url.params["sort"] == "-created_at"
    )
    ax.records.delete("p", "t", "notes", "rec_1")
    assert "if-match" not in rec.last.headers


def _usage_result(r: httpx.Request) -> httpx.Response:
    event = {
        "id": "use_1",
        "product_id": "p",
        "tenant_id": "t",
        "meter": "m",
        "quantity": 1.5,
        "idempotency_key": r.headers["idempotency-key"],
        "occurred_at": NOW,
        "period_start": NOW,
        "recorded_at": NOW,
        "properties": {},
        "reservation_id": None,
    }
    quota = {
        "meter": "m",
        "used": 1.5,
        "reserved": 0,
        "limit": None,
        "remaining": None,
        "over_limit": False,
        "enforcement": "soft",
        "source": "none",
        "period_start": NOW,
        "period_end": None,
    }
    return httpx.Response(201, json={"event": event, "quota": quota, "replayed": False})


def test_usage_record_sends_the_idempotency_key() -> None:
    ax, rec = client(_usage_result, api_key="k")
    res = ax.usage.record("p", "t", "m", Decimal("1.5"), idempotency_key="order-1", properties={"a": 1})
    assert rec.last.headers["idempotency-key"] == "order-1"
    assert json.loads(rec.last.content) == {"meter": "m", "quantity": "1.5", "properties": {"a": 1}}
    assert res.event.quantity == Decimal("1.5") and res.replayed is False
    ax.usage.record("p", "t", "m", 1)
    first = rec.last.headers["idempotency-key"]
    ax.usage.record("p", "t", "m", 1)
    assert len(first) == 36 and rec.last.headers["idempotency-key"] != first
    with pytest.raises(ValueError):
        ax.usage.record("p", "t", "m", 1, idempotency_key="x" * 201)


def test_usage_record_batch_sends_every_key_in_the_body() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        one = _usage_result(httpx.Request("POST", "http://x", headers={"Idempotency-Key": "a"})).json()
        return httpx.Response(200, json={"results": [one, {**one, "replayed": True}]})

    ax, rec = client(handler, api_key="k")
    results = ax.usage.record_batch(
        "p",
        "t",
        [
            {"meter": "m", "quantity": Decimal("1.5"), "idempotency_key": "a"},
            {
                "meter": "m",
                "quantity": 2,
                "idempotency_key": "b",
                "occurred_at": datetime(2026, 11, 1, tzinfo=UTC),
            },
        ],
        enforce=True,
    )
    assert rec.last.url.path == "/v1/products/p/tenants/t/usage/events/batch"
    body = json.loads(rec.last.content)
    assert body["enforce"] is True and [e["idempotency_key"] for e in body["entries"]] == ["a", "b"]
    assert body["entries"][0]["quantity"] == "1.5" and body["entries"][1]["occurred_at"].startswith("2026")
    assert "idempotency-key" not in rec.last.headers
    assert [r.replayed for r in results] == [False, True]
    with pytest.raises(ValueError):
        ax.usage.record_batch("p", "t", [{"meter": "m", "quantity": 1}])


def test_notify_send_validates_the_recipient() -> None:
    ax, rec = client(lambda r: httpx.Response(202, json={}), api_key="k")
    with pytest.raises(ValueError):
        ax.notify.send("p", "t", "welcome")
    with pytest.raises(ValueError):
        ax.notify.send("p", "t", "welcome", to_email="a@x", to_user_id="usr_1")
    with pytest.raises(Exception):
        ax.notify.send("p", "t", "welcome", to_email="a@x", idempotency_key="n-1")
    assert json.loads(rec.last.content) == {"template_key": "welcome", "to": {"email": "a@x"}}
    assert rec.last.headers["idempotency-key"] == "n-1"


# -- events, jobs, schedules, webhooks ------------------------------------------------------------


def _job(**extra: Any) -> dict[str, Any]:
    return {
        "id": "job_1",
        "product_id": "p",
        "tenant_id": "t",
        "kind": "report.build",
        "status": "queued",
        "run_after": NOW,
        "max_attempts": 5,
        "created_at": NOW,
        "updated_at": NOW,
        **extra,
    }


def _endpoint() -> dict[str, Any]:
    return {
        "id": "whk_1",
        "product_id": "p",
        "tenant_id": None,
        "url": "https://hooks.example.com/a",
        "description": "",
        "event_types": ["order.*"],
        "enabled": True,
        "version": 2,
        "created_by": "usr_1",
        "created_at": NOW,
        "updated_at": NOW,
    }


def test_jobs_send_the_body_idempotency_key_and_filters() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/kinds"):
            return httpx.Response(200, json={"any_kind": False, "items": [{"kind": "report.build"}]})
        if request.url.path.endswith("/stats"):
            return httpx.Response(
                200,
                json={
                    "counts": {"queued": 1},
                    "failed_last_24h": 0,
                    "succeeded_last_24h": 2,
                    "oldest_queued_at": NOW,
                    "by_kind": [{"kind": "report.build", "queued": 1}],
                },
            )
        if request.method == "GET" and request.url.path.endswith("/jobs"):
            return httpx.Response(200, json={"items": [_job()], "next_cursor": None})
        return httpx.Response(201 if request.method == "POST" else 200, json=_job(status="cancelled"))

    ax, rec = client(handler, api_key="k")
    job = ax.jobs.enqueue("p", "report.build", {"month": 11}, tenant_id="t", idempotency_key="r-11")
    assert rec.last.method == "POST" and rec.last.url.path == "/v1/products/p/jobs"
    assert rec.last.headers["idempotency-key"] == "r-11"
    assert json.loads(rec.last.content) == {
        "kind": "report.build",
        "payload": {"month": 11},
        "tenant_id": "t",
    }
    assert job.status == "cancelled" and job.max_attempts == 5
    page = ax.jobs.list("p", status="queued", kind="report.build")
    assert dict(rec.last.url.params) == {"status": "queued", "kind": "report.build"}
    assert [j.id for j in page.items] == ["job_1"]
    assert [j.id for j in ax.jobs.iter("p", tenant_id="t")] == ["job_1"]
    ax.jobs.cancel("p", "job_1")
    assert rec.last.url.path == "/v1/products/p/jobs/job_1/cancel"
    ax.jobs.retry("p", "job_1")
    assert rec.last.url.path == "/v1/products/p/jobs/job_1/retry"
    kinds = ax.jobs.kinds("p", tenant_id="t")
    assert rec.last.url.params["tenant_id"] == "t"
    assert kinds.any_kind is False and kinds.items[0].enqueue_permission is None
    stats = ax.jobs.stats("p")
    assert stats.by_kind[0].queued == 1 and stats.by_kind[0].dead == 0
    with pytest.raises(ValueError):
        ax.jobs.enqueue("p", "k", idempotency_key="x" * 201)


def test_events_publish_with_idempotency_key_and_type_filter() -> None:
    event = {
        "id": "evt_1",
        "product_id": "p",
        "tenant_id": "t",
        "type": "order.paid",
        "data": {"total": 3},
        "idempotency_key": "o-1",
        "actor_kind": "api_key",
        "actor_id": "key_1",
        "request_id": None,
        "occurred_at": NOW,
    }

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "POST":
            return httpx.Response(201, json=event)
        if request.url.path.endswith("/events"):
            return httpx.Response(200, json={"items": [event], "next_cursor": None})
        return httpx.Response(200, json=event)

    ax, rec = client(handler, api_key="k")
    got = ax.events.publish("p", "t", "order.paid", {"total": 3}, idempotency_key="o-1")
    assert rec.last.url.path == "/v1/products/p/tenants/t/events"
    assert json.loads(rec.last.content) == {"type": "order.paid", "data": {"total": 3}}
    assert rec.last.headers["idempotency-key"] == "o-1" and got.data == {"total": 3}
    ax.events.list("p", type="order.*")
    assert rec.last.url.params["type"] == "order.*"
    assert [e.id for e in ax.events.iter("p", tenant_id="t")] == ["evt_1"]
    assert ax.events.get("p", "evt_1").actor_kind == "api_key"


def test_schedules_need_exactly_one_timing_and_send_if_match() -> None:
    schedule: dict[str, Any] = {
        "id": "sch_1",
        "product_id": "p",
        "tenant_id": None,
        "name": "Nightly",
        "kind": "report.build",
        "payload": {},
        "interval_seconds": None,
        "cron": "0 3 * * *",
        "enabled": True,
        "priority": 0,
        "max_attempts": 5,
        "next_run_at": NOW,
        "last_run_at": None,
        "last_job_id": None,
        "version": 4,
        "created_by": "usr_1",
        "created_at": NOW,
        "updated_at": NOW,
    }
    ax, rec = client(
        lambda r: httpx.Response(204) if r.method == "DELETE" else httpx.Response(200, json=schedule),
        api_key="k",
    )
    with pytest.raises(ValueError):
        ax.schedules.create("p", "Nightly", "report.build")
    with pytest.raises(ValueError):
        ax.schedules.create("p", "Nightly", "report.build", interval_seconds=60, cron="* * * * *")
    created = ax.schedules.create("p", "Nightly", "report.build", cron="0 3 * * *")
    assert json.loads(rec.last.content) == {"name": "Nightly", "kind": "report.build", "cron": "0 3 * * *"}
    assert created.cron == "0 3 * * *" and created.version == 4
    ax.schedules.update("p", "sch_1", enabled=False, version=4)
    assert rec.last.method == "PATCH" and rec.last.headers["if-match"] == "4"
    assert json.loads(rec.last.content) == {"enabled": False}
    ax.schedules.delete("p", "sch_1", version=4)
    assert rec.last.method == "DELETE" and rec.last.headers["if-match"] == "4"


def test_webhooks_return_the_secret_once_and_list_deliveries() -> None:
    delivery = {
        "id": "dlv_1",
        "product_id": "p",
        "tenant_id": None,
        "endpoint_id": "whk_1",
        "event_id": "evt_1",
        "event_type": "order.paid",
        "status": "failed",
        "attempts": 1,
        "response_code": 500,
        "response_body": "oops",
        "duration_ms": 12,
        "last_error": "HTTP 500",
        "next_attempt_at": NOW,
        "job_id": "job_1",
        "created_at": NOW,
        "updated_at": NOW,
        "delivered_at": None,
    }

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if (path.endswith("/webhooks") and request.method == "POST") or path.endswith("/rotate-secret"):
            return httpx.Response(201, json={"endpoint": _endpoint(), "secret": "whsec_x"})
        if path.endswith("/deliveries"):
            return httpx.Response(200, json={"items": [delivery], "next_cursor": None})
        if "/deliveries/" in path or path.endswith("/test"):
            return httpx.Response(202 if path.endswith("/redeliver") else 200, json=delivery)
        if request.method == "DELETE":
            return httpx.Response(204)
        return httpx.Response(200, json=_endpoint())

    ax, rec = client(handler, api_key="k")
    new = ax.webhooks.create("p", "https://hooks.example.com/a", ("order.*",), description="Orders")
    assert json.loads(rec.last.content) == {
        "url": "https://hooks.example.com/a",
        "event_types": ["order.*"],
        "description": "Orders",
    }
    assert new.secret == "whsec_x" and new.endpoint.version == 2
    rotated = ax.webhooks.rotate_secret("p", "whk_1", grace_seconds=3600)
    assert json.loads(rec.last.content) == {"grace_seconds": 3600} and rotated.secret == "whsec_x"
    ax.webhooks.update("p", "whk_1", event_types=["*"], version=2)
    assert json.loads(rec.last.content) == {"event_types": ["*"]} and rec.last.headers["if-match"] == "2"
    ax.webhooks.delete("p", "whk_1")
    assert rec.last.method == "DELETE" and "if-match" not in rec.last.headers
    page = ax.webhooks.deliveries("p", "whk_1", status="failed")
    assert rec.last.url.params["status"] == "failed" and page.items[0].response_code == 500
    assert [d.id for d in ax.webhooks.iter_deliveries("p", "whk_1")] == ["dlv_1"]
    assert ax.webhooks.redeliver("p", "whk_1", "dlv_1").status == "failed"
    assert rec.last.url.path == "/v1/products/p/webhooks/whk_1/deliveries/dlv_1/redeliver"
    assert ax.webhooks.test("p", "whk_1").event_type == "order.paid"


def test_search_sends_repeated_kinds_and_parses_hits() -> None:
    hit = {
        "id": "sdoc_1",
        "kind": "note",
        "ref_id": "rec_1",
        "title": "Q4 plan",
        "metadata": {},
        "rank": 0.6,
        "title_highlight": "<mark>Q4</mark> plan",
        "body_highlight": "",
        "updated_at": NOW,
    }

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/kinds"):
            return httpx.Response(200, json=[{"kind": "note", "count": 3}])
        return httpx.Response(200, json={"items": [hit], "next_cursor": None})

    ax, rec = client(handler, api_key="k")
    page = ax.search.query("p", "t", "q4", kinds=["note", "task"], limit=5)
    assert rec.last.url.path == "/v1/products/p/tenants/t/search"
    assert rec.last.url.params.get_list("kind") == ["note", "task"] and rec.last.url.params["q"] == "q4"
    assert page.items[0].rank == 0.6 and page.items[0].title_highlight.startswith("<mark>")
    assert [h.ref_id for h in ax.search.iter("p", "t", "q4")] == ["rec_1"]
    assert "kind" not in rec.last.url.params and "match" not in rec.last.url.params
    ax.search.query("p", "t", "q", match="prefix")
    assert rec.last.url.params["match"] == "prefix"
    assert ax.search.kinds("p", "t")[0].count == 3


@pytest.mark.anyio
async def test_async_jobs_and_events() -> None:
    ax, rec = aclient(lambda r: httpx.Response(201, json=_job()), api_key="k")
    async with ax:
        job = await ax.jobs.enqueue("p", "report.build", delay_seconds=30)
        assert job.id == "job_1"
        assert json.loads(rec.last.content) == {"kind": "report.build", "delay_seconds": 30}


# -- files ---------------------------------------------------------------------------------------


def _file_info(size: int) -> dict[str, Any]:
    return {
        "id": "fil_1",
        "product_id": "p",
        "tenant_id": "t",
        "name": "a.txt",
        "content_type": "text/plain",
        "size": size,
        "sha256": None,
        "status": "active",
        "metadata": {},
        "version": 1,
        "created_by": None,
        "expires_at": None,
        "created_at": NOW,
        "updated_at": NOW,
    }


def test_upload_is_multipart_and_download_streams(tmp_path: Path) -> None:
    payload = b"0123456789" * 10_000

    def handler(r: httpx.Request) -> httpx.Response:
        if r.method == "POST":
            assert r.headers["content-type"].startswith("multipart/form-data; boundary=")
            assert b'name="file"; filename="a.txt"' in r.content
            assert b'name="metadata"' in r.content and b'{"k": "v"}' in r.content
            return httpx.Response(201, json=_file_info(len(payload)))
        return httpx.Response(200, content=payload, headers={"content-type": "application/octet-stream"})

    ax, _ = client(handler, api_key="k")
    src = tmp_path / "a.txt"
    src.write_bytes(payload)
    assert ax.files.upload("p", "t", src, content_type="text/plain", metadata={"k": "v"}).size == len(payload)
    assert ax.files.upload("p", "t", io.BytesIO(payload), filename="a.txt", metadata={"k": "v"}).id == "fil_1"
    assert ax.files.download("p", "t", "fil_1") == payload
    dest = tmp_path / "out.bin"
    assert ax.files.download_to("p", "t", "fil_1", dest) == len(payload)
    assert dest.read_bytes() == payload
    with ax.files.stream("p", "t", "fil_1") as r:
        assert b"".join(r.iter_bytes()) == payload


def test_download_errors_are_mapped() -> None:
    ax, _ = client(lambda r: problem(404, "not_found"), api_key="k")
    with pytest.raises(AxentraApiError) as ei:
        ax.files.download("p", "t", "fil_x")
    assert ei.value.code == "not_found" and ei.value.request_id == "req_1"


@pytest.mark.anyio
async def test_async_upload_and_download(tmp_path: Path) -> None:
    payload = b"async bytes"
    ax, _ = aclient(
        lambda r: (
            httpx.Response(201, json=_file_info(len(payload)))
            if r.method == "POST"
            else httpx.Response(200, content=payload)
        ),
        api_key="k",
    )
    async with ax:
        assert (await ax.files.upload("p", "t", payload, filename="a.txt")).size == len(payload)
        buf = io.BytesIO()
        assert await ax.files.download_to("p", "t", "fil_1", buf) == len(payload)
        assert buf.getvalue() == payload


# -- models --------------------------------------------------------------------------------------


def test_models_keep_unknown_fields_and_accept_unknown_enum_values() -> None:
    t = Tenant.model_validate(tenant("t1", status="archived_in_v1_9", brand_new_field={"x": 1}))
    assert t.status == "archived_in_v1_9"
    assert t.model_extra == {"brand_new_field": {"x": 1}}


def test_generic_request_escape_hatch() -> None:
    ax, rec = client(lambda r: httpx.Response(200, json={"items": [], "next_cursor": None}), api_key="k")
    assert ax.request_json("GET", "/v1/products/p/jobs", params={"status": "queued", "x": None}) == {
        "items": [],
        "next_cursor": None,
    }
    assert dict(rec.last.url.params) == {"status": "queued"}


def test_password_reset_and_email_verification_calls() -> None:
    ax, rec = client(lambda r: httpx.Response(202 if "confirm" not in r.url.path else 204), session_token="s")
    ax.auth.request_password_reset("a@example.com")
    assert rec.last.url.path == "/v1/auth/password-reset"
    assert json.loads(rec.last.content) == {"email": "a@example.com"}
    ax.auth.request_password_reset("a@example.com", product_id="prd_1")
    assert json.loads(rec.last.content) == {"email": "a@example.com", "product_id": "prd_1"}
    ax.auth.confirm_password_reset("axpwr_t", "new passphrase 1234")
    assert rec.last.url.path == "/v1/auth/password-reset/confirm"
    assert json.loads(rec.last.content) == {"token": "axpwr_t", "new_password": "new passphrase 1234"}
    ax.auth.confirm_email_verification("axemv_t")
    assert json.loads(rec.last.content) == {"token": "axemv_t"}
    ax.me.request_email_verification()
    assert rec.last.url.path == "/v1/me/email-verification" and json.loads(rec.last.content) == {}


def test_invalid_token_problem_is_raised() -> None:
    problem = {
        "type": "about:blank",
        "title": "Invalid or expired link",
        "status": 400,
        "code": "invalid_token",
    }
    ax, _ = client(
        lambda r: httpx.Response(400, json=problem, headers={"content-type": "application/problem+json"})
    )
    with pytest.raises(AxentraApiError) as err:
        ax.auth.confirm_email_verification("axemv_x")
    assert err.value.code == "invalid_token" and err.value.status == 400
