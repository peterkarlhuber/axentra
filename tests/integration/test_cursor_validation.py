"""Malformed pagination cursors are a ``400 invalid_cursor``, never a ``500`` (re-review AX-R1).

Before the fix, ``decode_cursor`` only checked that the cursor was base64 JSON of a list: a list
with the wrong number or types of values, a NUL character, a lone surrogate or a timestamp that
PostgreSQL rejects reached the SQL and failed there with ``500 internal``.
"""

from __future__ import annotations

import base64
import json
from typing import Any

import pytest

from axentra.core.pagination import encode_cursor
from tests.integration.conftest import World
from tests.integration.test_notify import _member, _product, _send, _template, _tenant


def _enc(value: Any) -> str:
    return base64.urlsafe_b64encode(json.dumps(value).encode()).decode().rstrip("=")


def _raw(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


TS = "2026-11-02T10:00:00+00:00"
MALFORMED: dict[str, str] = {
    # Not base64url / not JSON / not a list.
    "not base64": "!!!",
    "standard base64 alphabet": base64.b64encode(b'["2026-11-02T10:00:00+00:00","~~~?"]').decode(),  # has a +
    "too much padding": _enc([TS, "x"]) + "====",
    "not utf-8": _raw(b"\xff\xfe\xfd"),
    "not json": _raw(b"{not json"),
    "json object": _enc({"a": 1}),
    "json string": _enc("x"),
    "deeply nested": _raw(b"[" * 3000),
    "too long": "A" * 5000,
    "NaN": _raw(b'[NaN, "x"]'),
    # Wrong number or types of values.
    "empty list": _enc([]),
    "one value": _enc(["x"]),
    "three values": _enc([TS, "x", "y"]),
    "integers": _enc([1, 2]),
    "nulls": _enc([None, None]),
    "booleans": _enc([True, False]),
    "object as id": _enc([TS, {"a": 1}]),
    "list as id": _enc([TS, ["x"]]),
    "empty id": _enc([TS, ""]),
    # NUL characters and lone surrogates (PostgreSQL text holds neither).
    "NUL in id": _enc([TS, "a\u0000b"]),
    "NUL in timestamp": _enc([TS + "\u0000", "x"]),
    "lone surrogate in id": _enc([TS, "\ud800"]),
    "lone surrogate in timestamp": _enc(["2026-11-02T10:00:00+00:00\udfff", "x"]),
    # Timestamps PostgreSQL (or Python) would reject, or that are not what Axentra issues.
    "not a date": _enc(["not-a-date", "x"]),
    "naive timestamp": _enc(["2026-11-02T10:00:00", "x"]),
    "date only": _enc(["2026-11-02", "x"]),
    "ISO week date": _enc(["2026-W45-1T10:00:00+00:00", "x"]),
    "ordinal date": _enc(["2026-306T10:00:00+00:00", "x"]),
    "basic format": _enc(["20261102T100000+0000", "x"]),
    "space separator": _enc(["2026-11-02 10:00:00+00:00", "x"]),
    "comma fraction": _enc(["2026-11-02T10:00:00,5+00:00", "x"]),
    "seven fraction digits": _enc(["2026-11-02T10:00:00.1234567+00:00", "x"]),
    "offset with seconds": _enc(["2026-11-02T10:00:00+05:30:15", "x"]),
    "offset with microseconds": _enc(["2026-11-02T10:00:00+05:30:15.123456", "x"]),
    "offset out of range": _enc(["2026-11-02T10:00:00+99:00", "x"]),
    "hour 24": _enc(["2026-11-02T24:00:00+00:00", "x"]),
    "month 13": _enc(["2026-13-02T10:00:00+00:00", "x"]),
    "February 30": _enc(["2026-02-30T10:00:00+00:00", "x"]),
    "year 0": _enc(["0000-01-01T00:00:00+00:00", "x"]),
    "before year 1 in UTC": _enc(["0001-01-01T00:00:00+14:00", "x"]),
    "after year 9999 in UTC": _enc(["9999-12-31T23:59:59-14:00", "x"]),
    "full-width digits": _enc(["\uff12\uff10\uff12\uff16-11-02T10:00:00+00:00", "x"]),
}

ENDPOINTS = ("notify/messages", "notify/mailbox", "audit", "tenants")


def _path(pid: str, endpoint: str) -> tuple[str, dict[str, str]]:
    if endpoint == "audit":
        return "/v1/audit", {"product_id": pid}
    return f"/v1/products/{pid}/{endpoint}", {}


def _assert_invalid_cursor(r: Any, cursor: str) -> None:
    assert r.status_code == 400, r.text
    assert r.headers["content-type"].startswith("application/problem+json")
    body = r.json()
    assert body["code"] == "invalid_cursor" and body["detail"] == "invalid cursor", body
    # No decoder or database text and no echo of the cursor.
    text = r.text.lower()
    for leak in ("codec", "utf-8", "surrogate", "json", "base64", "postgres", "timestamp", "nul"):
        assert leak not in text, (leak, r.text)
    assert cursor not in r.text


@pytest.mark.parametrize("endpoint", ENDPOINTS)
def test_malformed_cursors_are_400_on_axentra_list_endpoints(world: World, endpoint: str) -> None:
    pid = _product(world)
    path, params = _path(pid, endpoint)
    assert world.admin.get(path, params=params).status_code == 200
    for name, cursor in MALFORMED.items():
        if endpoint == "tenants" and name == "one value":
            continue  # the tenant list pages by id alone, so ["x"] is a well-formed cursor there
        r = world.admin.get(path, params={**params, "cursor": cursor})
        assert r.status_code != 500, (name, r.text)
        _assert_invalid_cursor(r, cursor)


@pytest.mark.parametrize("endpoint", ENDPOINTS)
def test_well_formed_cursor_from_elsewhere_is_harmless(world: World, endpoint: str) -> None:
    """A cursor of the right shape that Axentra never issued just pages from that position."""
    pid = _product(world)
    path, params = _path(pid, endpoint)
    shape = [None] if endpoint == "tenants" else ["2026-11-02T10:00:00.123456Z", None]
    for last in ("zzz", "ten_é中\U0001f600", "'; DROP TABLE x; --"):
        cursor = _enc([v if v is not None else last for v in shape])
        assert world.admin.get(path, params={**params, "cursor": cursor}).status_code == 200


def test_issued_cursors_still_page_through_every_endpoint(world: World) -> None:
    pid = _product(world)
    tid = _tenant(world, pid)
    for slug in ("b-co", "c-co"):
        _tenant(world, pid, slug)
    _template(world, pid)
    _member(world, pid, tid, "alice@example.com")
    alice = world.login_as("alice@example.com")
    for idem in ("k-1", "k-2"):
        assert _send(alice, pid, tid, {"email": "alice@example.com"}, idem=idem).status_code == 202
    world.ax.notify.dispatcher().run_once(10)
    for endpoint in ENDPOINTS:
        path, params = _path(pid, endpoint)
        seen: list[str] = []
        cursor: str | None = None
        while True:
            r = world.admin.get(path, params={**params, "limit": 1, **({"cursor": cursor} if cursor else {})})
            assert r.status_code == 200, (endpoint, r.text)
            page = r.json()
            seen += [i["id"] for i in page["items"]]
            cursor = page["next_cursor"]
            if not cursor:
                break
        assert len(seen) >= 2 and len(seen) == len(set(seen)), (endpoint, seen)


def test_malformed_cursors_are_400_on_every_other_list_endpoint(world: World) -> None:
    pid = _product(world)
    tid = _tenant(world, pid)
    base = f"/v1/products/{pid}"
    paths: list[tuple[str, dict[str, str]]] = [
        ("/v1/users", {}),
        (f"{base}/jobs", {}),
        (f"{base}/schedules", {}),
        (f"{base}/events", {}),
        (f"{base}/webhooks", {}),
        (f"{base}/usage/summary", {}),
        (f"{base}/tenants/{tid}/usage/events", {}),
        (f"{base}/storage/usage", {}),
        (f"/v1/products/{pid}/tenants/{tid}/files", {}),
        (f"/v1/products/{pid}/tenants/{tid}/files", {"sort": "name"}),
        (f"/v1/products/{pid}/tenants/{tid}/files", {"sort": "-size"}),
        (f"{base}/tenants/{tid}/records/notes", {}),
        (f"{base}/tenants/{tid}/records/notes", {"sort": "-updated_at"}),
        (f"{base}/tenants/{tid}/search", {"q": "x"}),
    ]
    universal = (
        "not base64",
        "deeply nested",
        "empty list",
        "integers",
        "nulls",
        "NUL in id",
        "lone surrogate in id",
    )
    for path, params in paths:
        assert world.admin.get(path, params=params).status_code == 200, path
        samples = {k: MALFORMED[k] for k in universal}
        if params.get("sort") == "-size":
            samples["size as text"] = encode_cursor(["big", "fil_x"])
        if params.get("sort") == "name":
            samples["name as number"] = encode_cursor([1, "fil_x"])
        for name, cursor in samples.items():
            r = world.admin.get(path, params={**params, "cursor": cursor})
            assert r.status_code == 400, (path, params, name, r.text)
            assert r.json()["code"] == "invalid_cursor", (path, name, r.text)
