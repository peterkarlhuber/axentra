"""Quotas, reservations and idempotency keys hold under concurrent requests (audit round 3).

Parallel HTTP requests against real PostgreSQL; the expected numbers are exact because the services
serialize on row locks (storage usage row, usage counters, idempotency keys).
"""

from __future__ import annotations

from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from fastapi.testclient import TestClient

from axentra.access.permissions import TENANT
from tests.integration.conftest import World


def _ok(r: Any, code: int = 201) -> dict[str, Any]:
    assert r.status_code == code, r.text
    return r.json() if r.content else {}


def _par(n: int, fn: Callable[[int], Any]) -> list[Any]:
    with ThreadPoolExecutor(n) as ex:
        return list(ex.map(fn, range(n)))


def test_quotas_reservations_and_idempotency_under_concurrency(world: World) -> None:
    a = world.admin
    pid = _ok(a.post("/v1/products", json={"slug": "conc", "name": "C"}))["id"]
    tids = [
        _ok(a.post(f"/v1/products/{pid}/tenants", json={"slug": f"t{i}", "name": f"T{i}"}))["id"]
        for i in range(3)
    ]
    secret = _ok(a.post(f"/v1/products/{pid}/api-keys", json={"name": "k", "permissions": sorted(TENANT)}))[
        "secret"
    ]

    def client() -> TestClient:
        return TestClient(world.app, headers={"Authorization": f"Bearer {secret}"})

    # Storage bytes: 100-byte quota, 12 parallel uploads of 30 bytes -> exactly 3 fit.
    base = f"/v1/products/{pid}/tenants/{tids[0]}"
    _ok(a.put(f"{base}/storage/quota", json={"quota_bytes": 100, "quota_files": None}), 200)
    codes = _par(
        12,
        lambda i: (
            client().post(f"{base}/files", files={"file": (f"f{i}.txt", b"x" * 30, "text/plain")}).status_code
        ),
    )
    assert sorted(codes) == [201] * 3 + [429] * 9
    assert a.get(f"{base}/storage/usage").json()["bytes_used"] == 90

    # Storage files: 2-file quota, 8 parallel uploads -> exactly 2.
    base = f"/v1/products/{pid}/tenants/{tids[1]}"
    _ok(a.put(f"{base}/storage/quota", json={"quota_bytes": None, "quota_files": 2}), 200)
    codes = _par(
        8,
        lambda i: (
            client().post(f"{base}/files", files={"file": (f"g{i}.txt", b"y", "text/plain")}).status_code
        ),
    )
    assert sorted(codes) == [201] * 2 + [429] * 6

    # Usage: hard limit 10, 20 parallel reservations of 1 -> exactly 10.
    base = f"/v1/products/{pid}/tenants/{tids[2]}"
    _ok(a.post(f"/v1/products/{pid}/usage/meters", json={"key": "calls", "unit": "calls"}))
    _ok(a.put(f"{base}/usage/quotas/calls", json={"limit": 10, "enforcement": "hard"}), 200)
    res = _par(
        20, lambda i: client().post(f"{base}/usage/reservations", json={"meter": "calls", "quantity": 1})
    )
    ok = [r.json()["id"] for r in res if r.status_code == 201]
    assert len(ok) == 10 and sorted(r.status_code for r in res if r.status_code != 201) == [429] * 10

    # One reservation committed 8 times in parallel counts once.
    _par(8, lambda i: client().post(f"{base}/usage/reservations/{ok[0]}/commit", json={}))
    for rid in ok[1:]:
        _ok(client().post(f"{base}/usage/reservations/{rid}/release", json={}), 200)
    summary = a.get(f"{base}/usage/summary").json()[0]
    assert (summary["value"], summary["reserved"], summary["event_count"]) == (1.0, 0.0, 1)

    # 8 parallel usage events with one Idempotency-Key -> one event.
    ev = _par(
        8,
        lambda i: client().post(
            f"{base}/usage/events",
            json={"meter": "calls", "quantity": 1},
            headers={"Idempotency-Key": "same-key"},
        ),
    )
    # One creates the event, the others replay it (200); a replay is never a second event.
    assert [r.status_code for r in ev].count(201) == 1 and {r.status_code for r in ev} <= {200, 201}
    assert a.get(f"{base}/usage/summary").json()[0]["event_count"] == 2

    # Hard limit on direct recording: 8 left, 12 parallel events -> exactly 8.
    hv = _par(
        12,
        lambda i: (
            client()
            .post(
                f"{base}/usage/events",
                json={"meter": "calls", "quantity": 1},
                headers={"Idempotency-Key": f"k{i}"},
            )
            .status_code
        ),
    )
    assert sorted(hv) == [201] * 8 + [429] * 4
    end = a.get(f"{base}/usage/summary").json()[0]
    assert (end["value"], end["remaining"]) == (10.0, 0.0)


def test_if_match_races_have_exactly_one_winner(world: World) -> None:
    """Optimistic concurrency under real parallelism: N writers send the same ``If-Match`` at the
    same moment; exactly one wins (200), all others get 412, and the stored state is the winner's
    with the version bumped once."""
    a = world.admin
    pid = _ok(a.post("/v1/products", json={"slug": "race", "name": "R"}))["id"]
    tid = _ok(a.post(f"/v1/products/{pid}/tenants", json={"slug": "rt", "name": "T"}))["id"]
    perms = sorted(TENANT | {"tenants:update"})
    secret = _ok(a.post(f"/v1/products/{pid}/api-keys", json={"name": "k", "permissions": perms}))["secret"]
    n = 8

    def client() -> TestClient:
        return TestClient(world.app, headers={"Authorization": f"Bearer {secret}"})

    def race(method: str, url: str, etag: str, body: Callable[[int], dict[str, Any]]) -> int:
        res = _par(n, lambda i: client().request(method, url, json=body(i), headers={"If-Match": etag}))
        codes = sorted(r.status_code for r in res)
        assert codes == [200] + [412] * (n - 1), [r.text for r in res if r.status_code not in (200, 412)]
        return next(i for i, r in enumerate(res) if r.status_code == 200)

    base = f"/v1/products/{pid}/tenants/{tid}"
    # Records: two rounds of full replaces on the same record.
    rec = _ok(client().post(f"{base}/records/notes", json={"n": -1}))
    for version in (1, 2):
        winner = race("PUT", f"{base}/records/notes/{rec['id']}", f'"{version}"', lambda i: {"n": i})
        got = a.get(f"{base}/records/notes/{rec['id']}").json()
        assert got["data"] == {"n": winner} and got["version"] == version + 1

    # File metadata.
    f = _ok(client().post(f"{base}/files", files={"file": ("a.txt", b"a", "text/plain")}))
    winner = race("PATCH", f"{base}/files/{f['id']}", "1", lambda i: {"name": f"name-{i}.txt"})
    got = a.get(f"{base}/files/{f['id']}").json()
    assert got["name"] == f"name-{winner}.txt" and got["version"] == 2

    # Tenant storage quota.
    winner = race(
        "PUT", f"{base}/storage/quota", "0", lambda i: {"quota_bytes": 1000 + i, "quota_files": None}
    )
    usage = a.get(f"{base}/storage/usage").json()
    assert usage["quota_bytes"] == 1000 + winner and usage["quota_version"] == 1
