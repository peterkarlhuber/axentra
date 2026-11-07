"""Search: batch indexing, delete by kind and the metadata filter."""

from __future__ import annotations

import json

import pytest

from axentra.data.database import DbScope
from tests.integration.test_search import _base, _member, _product, _put, _search, _tenant


@pytest.fixture
def two_tenants(world):  # type: ignore[no-untyped-def]
    pid = _product(world)
    return world, pid, _tenant(world, pid, "acme"), _tenant(world, pid, "globex")


def _batch(client, pid, tid, documents):  # type: ignore[no-untyped-def]
    return client.post(f"{_base(pid, tid)}/documents/batch", json={"documents": documents})


def _actions(world, tid):  # type: ignore[no-untyped-def]
    with world.ax.db.transaction(DbScope.platform(), read_only=True) as tx:
        return [
            (r["action"], r["details"])
            for r in tx.all(
                "SELECT action, details FROM axentra_audit_events WHERE tenant_id = %s AND action LIKE 'search.%%'"
                " ORDER BY occurred_at, id",
                (tid,),
            )
        ]


def test_batch_upsert_is_all_or_nothing(two_tenants):  # type: ignore[no-untyped-def]
    world, pid, t1, t2 = two_tenants
    assert _put(world.admin, pid, t1, "note", "n1", title="Old title").status_code == 201
    docs = [
        {"kind": "note", "ref_id": "n1", "title": "Alpha report"},
        {"kind": "note", "ref_id": "n2", "body": "alpha body", "metadata": {"status": "open"}},
        {"kind": "task", "ref_id": "t1", "title": "Alpha task", "metadata": {"status": "done"}},
    ]
    r = _batch(world.admin, pid, t1, docs)
    assert r.status_code == 200, r.text
    body = r.json()
    assert (body["created"], body["updated"]) == (2, 1)
    assert [d["ref_id"] for d in body["documents"]] == ["n1", "n2", "t1"]
    assert body["documents"][0]["version"] == 2
    hits = _search(world.admin, pid, t1, "alpha").json()["items"]
    assert sorted(h["ref_id"] for h in hits) == ["n1", "n2", "t1"]
    assert _search(world.admin, pid, t2, "alpha").json()["items"] == []  # other tenant untouched
    assert [a for a, _ in _actions(world, t1)].count("search.document.upsert") == 4
    # One invalid document refuses the whole batch, and the error names it.
    bad = [{"kind": "note", "ref_id": "n3", "title": "Beta"}, {"kind": "note", "ref_id": "n4"}]
    r = _batch(world.admin, pid, t1, bad)
    assert r.status_code == 422 and "documents[1]" in r.json()["detail"]
    assert _search(world.admin, pid, t1, "beta").json()["items"] == []
    dup = [{"kind": "note", "ref_id": "n5", "title": "x"}, {"kind": "note", "ref_id": "n5", "title": "y"}]
    r = _batch(world.admin, pid, t1, dup)
    assert r.status_code == 422 and "more than once" in r.json()["detail"]
    assert _batch(world.admin, pid, t1, []).status_code == 422
    too_many = [{"kind": "note", "ref_id": f"m{i}", "title": "x"} for i in range(101)]
    assert _batch(world.admin, pid, t1, too_many).status_code == 422
    assert (
        _batch(world.admin, pid, t1, [{"kind": "Bad Kind", "ref_id": "x", "title": "x"}]).status_code == 422
    )


def test_delete_kind_and_permissions(two_tenants):  # type: ignore[no-untyped-def]
    world, pid, t1, t2 = two_tenants
    _batch(world.admin, pid, t1, [{"kind": "note", "ref_id": f"n{i}", "title": "gamma"} for i in range(5)])
    _put(world.admin, pid, t1, "task", "t1", title="gamma task")
    _put(world.admin, pid, t2, "note", "n1", title="gamma other")
    viewer = _member(world, pid, t1, "viewer@example.com", "viewer")
    assert viewer.delete(f"{_base(pid, t1)}/documents/note").status_code == 403
    assert _batch(viewer, pid, t1, [{"kind": "note", "ref_id": "v", "title": "x"}]).status_code == 403
    r = world.admin.delete(f"{_base(pid, t1)}/documents/note")
    assert r.status_code == 200 and r.json() == {"deleted": 5}
    assert [h["kind"] for h in _search(world.admin, pid, t1, "gamma").json()["items"]] == ["task"]
    assert len(_search(world.admin, pid, t2, "gamma").json()["items"]) == 1  # other tenant untouched
    assert ("search.documents.delete_kind", {"kind": "note", "count": 5}) in _actions(world, t1)
    assert world.admin.delete(f"{_base(pid, t1)}/documents/note").json() == {"deleted": 0}
    assert world.admin.delete(f"{_base(pid, t1)}/documents/Bad Kind").status_code == 422


def test_metadata_filter(two_tenants):  # type: ignore[no-untyped-def]
    world, pid, t1, _ = two_tenants
    _batch(
        world.admin,
        pid,
        t1,
        [
            {
                "kind": "ticket",
                "ref_id": "a",
                "title": "printer broken",
                "metadata": {"status": "open", "prio": 1},
            },
            {
                "kind": "ticket",
                "ref_id": "b",
                "title": "printer jam",
                "metadata": {"status": "closed", "prio": 1},
            },
            {
                "kind": "ticket",
                "ref_id": "c",
                "title": "printer ink",
                "metadata": {"status": "open", "prio": 2},
            },
        ],
    )

    def refs(meta):  # type: ignore[no-untyped-def]
        r = _search(world.admin, pid, t1, "printer", metadata=json.dumps(meta))
        assert r.status_code == 200, r.text
        return sorted(h["ref_id"] for h in r.json()["items"])

    assert refs({"status": "open"}) == ["a", "c"]
    assert refs({"status": "open", "prio": 2}) == ["c"]
    assert refs({"status": "missing"}) == []
    assert refs({}) == ["a", "b", "c"]
    for bad in ("[1]", "not json", '"text"'):
        r = _search(world.admin, pid, t1, "printer", metadata=bad)
        assert r.status_code == 422 and "metadata" in r.json()["detail"]
    assert _search(world.admin, pid, t1, "printer", metadata="x" * 2001).status_code == 422
    big = json.dumps({"k": "v" * 1995})
    assert _search(world.admin, pid, t1, "printer", metadata=big).status_code == 422
