"""Storage module with the S3 backend, against moto's in-process S3 mock (no real AWS)."""

from __future__ import annotations

import hashlib
import os
from urllib.parse import parse_qs, urlparse

from fastapi.testclient import TestClient
import pytest

from axentra.api.app import create_app
from axentra.core.context import Principal
from axentra.core.errors import PayloadTooLarge
from tests.integration.conftest import World, bootstrap_admin

boto3 = pytest.importorskip("boto3")
moto = pytest.importorskip("moto")

BUCKET = "axentra-test-bucket"


@pytest.fixture
def s3(monkeypatch):  # type: ignore[no-untyped-def]
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
    with moto.mock_aws():
        client = boto3.client("s3", region_name="us-east-1")
        client.create_bucket(Bucket=BUCKET)
        yield client


def _world(ax_factory, **storage) -> World:  # type: ignore[no-untyped-def]
    cfg = {"backend": "s3", "s3_bucket": BUCKET, "s3_region": "us-east-1", "s3_prefix": "ax", **storage}
    ax = ax_factory(storage=cfg)
    app = create_app(axentra=ax, start=False)
    return World(ax=ax, app=app, admin=bootstrap_admin(ax, app))


def _setup(world):
    pid = world.admin.post("/v1/products", json={"slug": "crm", "name": "CRM"}).json()["id"]
    tid = world.admin.post(f"/v1/products/{pid}/tenants", json={"slug": "acme", "name": "Acme"}).json()["id"]
    return pid, tid, f"/v1/products/{pid}/tenants/{tid}/files"


def _keys(client) -> list[str]:
    return sorted(o["Key"] for o in client.list_objects_v2(Bucket=BUCKET).get("Contents", []))


def test_s3_roundtrip_multipart_and_delete(s3, ax_factory):
    world = _world(ax_factory)
    pid, tid, base = _setup(world)
    small = b"small object"
    r = world.admin.post(base, files={"file": ("small.txt", small, "text/plain")})
    assert r.status_code == 201, r.text
    f1 = r.json()
    # Larger than one 8 MiB part: goes through a multipart upload.
    big = os.urandom(9 * 1024 * 1024 + 123)
    f2 = world.ax.storage.upload(
        Principal.system(),
        pid,
        tid,
        iter([big[i : i + 65536] for i in range(0, len(big), 65536)]),
        name="big.bin",
    )
    assert f2.size == len(big) and f2.sha256 == hashlib.sha256(big).hexdigest()
    assert _keys(s3) == sorted([f"ax/{pid}/{tid}/{f1['id']}", f"ax/{pid}/{tid}/{f2.id}"])
    head = s3.head_object(Bucket=BUCKET, Key=f"ax/{pid}/{tid}/{f1['id']}")
    assert head["ContentType"] == "text/plain"

    d = world.admin.get(f"{base}/{f1['id']}/content")
    assert d.status_code == 200 and d.content == small
    assert d.headers["content-disposition"].startswith("attachment")
    d = world.admin.get(f"{base}/{f2.id}/content")
    assert d.status_code == 200 and hashlib.sha256(d.content).hexdigest() == f2.sha256

    assert world.admin.delete(f"{base}/{f1['id']}").status_code == 204
    assert _keys(s3) == [f"ax/{pid}/{tid}/{f2.id}"]


def test_s3_size_limit_aborts_multipart_upload(s3, ax_factory):
    world = _world(ax_factory, max_file_bytes=10 * 1024 * 1024)
    pid, tid, _ = _setup(world)

    def stream():
        for _ in range(200):
            yield b"q" * (1024 * 1024)

    with pytest.raises(PayloadTooLarge):
        world.ax.storage.upload(Principal.system(), pid, tid, stream(), name="too-big.bin")
    assert _keys(s3) == []
    assert s3.list_multipart_uploads(Bucket=BUCKET).get("Uploads", []) == []


def test_s3_signed_and_presigned_urls_and_orphans(s3, ax_factory):
    world = _world(ax_factory)
    pid, tid, base = _setup(world)
    fid = world.admin.post(base, files={"file": ("a.txt", b"via token", "text/plain")}).json()["id"]
    u = world.admin.post(f"{base}/{fid}/download-url").json()
    assert u["kind"] == "signed"
    assert TestClient(world.app).get(u["path"]).content == b"via token"

    # Orphan purge on S3 (keys outside the Axentra id scheme are left alone).
    s3.put_object(Bucket=BUCKET, Key=f"ax/{pid}/{tid}/fil_{'0' * 26}", Body=b"orphan")
    s3.put_object(Bucket=BUCKET, Key="ax/other-stuff", Body=b"keep")
    assert world.ax.storage.purge().orphans_deleted == 1
    assert _keys(s3) == sorted([f"ax/{pid}/{tid}/{fid}", "ax/other-stuff"])

    world.ax.storage.cfg = world.ax.storage.cfg.model_copy(update={"s3_presigned_downloads": True})
    p = world.admin.post(f"{base}/{fid}/download-url", json={"ttl_seconds": 30}).json()
    assert p["kind"] == "presigned" and p["path"] is None
    q = parse_qs(urlparse(p["url"]).query)
    assert q["response-content-disposition"][0].startswith("attachment")
    assert q["response-content-type"] == ["text/plain"]
    assert urlparse(p["url"]).path.endswith(f"ax/{pid}/{tid}/{fid}")
    # SigV4 (SigV2 presigned URLs with response-* overrides are refused by S3-compatible stores).
    assert q["X-Amz-Algorithm"] == ["AWS4-HMAC-SHA256"] and "AWSAccessKeyId" not in q
