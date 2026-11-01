"""Contract tests against a RUNNING Axentra server (no server package needed).

Run by ``scripts/sdk-e2e.sh``, which starts a PostgreSQL-backed ``axentra serve`` and sets:
AXENTRA_SDK_E2E_URL, AXENTRA_SDK_E2E_API_KEY, AXENTRA_SDK_E2E_PRODUCT_ID, AXENTRA_SDK_E2E_TENANT_ID
and optionally AXENTRA_SDK_E2E_ADMIN_EMAIL / AXENTRA_SDK_E2E_ADMIN_PASSWORD.
"""

from __future__ import annotations

from collections.abc import Iterator
import os
import uuid

import pytest

from axentra_client import API_VERSION, AsyncAxentraClient, AxentraApiError, AxentraClient

URL = os.environ.get("AXENTRA_SDK_E2E_URL", "")
KEY = os.environ.get("AXENTRA_SDK_E2E_API_KEY", "")
PRODUCT = os.environ.get("AXENTRA_SDK_E2E_PRODUCT_ID", "")
TENANT = os.environ.get("AXENTRA_SDK_E2E_TENANT_ID", "")
ADMIN_EMAIL = os.environ.get("AXENTRA_SDK_E2E_ADMIN_EMAIL", "")
ADMIN_PASSWORD = os.environ.get("AXENTRA_SDK_E2E_ADMIN_PASSWORD", "")

pytestmark = [
    pytest.mark.e2e,
    pytest.mark.skipif(
        not (URL and KEY and PRODUCT and TENANT), reason="AXENTRA_SDK_E2E_* not set (see scripts/sdk-e2e.sh)"
    ),
]
RUN = uuid.uuid4().hex[:8]


@pytest.fixture(scope="module")
def ax() -> Iterator[AxentraClient]:
    with AxentraClient(URL, api_key=KEY) as c:
        yield c


def test_compatible(ax: AxentraClient) -> None:
    meta = ax.check_compatibility()
    assert meta.api_version.major == API_VERSION[0] and meta.api_version.minor >= API_VERSION[1]


def test_api_key_identity_and_errors(ax: AxentraClient) -> None:
    assert ax.me.get().actor_kind == "api_key"
    with pytest.raises(AxentraApiError) as ei:
        ax.products.get("prd_doesnotexist")
    assert ei.value.status == 404 and ei.value.code == "not_found" and ei.value.request_id
    with pytest.raises(AxentraApiError) as ei:
        AxentraClient(URL).me.get()
    assert ei.value.status == 401


def test_tenants_and_records(ax: AxentraClient) -> None:
    for i in range(3):
        ax.tenants.create(PRODUCT, f"py-{RUN}-{i}", f"Py {i}")
    slugs = {t.slug for t in ax.tenants.iter(PRODUCT, page_size=1)}
    assert {f"py-{RUN}-{i}" for i in range(3)} <= slugs
    rec = ax.records.create(PRODUCT, TENANT, "py_notes", {"n": 1})
    rec = ax.records.replace(PRODUCT, TENANT, "py_notes", rec.id, {"n": 2}, version=rec.version)
    with pytest.raises(AxentraApiError) as ei:
        ax.records.replace(PRODUCT, TENANT, "py_notes", rec.id, {"n": 3}, version=1)
    assert ei.value.code == "precondition_failed"
    assert [r.data["n"] for r in ax.records.iter(PRODUCT, TENANT, "py_notes")] == [2]
    ax.records.delete(PRODUCT, TENANT, "py_notes", rec.id)


def test_files_and_usage(ax: AxentraClient) -> None:
    payload = os.urandom(1_500_000)
    info = ax.files.upload(PRODUCT, TENANT, payload, filename="random.bin")
    assert ax.files.download(PRODUCT, TENANT, info.id) == payload
    meter = f"py_calls_{RUN}"
    ax.usage.create_meter(PRODUCT, meter, unit="calls")
    first = ax.usage.record(PRODUCT, TENANT, meter, 2, idempotency_key=f"py-{RUN}")
    again = ax.usage.record(PRODUCT, TENANT, meter, 2, idempotency_key=f"py-{RUN}")
    assert again.replayed and again.event.id == first.event.id
    assert {m.meter: m.value for m in ax.usage.summary(PRODUCT, TENANT)}[meter] == 2


@pytest.mark.skipif(not (ADMIN_EMAIL and ADMIN_PASSWORD), reason="no admin credentials")
def test_password_login_and_logout() -> None:
    with AxentraClient(URL) as c:
        info = c.auth.login_password(ADMIN_EMAIL, ADMIN_PASSWORD)
        assert info.user.email == ADMIN_EMAIL
        assert c.me.get().platform_role is not None
        assert c.me.update(name=f"Py {RUN}").name == f"Py {RUN}"
        token = c.token
        c.auth.logout()
    with pytest.raises(AxentraApiError) as ei:
        AxentraClient(URL, session_token=token).me.get()
    assert ei.value.status == 401


@pytest.mark.anyio
async def test_async_client() -> None:
    async with AsyncAxentraClient(URL, api_key=KEY) as c:
        await c.check_compatibility()
        rec = await c.records.create(PRODUCT, TENANT, "py_async", {"ok": True})
        assert (await c.records.get(PRODUCT, TENANT, "py_async", rec.id)).data == {"ok": True}
