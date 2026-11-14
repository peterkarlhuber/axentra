# ruff: noqa: S603, S607
"""Live S3 check: Axentra's S3 storage backend against SeaweedFS (synthetic data only).

Needs (see compose.yml) the ``seaweedfs`` service: S3 API on 127.0.0.1:19333 with the synthetic
identity from ``seaweedfs-s3.json``, and Docker access to stop/start the container named in
``LC_S3_CONTAINER`` (default ``lc-seaweedfs``) for the outage part.

Checks upload, download (session and signed token), presigned download, delete, quota, tenant
isolation of object keys, and the behaviour while the S3 endpoint is down (status, problem body and
logs must not reveal credentials).
"""

from __future__ import annotations

import hashlib
import os
import subprocess
import sys
import time

import httpx
from lib import (
    EVIDENCE,
    Api,
    Report,
    base_env,
    bootstrap_admin,
    product_and_tenant,
    reset_database,
    run_cli,
    scan_for_secrets,
    serve,
)

PORT = int(os.environ.get("LC_S3_AX_PORT", "19202"))
ENDPOINT = os.environ.get("LC_S3_ENDPOINT", "http://127.0.0.1:19333")
BUCKET = os.environ.get("LC_S3_BUCKET", "lc-axentra")
ACCESS = os.environ.get("LC_S3_ACCESS_KEY", "LCSYNTHETICACCESS")
SECRET = os.environ.get("LC_S3_SECRET_KEY", "lc-synthetic-s3-secret-0123456789")
CONTAINER = os.environ.get("LC_S3_CONTAINER", "lc-seaweedfs")


def s3client():  # type: ignore[no-untyped-def]
    import boto3

    return boto3.client(
        "s3",
        endpoint_url=ENDPOINT,
        aws_access_key_id=ACCESS,
        aws_secret_access_key=SECRET,
        region_name="us-east-1",
    )


def keys(client) -> list[str]:  # type: ignore[no-untyped-def]
    return sorted(
        o["Key"] for o in client.list_objects_v2(Bucket=BUCKET, Prefix="ax/").get("Contents", []) or []
    )


def wait_s3(timeout: float = 60) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            s3client().head_bucket(Bucket=BUCKET)
            return
        except Exception:
            time.sleep(1)
    raise RuntimeError("S3 endpoint did not come back")


def main() -> int:
    rep = Report("s3")
    log = EVIDENCE / "s3-serve.log"
    log.unlink(missing_ok=True)
    s3 = s3client()
    try:
        s3.create_bucket(Bucket=BUCKET)
    except Exception as exc:  # already exists
        rep.note(f"create_bucket: {type(exc).__name__}")
    for k in keys(s3):
        s3.delete_object(Bucket=BUCKET, Key=k)

    db = reset_database("lc_s3")
    storage = {
        "AXENTRA__STORAGE__BACKEND": "s3",
        "AXENTRA__STORAGE__S3_BUCKET": BUCKET,
        "AXENTRA__STORAGE__S3_ENDPOINT_URL": ENDPOINT,
        "AXENTRA__STORAGE__S3_REGION": "us-east-1",
        "AXENTRA__STORAGE__S3_PREFIX": "ax",
        "AXENTRA__STORAGE__S3_ACCESS_KEY_REF": "env:LC_S3_ACCESS_KEY",
        "AXENTRA__STORAGE__S3_SECRET_KEY_REF": "env:LC_S3_SECRET_KEY",
        "LC_S3_ACCESS_KEY": ACCESS,
        "LC_S3_SECRET_KEY": SECRET,
    }
    env = base_env(db, PORT, **storage, AXENTRA__OBSERVABILITY__LOG_LEVEL="INFO")
    outage: dict[str, object] = {}
    with serve(env, PORT, log):
        admin = bootstrap_admin(env, PORT, log)
        pid, acme = product_and_tenant(admin, "lcfiles", "acme")
        globex = admin.ok("POST", f"/v1/products/{pid}/tenants", json={"slug": "globex", "name": "Globex"})[
            "id"
        ]
        fa = f"/v1/products/{pid}/tenants/{acme}/files"
        fg = f"/v1/products/{pid}/tenants/{globex}/files"

        payload = os.urandom(200_000)
        r = admin.post(
            fa, files={"file": ("../../globex/evil name.bin", payload, "application/octet-stream")}
        )
        rep.check("upload to SeaweedFS answers 201", r.status_code == 201, f"{r.status_code} {r.text[:200]}")
        f1 = r.json()
        rep.check(
            "sha256 and size recorded",
            f1["sha256"] == hashlib.sha256(payload).hexdigest() and f1["size"] == len(payload),
        )
        rep.check("display name sanitized (last segment only)", f1["name"] == "evil name.bin", f1["name"])
        g1 = admin.ok("POST", fg, files={"file": ("g.txt", b"globex synthetic data", "text/plain")})
        ks = keys(s3)
        rep.check(
            "object keys are <prefix>/<product>/<tenant>/<file id>, from ids only",
            ks == sorted([f"ax/{pid}/{acme}/{f1['id']}", f"ax/{pid}/{globex}/{g1['id']}"]),
            ks,
        )
        head = s3.head_object(Bucket=BUCKET, Key=f"ax/{pid}/{acme}/{f1['id']}")
        rep.check(
            "bucket object has the uploaded bytes",
            head["ContentLength"] == len(payload),
            head["ContentLength"],
        )

        d = admin.get(f"{fa}/{f1['id']}/content")
        rep.check(
            "download through the session", d.status_code == 200 and d.content == payload, d.status_code
        )
        rep.check(
            "download is an attachment with nosniff",
            d.headers.get("content-disposition", "").startswith("attachment")
            and d.headers.get("x-content-type-options") == "nosniff",
        )

        # Tenant isolation: the acme file id through the globex path, and listing.
        rep.check(
            "acme file via globex path -> 404", admin.get(f"{fg}/{f1['id']}/content").status_code == 404
        )
        lst = admin.ok("GET", fg)["items"]
        rep.check("globex listing shows only globex files", [x["id"] for x in lst] == [g1["id"]])

        # Signed download token flow: anonymous client, then tampering.
        du = admin.ok("POST", f"{fa}/{f1['id']}/download-url", json={"ttl_seconds": 60})
        rep.check(
            "download-url kind=signed",
            du["kind"] == "signed" and du["path"].startswith("/v1/files/download/"),
            du["kind"],
        )
        anon = httpx.get(f"http://127.0.0.1:{PORT}{du['path']}", timeout=30)
        rep.check(
            "anonymous download with the signed token",
            anon.status_code == 200 and anon.content == payload,
            anon.status_code,
        )
        tok = du["path"].rsplit("/", 1)[1]
        bad = tok[:-2] + ("AA" if not tok.endswith("AA") else "BB")
        rep.check(
            "tampered token -> 404",
            httpx.get(f"http://127.0.0.1:{PORT}/v1/files/download/{bad}", timeout=30).status_code == 404,
        )

        # Quota: 250 kB for acme (one file of 200 kB is already stored).
        usage = admin.ok("GET", f"/v1/products/{pid}/tenants/{acme}/storage/usage")
        admin.ok(
            "PUT",
            f"/v1/products/{pid}/tenants/{acme}/storage/quota",
            json={"quota_bytes": 250_000, "quota_files": None},
            headers={"If-Match": f'"{usage["quota_version"]}"'},
        )
        r = admin.post(fa, files={"file": ("big.bin", os.urandom(100_000), "application/octet-stream")})
        rep.check(
            "upload beyond quota -> 429 quota_exceeded",
            r.status_code == 429 and r.json().get("code") == "quota_exceeded",
            f"{r.status_code} {r.text[:200]}",
        )
        rep.check("no orphan object left by the refused upload", len(keys(s3)) == 2, keys(s3))
        r = admin.post(fa, files={"file": ("small.bin", os.urandom(10_000), "application/octet-stream")})
        rep.check("upload within quota still works", r.status_code == 201, r.status_code)
        small = r.json()

        # Delete: object removed from the bucket, later reads 404, token dead.
        r = admin.delete(f"{fa}/{f1['id']}")
        rep.check("delete -> 204", r.status_code == 204, r.status_code)
        rep.check("object removed from the bucket", f"ax/{pid}/{acme}/{f1['id']}" not in keys(s3), keys(s3))
        rep.check("deleted file content -> 404", admin.get(f"{fa}/{f1['id']}/content").status_code == 404)
        rep.check(
            "signed token of the deleted file -> 404",
            httpx.get(f"http://127.0.0.1:{PORT}{du['path']}", timeout=30).status_code == 404,
        )
        usage = admin.ok("GET", f"/v1/products/{pid}/tenants/{acme}/storage/usage")
        rep.check(
            "usage counts only the remaining file",
            usage["bytes_used"] == 10_000 and usage["files_used"] == 1,
            usage,
        )

        # Outage: stop the S3 container (connection refused).
        subprocess.run(["docker", "stop", CONTAINER], check=True, capture_output=True)
        try:

            def attempt(name: str, fn) -> None:  # type: ignore[no-untyped-def]
                t0 = time.monotonic()
                try:
                    res = fn()
                    outage[name] = {
                        "status": res.status_code,
                        "seconds": round(time.monotonic() - t0, 1),
                        "body": res.text[:600],
                        "headers": dict(res.headers),
                    }
                except httpx.HTTPError as exc:
                    # uvicorn closes a keep-alive connection after an unhandled exception; the client's
                    # next request on that pooled connection sees a reset. Record it, retry once on a new one.
                    first = f"transport error: {type(exc).__name__}: {exc}"
                    res = fn()
                    outage[name] = {
                        "status": res.status_code,
                        "first_attempt": first,
                        "seconds": round(time.monotonic() - t0, 1),
                        "body": res.text[:600],
                        "headers": dict(res.headers),
                    }

            attempt(
                "upload", lambda: admin.post(fa, files={"file": ("down.txt", b"while down", "text/plain")})
            )
            attempt("download", lambda: admin.get(f"{fa}/{small['id']}/content"))
            attempt(
                "signed_download",
                lambda: httpx.get(
                    f"http://127.0.0.1:{PORT}"
                    + admin.ok("POST", f"{fa}/{small['id']}/download-url", json={})["path"],
                    timeout=60,
                ),
            )
            attempt("delete", lambda: admin.delete(f"{fa}/{small['id']}"))
            rep.save_json("outage", outage)
            for name, res in outage.items():
                body = str(res["body"])  # type: ignore[index]
                rep.check(
                    f"S3 down: {name} -> no credentials/endpoint in the response",
                    ACCESS not in body
                    and SECRET not in body
                    and "19333" not in body
                    and "botocore" not in body,
                    res,
                )
            for name in ("upload", "download", "signed_download"):
                res = outage[name]
                rep.check(
                    f"S3 down: {name} -> 503 service_unavailable with Retry-After",
                    res["status"] == 503  # type: ignore[index]
                    and '"service_unavailable"' in str(res["body"])  # type: ignore[index]
                    and "retry-after" in res.get("headers", {}),  # type: ignore[union-attr]
                    (res["status"], res.get("headers", {}).get("retry-after")),  # type: ignore[index,union-attr]
                )
            rep.check(
                "S3 down: keep-alive intact (no reset on the next request, nothing escaped to uvicorn)",
                not any("first_attempt" in v for v in outage.values()),  # type: ignore[operator]
                {k: v.get("first_attempt") for k, v in outage.items()},  # type: ignore[union-attr]
            )
            statuses = {k: v["status"] for k, v in outage.items()}  # type: ignore[index]
            rep.note(f"S3 down status codes: {statuses}")
            files_now = [x["id"] for x in admin.ok("GET", fa)["items"]]
            rep.note(f"acme files listed after the outage attempts: {files_now}")
        finally:
            subprocess.run(["docker", "start", CONTAINER], check=True, capture_output=True)
            wait_s3()
        time.sleep(2)
        d = admin.get(f"{fa}/{small['id']}/content")
        rep.note(f"after recovery: download of the small file -> {d.status_code}")
        orphan = f"ax/{pid}/{acme}/{small['id']}"
        rep.note(
            f"after recovery: object of the file deleted during the outage still in the bucket: {orphan in keys(s3)} (left for `axentra storage purge` orphan scan)"
        )
        purge = run_cli(env, "storage", "purge", log=log)
        rep.check(
            "after recovery: `axentra storage purge` removes that object",
            orphan not in keys(s3),
            purge.strip()[-300:],
        )
        r = admin.post(fa, files={"file": ("after.txt", b"after recovery", "text/plain")})
        rep.check("after recovery: upload works again", r.status_code == 201, r.status_code)
        pend = admin.ok("GET", f"/v1/products/{pid}/tenants/{acme}/storage/usage")
        rep.note(f"usage after outage + recovery: {pend}")

    rep.check(
        "no unhandled exception reached uvicorn",
        "Exception in ASGI application" not in log.read_text(errors="replace"),
    )
    hits = scan_for_secrets(log, {"s3_secret_key": SECRET})
    rep.check("S3 secret key not in the serve log", not any(hits.values()), hits)
    rep.note(f"S3 access key id occurrences in the serve log: {scan_for_secrets(log, {'access': ACCESS})}")

    # Presigned downloads (s3_presigned_downloads = true): second run against the same database.
    # DEBUG: botocore logs its request headers; the SigV4 Authorization value must be redacted.
    env2 = dict(
        env, AXENTRA__STORAGE__S3_PRESIGNED_DOWNLOADS="true", AXENTRA__OBSERVABILITY__LOG_LEVEL="DEBUG"
    )
    debug_from = log.stat().st_size
    with serve(env2, PORT, log):
        admin = Api(PORT)
        from lib import ADMIN_EMAIL, ADMIN_PASSWORD

        admin.login(ADMIN_EMAIL, ADMIN_PASSWORD)
        f = admin.ok("POST", fa, files={"file": ("pres.txt", b"presigned synthetic", "text/plain")})
        du = admin.ok("POST", f"{fa}/{f['id']}/download-url", json={"ttl_seconds": 60})
        rep.check(
            "presigned: kind=presigned, URL on the S3 endpoint",
            du["kind"] == "presigned" and du["url"].startswith(ENDPOINT),
            du["url"].split("?")[0],
        )
        r = httpx.get(du["url"], timeout=30)
        rep.check(
            "presigned URL is SigV4",
            "X-Amz-Algorithm=AWS4-HMAC-SHA256" in du["url"],
            du["url"].split("?")[1][:40],
        )
        rep.check(
            "presigned URL downloads the object from SeaweedFS",
            r.status_code == 200 and r.content == b"presigned synthetic",
            r.status_code,
        )
        rep.check("presigned URL carries no secret key", SECRET not in du["url"])
    debug_log = log.read_text(errors="replace")[debug_from:]
    rep.check(
        "DEBUG log: botocore request headers logged, SigV4 credential and signature redacted",
        "AWS4-HMAC-SHA256" in debug_log
        and f"Credential={ACCESS}" not in debug_log
        and SECRET not in debug_log,
        {
            "authorization_lines": debug_log.count("AWS4-HMAC-SHA256"),
            "access_key_id_hits": debug_log.count(ACCESS),
        },
    )
    return rep.finish()


if __name__ == "__main__":
    sys.exit(main())
