# ruff: noqa: S603
"""Live webhook check: real deliveries from ``axentra worker`` to a local HTTP receiver.

No external service is needed: the receiver runs in this process on 127.0.0.1 (``LC_WH_RECEIVER_PORT``,
default 19290). Phase 1 runs with ``webhook_allow_http`` + ``webhook_allow_private_targets`` (needed
for a loopback receiver) and short retry settings; phase 2 restarts Axentra with the SSRF guard on.

Checks: signature (verified independently with hmac), headers, retries with backoff on HTTP 500,
timeouts, connection refused and DNS failure, the final ``dead`` state, no redirect following,
secret rotation (two signatures), and the SSRF guard for private/loopback/link-local/metadata targets.
"""

from __future__ import annotations

import contextlib
import hashlib
import hmac
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
import subprocess
import sys
import threading
import time

from lib import (
    ADMIN_EMAIL,
    ADMIN_PASSWORD,
    EVIDENCE,
    PYTHON,
    Api,
    Report,
    base_env,
    bootstrap_admin,
    product_and_tenant,
    reset_database,
    scan_for_secrets,
    serve,
)

PORT = int(os.environ.get("LC_WH_AX_PORT", "19204"))
RPORT = int(os.environ.get("LC_WH_RECEIVER_PORT", "19290"))
REFUSED_PORT = int(os.environ.get("LC_WH_REFUSED_PORT", "19291"))  # nothing listens here
R = f"http://127.0.0.1:{RPORT}"
HITS: list[dict] = []
LOCK = threading.Lock()


class Receiver(BaseHTTPRequestHandler):
    def log_message(self, *a: object) -> None:
        pass

    def do_POST(self) -> None:
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        with LOCK:
            HITS.append(
                {"path": self.path, "t": time.time(), "headers": dict(self.headers), "body": body.decode()}
            )
        if self.path.startswith("/slow"):
            time.sleep(6)
        code = {"/ok": 200, "/fail500": 500, "/slow": 200, "/redirect": 302}.get(self.path.split("?")[0], 404)
        self.send_response(code)
        if code == 302:
            self.send_header("Location", f"{R}/ok?from=redirect")
        payload = b'{"received": true}' if code == 200 else b"synthetic receiver error"
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        with contextlib.suppress(BrokenPipeError):  # the slow case: Axentra already gave up (timeout)
            self.wfile.write(payload)


def verify(secret: str, header: str, body: str) -> bool:
    parts = dict(p.split("=", 1) for p in header.split(",") if p.startswith("t="))
    t = parts.get("t", "")
    sigs = [p.split("=", 1)[1] for p in header.split(",") if p.startswith("v1=")]
    mac = hmac.new(secret.encode(), f"{t}.".encode() + body.encode(), hashlib.sha256).hexdigest()
    return any(hmac.compare_digest(mac, s) for s in sigs) and abs(time.time() - int(t)) < 300


def hits(path: str) -> list[dict]:
    with LOCK:
        return [h for h in HITS if h["path"].split("?")[0] == path]


def wait_deliveries(api: Api, pid: str, wid: str, final: set[str], timeout: float = 120) -> list[dict]:
    deadline = time.monotonic() + timeout
    while True:
        items = api.ok("GET", f"/v1/products/{pid}/webhooks/{wid}/deliveries")["items"]
        if items and all(d["status"] in final for d in items):
            return items
        if time.monotonic() > deadline:
            return items
        time.sleep(1)


def main() -> int:
    rep = Report("webhooks")
    log, wlog = EVIDENCE / "webhooks-serve.log", EVIDENCE / "webhooks-worker.log"
    for p in (log, wlog):
        p.unlink(missing_ok=True)
    srv = ThreadingHTTPServer(("127.0.0.1", RPORT), Receiver)
    threading.Thread(target=srv.serve_forever, daemon=True).start()

    db = reset_database("lc_wh")
    env = base_env(
        db,
        PORT,
        AXENTRA__EVENTS__WEBHOOK_ALLOW_HTTP="true",
        AXENTRA__EVENTS__WEBHOOK_ALLOW_PRIVATE_TARGETS="true",
        AXENTRA__EVENTS__WEBHOOK_MAX_ATTEMPTS="3",
        AXENTRA__EVENTS__WEBHOOK_BACKOFF_BASE_SECONDS="2",
        AXENTRA__EVENTS__WEBHOOK_BACKOFF_MAX_SECONDS="4",
        AXENTRA__EVENTS__WEBHOOK_TIMEOUT_SECONDS="2",
        AXENTRA__OBSERVABILITY__LOG_LEVEL="INFO",
    )
    secrets_seen: dict[str, str] = {}
    with serve(env, PORT, log):
        admin = bootstrap_admin(env, PORT, log)
        pid, tid = product_and_tenant(admin, "lchooks", "acme")
        W = f"/v1/products/{pid}/webhooks"
        targets = {
            "ok": f"{R}/ok",
            "fail500": f"{R}/fail500",
            "slow": f"{R}/slow",
            "redirect": f"{R}/redirect",
            "refused": f"http://127.0.0.1:{REFUSED_PORT}/hook",
            "dns": "http://lc-no-such-host.invalid/hook",
        }
        eps: dict[str, dict] = {}
        for name, url in targets.items():
            created = admin.ok(
                "POST", W, json={"url": url, "event_types": ["lc.*"], "description": f"lc {name}"}
            )
            eps[name] = created["endpoint"]
            secrets_seen[name] = created["secret"]
        rep.check(
            "endpoints created, secrets are whsec_",
            all(s.startswith("whsec_") for s in secrets_seen.values()),
        )
        listed = admin.ok("GET", W)["items"]
        rep.check("secret never returned by GET", "whsec_" not in json.dumps(listed))

        worker = subprocess.Popen(
            [PYTHON, "-m", "axentra.cli", "worker", "--concurrency", "8"],
            env=env,
            stdout=wlog.open("ab"),
            stderr=subprocess.STDOUT,
        )
        try:
            t_pub = time.time()
            ev = admin.ok(
                "POST",
                f"/v1/products/{pid}/tenants/{tid}/events",
                json={"type": "lc.order.created", "data": {"order": "synthetic-1", "amount": 42}},
            )
            rep.note(f"published event {ev['id']} at {t_pub:.1f}")
            final = {"succeeded", "dead"}
            results = {
                name: wait_deliveries(admin, pid, ep["id"], final, timeout=150) for name, ep in eps.items()
            }
        finally:
            worker.terminate()
            worker.wait(30)
        rep.save_json("deliveries", results)
        summary = {
            n: [(d["status"], d["attempts"], d["response_code"], (d["last_error"] or "")[:120]) for d in ds]
            for n, ds in results.items()
        }
        rep.save_json("delivery-summary", summary)

        ok = hits("/ok")
        d_ok = results["ok"][0] if results["ok"] else {}
        rep.check(
            "200 receiver: delivery succeeded on the first attempt",
            d_ok.get("status") == "succeeded" and d_ok.get("attempts") == 1,
            summary["ok"],
        )
        if ok:
            h, body = ok[0]["headers"], ok[0]["body"]
            rep.check(
                "signature verifies with the endpoint secret (independent HMAC-SHA256)",
                verify(secrets_seen["ok"], h.get("Axentra-Signature", ""), body),
            )
            rep.check(
                "signature does NOT verify with another endpoint's secret",
                not verify(secrets_seen["fail500"], h.get("Axentra-Signature", ""), body),
            )
            from axentra.events import verify_signature

            try:
                verify_signature(secrets_seen["ok"], h["Axentra-Signature"], body.encode())
                helper_ok = True
            except Exception as exc:
                helper_ok = repr(exc)
            rep.check(
                "axentra.events.verify_signature accepts the real request", helper_ok is True, helper_ok
            )
            b = json.loads(body)
            rep.check(
                "headers and body shape",
                h.get("Axentra-Event") == "lc.order.created"
                and h.get("Axentra-Event-Id") == b["id"] == ev["id"]
                and h.get("Axentra-Delivery", "").startswith("dlv_")
                and b["data"] == {"order": "synthetic-1", "amount": 42}
                and b["tenant_id"] == tid,
                {
                    k: h.get(k)
                    for k in (
                        "Axentra-Event",
                        "Axentra-Event-Id",
                        "Axentra-Delivery",
                        "Content-Type",
                        "User-Agent",
                    )
                },
            )
        f5 = hits("/fail500")
        d5 = results["fail500"][0] if results["fail500"] else {}
        gaps = [round(f5[i + 1]["t"] - f5[i]["t"], 1) for i in range(len(f5) - 1)]
        rep.check(
            "HTTP 500 receiver: 3 attempts, then dead",
            d5.get("status") == "dead" and d5.get("attempts") == 3 and len(f5) == 3,
            (summary["fail500"], len(f5)),
        )
        rep.check(
            "retry waits follow the configured backoff (base 2 s, cap 4 s, equal jitter: 1-2 s then 2-4 s, plus queue latency)",
            len(gaps) == 2 and 0.9 <= gaps[0] <= 4.5 and 1.9 <= gaps[1] <= 7,
            gaps,
        )
        rep.check(
            "same event id and delivery id on every retry (receiver can deduplicate)",
            len({x["headers"].get("Axentra-Event-Id") for x in f5}) == 1
            and len({x["headers"].get("Axentra-Delivery") for x in f5}) == 1,
        )
        rep.check(
            "response body of the failure is stored (truncated)",
            "synthetic receiver error" in (d5.get("response_body") or ""),
            d5.get("response_body"),
        )
        ds = results["slow"][0] if results["slow"] else {}
        rep.check(
            "slow receiver (6 s > 2 s timeout): timeouts, then dead",
            ds.get("status") == "dead" and ds.get("attempts") == 3,
            summary["slow"],
        )
        dr = results["refused"][0] if results["refused"] else {}
        rep.check(
            "connection refused: retried, then dead",
            dr.get("status") == "dead" and dr.get("attempts") == 3,
            summary["refused"],
        )
        dd = results["dns"][0] if results["dns"] else {}
        rep.check(
            "DNS failure: retried, then dead",
            dd.get("status") == "dead" and dd.get("attempts") == 3,
            summary["dns"],
        )
        drd = results["redirect"][0] if results["redirect"] else {}
        rep.check(
            "302 is not followed and counts as a failure",
            drd.get("status") == "dead" and not [x for x in hits("/ok") if "from=redirect" in x["path"]],
            summary["redirect"],
        )
        rep.check(
            "last_error carries no secret", not any(s in json.dumps(results) for s in secrets_seen.values())
        )

        # Redeliver a dead delivery after the receiver is "fixed" (PATCH url to /ok).
        ep = admin.ok("GET", f"{W}/{eps['fail500']['id']}")
        admin.ok(
            "PATCH",
            f"{W}/{eps['fail500']['id']}",
            json={"url": f"{R}/ok"},
            headers={"If-Match": f'"{ep["version"]}"'} if "version" in ep else {},
        )
        r = admin.post(f"{W}/{eps['fail500']['id']}/deliveries/{d5['id']}/redeliver")
        rep.check("redeliver a dead delivery -> 202", r.status_code == 202, f"{r.status_code} {r.text[:200]}")
        n_ok = len(hits("/ok"))
        run = subprocess.run(
            [PYTHON, "-m", "axentra.cli", "worker", "--once"],
            env=env,
            capture_output=True,
            text=True,
            timeout=120,
        )
        wlog.open("a").write(run.stdout + run.stderr)
        again = admin.ok("GET", f"{W}/{eps['fail500']['id']}/deliveries/{d5['id']}")
        rep.check(
            "redelivered to the fixed receiver -> succeeded",
            again["status"] == "succeeded" and len(hits("/ok")) == n_ok + 1,
            (again["status"], again["attempts"]),
        )

        # Secret rotation with grace: two v1 signatures, both valid.
        rot = admin.ok("POST", f"{W}/{eps['ok']['id']}/rotate-secret", json={"grace_seconds": 600})
        new_secret = rot["secret"]
        secrets_seen["ok-rotated"] = new_secret
        t = admin.ok("POST", f"{W}/{eps['ok']['id']}/test")
        last = hits("/ok")[-1]
        sig = last["headers"].get("Axentra-Signature", "")
        rep.check("test send (axentra.ping) succeeded synchronously", t["status"] == "succeeded", t["status"])
        rep.check(
            "after rotation with grace: two v1 signatures, new and old secret both verify",
            sig.count("v1=") == 2
            and verify(new_secret, sig, last["body"])
            and verify(secrets_seen["ok"], sig, last["body"]),
            sig.count("v1="),
        )

    # Phase 2: SSRF guard on (defaults), http still allowed so the address check is what refuses.
    env2 = {k: v for k, v in env.items() if k != "AXENTRA__EVENTS__WEBHOOK_ALLOW_PRIVATE_TARGETS"}
    with serve(env2, PORT, log):
        admin = Api(PORT)
        admin.login(ADMIN_EMAIL, ADMIN_PASSWORD)
        ssrf = {}
        for url in (
            f"{R}/ok",
            "http://localhost:19290/ok",
            "http://10.1.2.3/hook",
            "http://192.168.0.10/hook",
            "http://169.254.169.254/latest/meta-data/",
            "http://[::1]:19290/ok",
            "http://[::ffff:127.0.0.1]:19290/ok",
            "http://0.0.0.0:19290/ok",
            "http://metadata.internal/hook",
            "http://user:pw@example.com/hook",
        ):
            r = admin.post(f"/v1/products/{pid}/webhooks", json={"url": url, "event_types": ["lc.*"]})
            entry: dict[str, object] = {
                "create": r.status_code,
                "detail": (
                    r.json().get("detail")
                    if r.headers.get("content-type", "").startswith("application/")
                    else r.text
                )[:160],
            }
            if r.status_code == 201:
                wid = r.json()["endpoint"]["id"]
                n = len(HITS)
                t = admin.post(f"/v1/products/{pid}/webhooks/{wid}/test")
                entry["test"] = t.status_code
                if t.status_code == 200:
                    entry["delivery"] = {k: t.json().get(k) for k in ("status", "attempts", "last_error")}
                entry["receiver_hit"] = len(HITS) > n
            ssrf[url] = entry
        rep.save_json("ssrf", ssrf)
        for url, e in ssrf.items():
            blocked = e["create"] in (400, 422) or (e.get("delivery") or {}).get("status") in (
                "dead",
                "failed",
            )
            rep.check(f"SSRF guard blocks {url}", blocked and not e.get("receiver_hit"), e)
        # Existing endpoints that point at loopback: an event now ends dead without a request.
        n = len(HITS)
        admin.ok(
            "POST",
            f"/v1/products/{pid}/tenants/{tid}/events",
            json={"type": "lc.order.created", "data": {"order": "synthetic-2"}},
        )
        run = subprocess.run(
            [PYTHON, "-m", "axentra.cli", "worker", "--once"],
            env=env2,
            capture_output=True,
            text=True,
            timeout=120,
        )
        wlog.open("a").write(run.stdout + run.stderr)
        time.sleep(1)
        okd = admin.ok("GET", f"/v1/products/{pid}/webhooks/{eps['ok']['id']}/deliveries")["items"][0]
        rep.check(
            "guard on: delivery to an existing loopback endpoint is refused (dead, no request)",
            okd["status"] == "dead" and len(HITS) == n,
            (okd["status"], okd["attempts"], okd["last_error"]),
        )
    srv.shutdown()
    needles = {f"secret:{k}": v for k, v in secrets_seen.items()}
    for p in (log, wlog):
        h = scan_for_secrets(p, needles)
        rep.check(f"no webhook secret in {p.name}", not any(h.values()), h)
    rep.save_json(
        "receiver-hits",
        [{k: v for k, v in x.items() if k != "body"} | {"body": x["body"][:300]} for x in HITS],
    )
    return rep.finish()


if __name__ == "__main__":
    sys.exit(main())
