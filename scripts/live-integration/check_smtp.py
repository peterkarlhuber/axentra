"""Live SMTP check: Axentra's SmtpProvider against Mailpit with TLS (synthetic data only).

Needs (see compose.yml): ``mailpit-starttls`` (SMTP 19125 with STARTTLS required + AUTH, API 19126) and
``mailpit-tls`` (implicit TLS on 19465, API 19127), both serving a certificate signed by the throwaway
CA in ``$LC_CERTS/ca.pem`` (``make_certs.sh``).

Flow: a real ``axentra serve`` enqueues an invitation, a password reset and an email verification;
``axentra notify-dispatch --once`` (a separate process, like production) delivers them:

1. without ``smtp_ca_file`` (system CAs only): the self-signed chain must be refused, nothing delivered;
2. against the implicit-TLS port: documents the current behaviour (implicit TLS is not implemented);
3. with ``smtp_ca_file`` = the test CA: all three messages arrive in Mailpit, links work (the reset and
   verification tokens are confirmed through the API), and no token or the SMTP password is in any log.
"""

from __future__ import annotations

import os
from pathlib import Path
import re
import smtplib
import ssl
import sys
import time

import httpx
from lib import (
    ADMIN_EMAIL,
    EVIDENCE,
    Report,
    base_env,
    bootstrap_admin,
    product_and_tenant,
    reset_database,
    run_cli,
    scan_for_secrets,
    serve,
)

PORT = int(os.environ.get("LC_SMTP_AX_PORT", "19201"))
CERTS = Path(os.environ["LC_CERTS"])
SMTP_PASSWORD = os.environ.get("LC_SMTP_PASSWORD", "lc-smtp-Secr3t-synthetic")
STARTTLS_PORT, STARTTLS_API = 19125, "http://127.0.0.1:19126"
TLS_PORT, TLS_API = 19465, "http://127.0.0.1:19127"
TOKEN_RE = re.compile(r"ax(?:inv|pwr|emv)_[A-Za-z0-9_\-]+")


def mailpit_messages(api: str) -> list[dict]:
    r = httpx.get(f"{api}/api/v1/messages", timeout=10)
    r.raise_for_status()
    return r.json().get("messages") or []


def mailpit_message(api: str, mid: str) -> dict:
    r = httpx.get(f"{api}/api/v1/message/{mid}", timeout=10)
    r.raise_for_status()
    body = r.json()
    h = httpx.get(f"{api}/api/v1/message/{mid}/headers", timeout=10)
    h.raise_for_status()
    body["Headers"] = h.json()
    return body


def main() -> int:
    rep = Report("smtp")
    log = EVIDENCE / "smtp-serve.log"
    dlog = EVIDENCE / "smtp-dispatch.log"
    for p in (log, dlog):
        p.unlink(missing_ok=True)
    for api in (STARTTLS_API, TLS_API):
        httpx.delete(f"{api}/api/v1/messages", timeout=10)

    db = reset_database("lc_smtp")
    smtp_env = {
        "AXENTRA__NOTIFY__PROVIDER": "smtp",
        "AXENTRA__NOTIFY__SENDER": "LC Axentra <no-reply@lc.example.com>",
        "AXENTRA__NOTIFY__SMTP_HOST": "localhost",
        "AXENTRA__NOTIFY__SMTP_PORT": str(STARTTLS_PORT),
        "AXENTRA__NOTIFY__SMTP_STARTTLS": "true",
        "AXENTRA__NOTIFY__SMTP_USERNAME": "lcmailer",
        "AXENTRA__NOTIFY__SMTP_PASSWORD_REF": "env:LC_SMTP_PASSWORD",
        "AXENTRA__NOTIFY__SMTP_TIMEOUT_SECONDS": "5",
        "AXENTRA__NOTIFY__BACKOFF_BASE_SECONDS": "0",
        "AXENTRA__NOTIFY__BACKOFF_MAX_SECONDS": "0",
        "LC_SMTP_PASSWORD": SMTP_PASSWORD,
    }
    env = base_env(db, PORT, **smtp_env)
    tokens: dict[str, str] = {}
    with serve(env, PORT, log):
        admin = bootstrap_admin(env, PORT, log)
        pid, tid = product_and_tenant(admin)
        admin.ok(
            "POST",
            f"/v1/products/{pid}/tenants/{tid}/members",
            json={"email": ADMIN_EMAIL, "role": "tenant_admin"},
        )
        inv = admin.ok(
            "POST",
            f"/v1/products/{pid}/tenants/{tid}/invitations",
            json={"email": "invitee@lc.example.com", "role": "member"},
        )
        tokens["invitation"] = inv["token"]
        r = admin.post("/v1/auth/password-reset", json={"email": ADMIN_EMAIL, "product_id": pid})
        rep.check("password reset request answers 202", r.status_code == 202, r.status_code)
        r = admin.post("/v1/me/email-verification", json={"product_id": pid})
        rep.check(
            "email verification request answers 202", r.status_code == 202, f"{r.status_code} {r.text[:200]}"
        )
        time.sleep(2)  # the reset is enqueued after the response (background task)
        msgs = admin.ok("GET", f"/v1/products/{pid}/notify/messages")["items"]
        rep.check("three messages queued", len(msgs) == 3, [(m["template_key"], m["status"]) for m in msgs])

        # 1. Untrusted certificate: no smtp_ca_file -> system CAs -> must fail verification.
        untrusted = dict(env)
        run_cli(untrusted, "notify-dispatch", "--once", log=dlog)
        msgs = admin.ok("GET", f"/v1/products/{pid}/notify/messages")["items"]
        errs = {m["last_error"] for m in msgs}
        rep.check(
            "untrusted CA: all messages stay queued with a certificate verification error",
            all(
                m["status"] == "queued" and "CERTIFICATE_VERIFY_FAILED" in (m["last_error"] or "")
                for m in msgs
            ),
            errs,
        )
        rep.check("untrusted CA: Mailpit received nothing", mailpit_messages(STARTTLS_API) == [])

        # 2. Implicit TLS (SMTPS) port with the trusted CA: Axentra has no implicit-TLS mode.
        implicit = dict(
            env, AXENTRA__NOTIFY__SMTP_PORT=str(TLS_PORT), AXENTRA__NOTIFY__SMTP_CA_FILE=str(CERTS / "ca.pem")
        )
        t0 = time.monotonic()
        run_cli(implicit, "notify-dispatch", "--once", log=dlog)
        msgs = admin.ok("GET", f"/v1/products/{pid}/notify/messages")["items"]
        rep.note(
            f"implicit TLS port {TLS_PORT} with smtp_starttls=true: dispatch took {time.monotonic() - t0:.1f}s,"
            f" last_error={sorted({m['last_error'] for m in msgs})}"
        )
        rep.check(
            "implicit TLS: not supported, fails cleanly (message retried, nothing delivered, no plaintext sent)",
            all(m["status"] == "queued" for m in msgs) and mailpit_messages(TLS_API) == [],
        )
        # Control: the implicit-TLS Mailpit itself works with a TLS-from-the-first-byte client.
        ctx = ssl.create_default_context(cafile=str(CERTS / "ca.pem"))
        with smtplib.SMTP_SSL("localhost", TLS_PORT, context=ctx, timeout=10) as s:
            s.login("lcmailer", SMTP_PASSWORD)
            s.sendmail("probe@lc.example.com", ["probe@lc.example.com"], b"Subject: control\r\n\r\ncontrol")
        rep.check(
            "control: Mailpit implicit TLS accepts smtplib.SMTP_SSL (server side is fine)",
            len(mailpit_messages(TLS_API)) == 1,
        )

        # 3. Trusted CA, STARTTLS, verification on (ssl.create_default_context(cafile=...)).
        trusted = dict(env, AXENTRA__NOTIFY__SMTP_CA_FILE=str(CERTS / "ca.pem"))
        run_cli(trusted, "notify-dispatch", "--once", log=dlog)
        msgs = admin.ok("GET", f"/v1/products/{pid}/notify/messages")["items"]
        rep.check(
            "trusted CA: all messages sent",
            all(m["status"] == "sent" for m in msgs),
            [(m["template_key"], m["status"], m["attempts"]) for m in msgs],
        )
        rep.check(
            "sensitive content is not readable through the API after sending",
            all(
                m.get("content") is None and m["content_state"] in ("redacted", "purged", "none")
                for m in msgs
            ),
            sorted({m["content_state"] for m in msgs}),
        )
        mails = mailpit_messages(STARTTLS_API)
        rep.check("Mailpit (STARTTLS) received 3 messages", len(mails) == 3, [m["Subject"] for m in mails])
        full = [mailpit_message(STARTTLS_API, m["ID"]) for m in mails]
        rep.save_json(
            "mailpit-messages",
            [{k: f.get(k) for k in ("Subject", "From", "To", "MessageID", "Text", "Headers")} for f in full],
        )
        by_kind: dict[str, dict] = {}
        for f in full:
            found = TOKEN_RE.findall(f.get("Text") or "")
            kind = {"axinv": "invitation", "axpwr": "password_reset", "axemv": "email_verification"}.get(
                found[0][:5] if found else "", "?"
            )
            by_kind[kind] = f
            if kind == "password_reset":
                tokens["password_reset"] = found[0]
            if kind == "email_verification":
                tokens["email_verification"] = found[0]
        rep.check(
            "one email per kind",
            set(by_kind) == {"invitation", "password_reset", "email_verification"},
            sorted(by_kind),
        )
        inv_mail = by_kind.get("invitation", {})
        rep.check(
            "invitation email carries the invitation token and the accept link",
            tokens["invitation"] in (inv_mail.get("Text") or "")
            and f"http://127.0.0.1:{PORT}/accept-invitation?token=" in (inv_mail.get("Text") or ""),
        )
        rep.check(
            "reset link points to account_url/reset-password",
            f"http://127.0.0.1:{PORT}/reset-password?token="
            in (by_kind.get("password_reset", {}).get("Text") or ""),
        )
        hdrs = (by_kind.get("invitation") or {}).get("Headers") or {}
        rep.check(
            "Auto-Submitted header set",
            hdrs.get("Auto-Submitted") == ["auto-generated"],
            hdrs.get("Auto-Submitted"),
        )
        rep.check(
            "Message-ID uses the sender domain",
            "@lc.example.com" in (inv_mail.get("MessageID") or ""),
            inv_mail.get("MessageID"),
        )

        # The tokens from the real emails work (end-to-end proof).
        if "email_verification" in tokens:
            r = admin.post(
                "/v1/auth/email-verification/confirm", json={"token": tokens["email_verification"]}
            )
            rep.check(
                "verification token from the email confirms the address", r.status_code == 204, r.status_code
            )
        if "password_reset" in tokens:
            r = admin.post(
                "/v1/auth/password-reset/confirm",
                json={"token": tokens["password_reset"], "new_password": "lc new synthetic password 2"},
            )
            rep.check("reset token from the email sets a new password", r.status_code == 204, r.status_code)
            r = httpx.post(
                f"http://127.0.0.1:{PORT}/v1/auth/login/password",
                headers={"Origin": f"http://127.0.0.1:{PORT}"},
                json={"email": ADMIN_EMAIL, "password": "lc new synthetic password 2"},
            )
            rep.check("login with the new password works", r.status_code == 200, r.status_code)
        time.sleep(1)

    needles = {f"token:{k}": v for k, v in tokens.items()} | {"smtp_password": SMTP_PASSWORD}
    for p in (log, dlog):
        hits = scan_for_secrets(p, needles)
        rep.check(f"no token / SMTP password in {p.name}", not any(hits.values()), hits)
    starttls_logs = httpx.get(f"{STARTTLS_API}/api/v1/messages", timeout=10).json()
    rep.save_json(
        "mailpit-summary",
        {
            "total": starttls_logs.get("total"),
            "subjects": [m["Subject"] for m in starttls_logs.get("messages") or []],
        },
    )
    return rep.finish()


if __name__ == "__main__":
    sys.exit(main())
