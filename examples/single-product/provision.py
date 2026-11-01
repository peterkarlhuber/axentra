"""Single-product demo: one isolated Axentra installation that serves exactly one product.

    export AXENTRA_DEMO_ADMIN_PASSWORD='...' AXENTRA_DEMO_OPERATOR_PASSWORD='...'
    export AXENTRA_SETUP_TOKEN=axsetup_...       # only on a fresh installation
    python examples/single-product/provision.py --base-url http://127.0.0.1:8080 \
        --config examples/single-product/product.toml --create-users

1. Checks the deployment model: ``/v1/meta`` reports ``mode: single`` and the configured product,
   creating or archiving products is refused (``409 mode_not_supported``), and every caller
   sees exactly that one product.
2. Provisions tenants, operators and API keys of the product (idempotent).
3. Verifies tenant isolation inside the product: a tenant-bound key gets 404 for the other
   tenants, and API keys never reach platform endpoints.

Exit codes: 0 all checks passed, 1 at least one leak or unexpected answer, 2 provisioning failed.
"""

from __future__ import annotations

import argparse
from pathlib import Path
import sys
from typing import Any

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "common"))

from axdemo import (
    Api,
    Checks,
    ClientFactory,
    DemoError,
    UserCreator,
    admin_session,
    ensure_api_key,
    ensure_operator,
    ensure_tenant,
    library_user_creator,
    load_config,
    probe_key,
    secret_from_env,
    write_secrets,
)

PROBE_COLLECTION = "isolation_probe"


def run(
    new_client: ClientFactory,
    cfg: dict[str, Any],
    *,
    create_user: UserCreator | None = None,
    secrets_out: str | None = None,
    log: Any = print,
) -> tuple[dict[str, Any], Checks]:
    spec = cfg["product"]
    meta = new_client().get("/v1/meta").json()
    if meta["mode"] != "single":
        raise DemoError(f"this demo needs mode = 'single', the server runs mode = {meta['mode']!r}")
    if not meta["product"] or meta["product"]["slug"] != spec["slug"]:
        raise DemoError(f"the server serves product {meta['product']!r}, the config expects {spec['slug']!r}")
    pid = meta["product"]["id"]
    admin = admin_session(new_client, cfg, meta)
    checks = Checks(log=log)

    # The deployment model itself.
    r = admin.request("POST", "/v1/products", json={"slug": "second", "name": "Second"})
    checks.expect(
        r.status_code == 409 and r.json().get("code") == "mode_not_supported",
        f"creating a second product is refused (got {r.status_code})",
        leak=r.status_code < 300,
    )
    r = admin.request("POST", f"/v1/products/{pid}/archive")
    checks.expect(r.status_code == 409, f"archiving the only product is refused (got {r.status_code})")

    # Provisioning (idempotent).
    op_password = secret_from_env(
        cfg.get("operators", {}).get("password_env", "AXENTRA_DEMO_OPERATOR_PASSWORD")
    )
    tenants = {slug: ensure_tenant(admin, pid, slug) for slug in spec.get("tenants", [])}
    for op in spec.get("operators", []):
        if create_user is not None:
            create_user(op["email"], op.get("name", ""), op_password)
        ensure_operator(admin, pid, op["email"], op["role"])
    secrets: dict[str, str] = {}
    for key in spec.get("api_keys", []):
        secret = ensure_api_key(
            admin, pid, key["name"], key["permissions"], tenants[key["tenant"]] if key.get("tenant") else None
        )
        if secret:
            secrets[f"{spec['slug']}/{key['name']}"] = secret
    write_secrets(secrets_out, secrets)
    log(
        f"product {spec['slug']} ({pid}): {len(tenants)} tenants, {len(spec.get('operators', []))} operators, {len(secrets)} new keys"
    )

    # Isolation inside the product.
    probes: list[str] = []
    try:
        kid, secret = probe_key(
            admin, pid, ["tenants:read", "records:read", "records:write"], None, "product"
        )
        probes.append(kid)
        product_key = Api.with_key(new_client, secret, "product key")
        (first_slug, first), *others = tenants.items()
        kid, secret = probe_key(admin, pid, ["records:read", "records:write"], first, first_slug)
        probes.append(kid)
        tenant_key = Api.with_key(new_client, secret, f"{first_slug} tenant key")
        callers = [admin, product_key, tenant_key]
        if spec.get("operators"):
            op = spec["operators"][0]
            callers.append(Api(new_client(), f"operator {op['email']}").login(op["email"], op_password))

        for caller in callers:
            listed = caller.ok("GET", "/v1/products", status=200)
            checks.expect(
                [p["id"] for p in listed] == [pid], f"{caller.label} sees exactly the one product", leak=True
            )
        for tid in tenants.values():
            checks.allowed(
                product_key,
                "POST",
                f"/v1/products/{pid}/tenants/{tid}/records/{PROBE_COLLECTION}",
                "product key writes in every tenant",
                json={"tenant": tid},
            )
        rec = f"/v1/products/{pid}/tenants/{first}/records/{PROBE_COLLECTION}"
        own = checks.allowed(tenant_key, "GET", rec, "tenant key reads its tenant")
        if own.status_code == 200:
            seen = {r["data"]["tenant"] for r in own.json()["items"]}
            checks.expect(seen == {first}, f"tenant {first_slug} sees only its own records", leak=True)
        for slug, tid in others:
            other = f"/v1/products/{pid}/tenants/{tid}/records/{PROBE_COLLECTION}"
            checks.denied(tenant_key, "GET", other, f"{first_slug} key -> tenant {slug}: read")
            checks.denied(
                tenant_key, "POST", other, f"{first_slug} key -> tenant {slug}: write", json={"x": 1}
            )
            checks.denied(
                tenant_key, "GET", f"/v1/products/{pid}/tenants/{tid}", f"{first_slug} key -> tenant {slug}"
            )
        for key in (product_key, tenant_key):
            checks.denied(key, "GET", "/v1/users", "API keys never hold platform permissions")
            checks.denied(key, "GET", "/v1/audit", "API keys cannot read the platform audit")
            checks.denied(
                key,
                "POST",
                f"/v1/products/{pid}/api-keys",
                "keys cannot mint keys",
                json={"name": "x", "permissions": ["records:read"]},
            )
    finally:
        for kid in probes:
            admin.request("POST", f"/v1/products/{pid}/api-keys/{kid}/revoke")
        for tid in tenants.values():
            page = admin.request("GET", f"/v1/products/{pid}/tenants/{tid}/records/{PROBE_COLLECTION}")
            for r in page.json().get("items", []) if page.status_code == 200 else []:
                admin.request(
                    "DELETE", f"/v1/products/{pid}/tenants/{tid}/records/{PROBE_COLLECTION}/{r['id']}"
                )
    log(checks.summary())
    return {"product_id": pid, "tenants": tenants, "new_secrets": secrets}, checks


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--base-url", default="http://127.0.0.1:8080")
    parser.add_argument("--config", default=str(Path(__file__).with_name("product.toml")))
    parser.add_argument(
        "--create-users", action="store_true", help="create missing operator accounts (library)"
    )
    parser.add_argument("--secrets-out", help="append new API key secrets to this file (mode 0600)")
    args = parser.parse_args(argv)
    try:
        _, checks = run(
            lambda: httpx.Client(base_url=args.base_url, timeout=30),
            load_config(args.config),
            create_user=library_user_creator() if args.create_users else None,
            secrets_out=args.secrets_out,
        )
    except (DemoError, httpx.HTTPError) as exc:
        print(f"provisioning failed: {exc}", file=sys.stderr)
        return 2
    return checks.exit_code


if __name__ == "__main__":
    sys.exit(main())
