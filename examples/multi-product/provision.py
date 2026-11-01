"""Multi-product demo: two independent products on ONE Axentra installation.

    export AXENTRA_DEMO_ADMIN_PASSWORD='...' AXENTRA_DEMO_OPERATOR_PASSWORD='...'
    export AXENTRA_SETUP_TOKEN=axsetup_...       # only on a fresh installation
    python examples/multi-product/provision.py --base-url http://127.0.0.1:8080 \
        --config examples/multi-product/products.toml --create-users --secrets-out keys.env

1. Provisions every product of the config (idempotent): the product, its tenants, its operators
   (product members) and its API keys. New key secrets are printed or appended to --secrets-out.
2. Verifies the isolation between the products with short-lived probe keys and the operator
   sessions: a key or operator of one product must get 403/404 for everything of another product,
   and a tenant-bound key must get 404 for the other tenants of its own product.

Exit codes: 0 all checks passed, 1 at least one leak or unexpected answer, 2 provisioning failed.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass, field
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


@dataclass
class ProvisionedProduct:
    slug: str
    id: str
    tenants: dict[str, str]  # slug -> id
    operators: list[dict[str, str]]
    new_secrets: dict[str, str] = field(default_factory=dict)


def ensure_product(admin: Api, slug: str, name: str) -> str:
    for p in admin.ok("GET", "/v1/products", status=200):
        if p["slug"] == slug:
            return str(p["id"])
    return str(admin.ok("POST", "/v1/products", json={"slug": slug, "name": name})["id"])


def provision(
    new_client: ClientFactory, cfg: dict[str, Any], *, create_user: UserCreator | None, log: Any = print
) -> tuple[Api, list[ProvisionedProduct]]:
    meta = new_client().get("/v1/meta").json()
    if meta["mode"] != "multi":
        raise DemoError(f"this demo needs mode = 'multi', the server runs mode = {meta['mode']!r}")
    admin = admin_session(new_client, cfg, meta)
    op_password = secret_from_env(
        cfg.get("operators", {}).get("password_env", "AXENTRA_DEMO_OPERATOR_PASSWORD")
    )
    out = []
    for spec in cfg["products"]:
        pid = ensure_product(admin, spec["slug"], spec["name"])
        tenants = {slug: ensure_tenant(admin, pid, slug) for slug in spec.get("tenants", [])}
        for op in spec.get("operators", []):
            if create_user is not None:
                create_user(op["email"], op.get("name", ""), op_password)
            ensure_operator(admin, pid, op["email"], op["role"])
        prod = ProvisionedProduct(spec["slug"], pid, tenants, list(spec.get("operators", [])))
        for key in spec.get("api_keys", []):
            tid = tenants[key["tenant"]] if key.get("tenant") else None
            secret = ensure_api_key(admin, pid, key["name"], key["permissions"], tid)
            if secret:
                prod.new_secrets[f"{spec['slug']}/{key['name']}"] = secret
        log(
            f"product {spec['slug']} ({pid}): {len(tenants)} tenants, {len(prod.operators)} operators,"
            f" {len(spec.get('api_keys', []))} API keys ({len(prod.new_secrets)} new)"
        )
        out.append(prod)
    return admin, out


def verify(
    new_client: ClientFactory,
    admin: Api,
    products: list[ProvisionedProduct],
    op_password: str,
    *,
    log: Any = print,
) -> Checks:
    checks = Checks(log=log)
    probes: list[tuple[str, str]] = []  # (product id, key id) to revoke
    keys: dict[str, Api] = {}
    tenant_keys: dict[str, Api] = {}
    operators: dict[str, Api] = {}
    try:
        for p in products:
            kid, secret = probe_key(
                admin, p.id, ["tenants:read", "records:read", "records:write"], None, p.slug
            )
            probes.append((p.id, kid))
            keys[p.slug] = Api.with_key(new_client, secret, f"{p.slug} product key")
            first = next(iter(p.tenants.values()))
            kid, secret = probe_key(admin, p.id, ["records:read", "records:write"], first, f"{p.slug}-tenant")
            probes.append((p.id, kid))
            tenant_keys[p.slug] = Api.with_key(new_client, secret, f"{p.slug} tenant key")
            if p.operators:
                op = p.operators[0]
                operators[p.slug] = Api(new_client(), f"{p.slug} operator {op['email']}").login(
                    op["email"], op_password
                )
            # Positive checks first: every caller can work in its own product (else the denials prove nothing).
            for tid in p.tenants.values():
                checks.allowed(
                    keys[p.slug],
                    "POST",
                    f"/v1/products/{p.id}/tenants/{tid}/records/{PROBE_COLLECTION}",
                    "own product: write",
                    json={"product": p.slug},
                )
            checks.allowed(keys[p.slug], "GET", f"/v1/products/{p.id}/tenants", "own product: list tenants")
            checks.allowed(
                tenant_keys[p.slug],
                "GET",
                f"/v1/products/{p.id}/tenants/{first}/records/{PROBE_COLLECTION}",
                "own tenant: read",
            )
            if p.slug in operators:
                checks.allowed(
                    operators[p.slug], "GET", f"/v1/products/{p.id}/tenants", "operator: own tenants"
                )

        for a in products:
            # A tenant-bound key reaches no other tenant of its own product.
            for slug, tid in list(a.tenants.items())[1:]:
                checks.denied(
                    tenant_keys[a.slug],
                    "GET",
                    f"/v1/products/{a.id}/tenants/{tid}/records/{PROBE_COLLECTION}",
                    f"other tenant {slug} of the same product",
                )
            listed = keys[a.slug].ok("GET", "/v1/products", status=200)
            checks.expect(
                [p["id"] for p in listed] == [a.id], f"{a.slug} key lists only its product", leak=True
            )
            if a.slug in operators:
                listed = operators[a.slug].ok("GET", "/v1/products", status=200)
                checks.expect(
                    {p["id"] for p in listed} == {a.id},
                    f"{a.slug} operator lists only its product",
                    leak=True,
                )
            for b in products:
                if b.id == a.id:
                    continue
                tb = next(iter(b.tenants.values()))
                rec = f"/v1/products/{b.id}/tenants/{tb}/records/{PROBE_COLLECTION}"
                for caller in filter(None, (keys[a.slug], tenant_keys[a.slug], operators.get(a.slug))):
                    what = f"{a.slug} -> {b.slug}"
                    checks.denied(caller, "GET", f"/v1/products/{b.id}", what + ": product")
                    checks.denied(caller, "GET", f"/v1/products/{b.id}/tenants", what + ": tenants")
                    checks.denied(caller, "GET", f"/v1/products/{b.id}/tenants/{tb}", what + ": tenant")
                    checks.denied(caller, "GET", rec, what + ": read records")
                    checks.denied(caller, "POST", rec, what + ": write records", json={"x": 1})
                    checks.denied(caller, "GET", f"/v1/products/{b.id}/api-keys", what + ": API keys")
                    checks.denied(
                        caller,
                        "POST",
                        f"/v1/products/{b.id}/api-keys",
                        what + ": create API key",
                        json={"name": "x", "permissions": ["records:read"]},
                    )
                    checks.denied(caller, "GET", f"/v1/products/{b.id}/members", what + ": operators")
                    checks.denied(caller, "GET", "/v1/audit", what + ": audit", params={"product_id": b.id})
                    checks.denied(caller, "GET", "/v1/users", what + ": users", params={"product_id": b.id})
                op_api = operators.get(a.slug)
                if op_api is not None:
                    checks.denied(
                        op_api,
                        "POST",
                        f"/v1/products/{b.id}/tenants",
                        f"{a.slug} operator -> {b.slug}: create tenant",
                        json={"slug": "intruder", "name": "x"},
                    )
                    checks.denied(
                        op_api,
                        "POST",
                        f"/v1/products/{b.id}/members",
                        f"{a.slug} operator -> {b.slug}: add operator",
                        json={"email": a.operators[0]["email"], "role": "product_owner"},
                    )
            # Records written in product A are not visible to B's product key (data isolation).
            for b in products:
                if b.id == a.id:
                    continue
                for tid in b.tenants.values():
                    page = keys[b.slug].ok(
                        "GET", f"/v1/products/{b.id}/tenants/{tid}/records/{PROBE_COLLECTION}", status=200
                    )
                    foreign = [r for r in page["items"] if r["data"].get("product") != b.slug]
                    checks.expect(
                        not foreign, f"{b.slug} tenant {tid} sees no records of {a.slug}", leak=True
                    )
    finally:
        for pid, kid in probes:
            admin.request("POST", f"/v1/products/{pid}/api-keys/{kid}/revoke")
        for p in products:
            for tid in p.tenants.values():
                page = admin.request("GET", f"/v1/products/{p.id}/tenants/{tid}/records/{PROBE_COLLECTION}")
                for r in page.json().get("items", []) if page.status_code == 200 else []:
                    admin.request(
                        "DELETE", f"/v1/products/{p.id}/tenants/{tid}/records/{PROBE_COLLECTION}/{r['id']}"
                    )
    return checks


def run(
    new_client: ClientFactory,
    cfg: dict[str, Any],
    *,
    create_user: UserCreator | None = None,
    secrets_out: str | None = None,
    log: Any = print,
) -> tuple[list[ProvisionedProduct], Checks]:
    admin, products = provision(new_client, cfg, create_user=create_user, log=log)
    for p in products:
        write_secrets(secrets_out, p.new_secrets)
    op_password = secret_from_env(
        cfg.get("operators", {}).get("password_env", "AXENTRA_DEMO_OPERATOR_PASSWORD")
    )
    checks = verify(new_client, admin, products, op_password, log=log)
    log(checks.summary())
    return products, checks


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--base-url", default="http://127.0.0.1:8080")
    parser.add_argument("--config", default=str(Path(__file__).with_name("products.toml")))
    parser.add_argument(
        "--create-users",
        action="store_true",
        help="create missing operator accounts with the Axentra library (needs the server's AXENTRA_* settings)",
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
