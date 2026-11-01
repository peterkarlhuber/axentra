# Examples

These examples are tested. They run in the repository's `pytest` run against PostgreSQL. None of
them depends on Nodestro, orkexa or Axentra Studio.

| Directory | What it shows | Tests |
|---|---|---|
| [taskboard/](taskboard/) | A multi-tenant SaaS backend (projects, tasks, attachments, plans) that uses Axentra **as a library** and mounts the Axentra API under `/axentra` in the same process. It has its own tables in its own migration namespace with forced RLS. | `examples/taskboard/tests/` |
| [single-product/](single-product/) | One isolated Axentra installation for one product (`mode = "single"`). The config and an httpx script provision tenants, operators and API keys and check tenant isolation and the deployment-model rules. | `tests/integration/test_deployment_models.py` |
| [multi-product/](multi-product/) | One Axentra installation serving two independent products ("taskboard" and "invoicing"). The script provisions both, then asserts that keys and operators of one product cannot reach the other. It exits non-zero on any leak. | `tests/integration/test_deployment_models.py` |
| [common/](common/) | `axdemo.py`: the small httpx helpers that both deployment scripts share. | (via the above) |

Step-by-step guide for your own product: [docs/guides/BUILDING_A_PRODUCT.md](../docs/guides/BUILDING_A_PRODUCT.md).

## Library or HTTP?

- **Taskboard** is the library model. The product's Python backend imports `axentra.platform.Axentra`,
  calls the services with a `Principal` and keeps its own tables next to Axentra's. Login and
  administration come from the mounted Axentra API.
- **single-product / multi-product** are the HTTP model. Axentra runs as its own server
  (`axentra serve` or the container image). Products, frontends and scripts in any language use
  `/v1/...` with sessions or API keys.

## Running the deployment demos against a server

```bash
# 1. A server (development settings, local PostgreSQL)
createdb axentra_multi
export AXENTRA_CONFIG=examples/multi-product/axentra.toml
export AXENTRA__DATABASE__URL=postgresql://$USER@127.0.0.1:5432/axentra_multi
axentra migrate
export AXENTRA_SETUP_TOKEN=$(axentra admin setup-token)
axentra serve &                                  # http://127.0.0.1:8080

# 2. The demo (same shell: --create-users uses the same AXENTRA_* settings)
export AXENTRA_DEMO_ADMIN_PASSWORD='choose a long admin passphrase'
export AXENTRA_DEMO_OPERATOR_PASSWORD='choose a long operator passphrase'
python examples/multi-product/provision.py --create-users --secrets-out multi-keys.env
echo $?                                          # 0: no leaks; 1: leak or unexpected answer; 2: setup failed
```

`examples/single-product` works the same way with `examples/single-product/axentra.toml` and
`provision.py`. Both scripts are idempotent. A second run creates nothing and checks again.

Why `--create-users`: Axentra's HTTP API has no endpoint that creates arbitrary user accounts.
Accounts come from the first-run setup, OIDC sign-up, or a product backend's signup (like
Taskboard's `POST /api/signup`). The scripts therefore create the operator accounts with the
Axentra library, using the server's settings. Without the flag the accounts must already exist.
