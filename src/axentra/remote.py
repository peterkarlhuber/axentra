"""``axentra remote``: administration over the HTTP API, without database access.

The CLI's other commands talk to PostgreSQL directly and need the configuration with the database
URL and keyring. ``axentra remote`` needs only the API's base URL and a credential, so operators
can manage products, tenants, API keys and users from any machine that reaches the API, with the
API's own permission checks and audit trail.

The credential never goes on the command line (it would show in ``ps`` and shell history):

- ``AXENTRA_API_KEY`` (or ``--api-key-file``): an API key, sent as ``Authorization: Bearer``;
- ``AXENTRA_SESSION_TOKEN`` (or ``--session-token-file``): a user session (for example a platform
  admin's), sent the same way. ``axentra remote login`` signs in with email and password (prompted)
  and prints such a token.

Only the standard library is used (``urllib``), so the command works with the core install.
Answers are printed as JSON; an error answer prints ``axentra: <code>: <detail>`` and exits with 2.
"""

from __future__ import annotations

import argparse
from collections.abc import Mapping
from dataclasses import dataclass
import getpass
import json
import os
from pathlib import Path
import sys
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode, urlsplit
import urllib.request

from axentra._version import __version__

#: Session cookie names of Axentra (``__Host-`` in production, plain otherwise).
_SESSION_COOKIES = ("__Host-axentra-session", "axentra-session")
DEFAULT_TIMEOUT_SECONDS = 30.0


class RemoteError(Exception):
    """An error answer of the API (``code`` from the problem details) or a transport failure."""

    def __init__(self, code: str, detail: str, status: int | None = None) -> None:
        super().__init__(detail)
        self.code = code
        self.detail = detail
        self.status = status


@dataclass
class RemoteClient:
    base_url: str
    token: str | None = None
    timeout: float = DEFAULT_TIMEOUT_SECONDS

    def __post_init__(self) -> None:
        parts = urlsplit(self.base_url)
        if parts.scheme not in ("http", "https") or not parts.hostname:
            raise RemoteError(
                "invalid_url", "the API URL must be an absolute http(s) URL, e.g. https://api.example.com"
            )
        self.base_url = self.base_url.rstrip("/")

    def request(
        self,
        method: str,
        path: str,
        *,
        body: Any = None,
        params: Mapping[str, Any] | None = None,
        authenticate: bool = True,
    ) -> tuple[Any, list[tuple[str, str]]]:
        """Send one request; returns the decoded JSON body (``None`` for 204) and the headers."""
        query = {k: v for k, v in (params or {}).items() if v is not None}
        url = self.base_url + path + (("?" + urlencode(query, doseq=True)) if query else "")
        headers = {"Accept": "application/json", "User-Agent": f"axentra-cli/{__version__}"}
        if authenticate and self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        data = None
        if body is not None:
            data = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(url, data=data, method=method, headers=headers)  # noqa: S310  # nosec B310
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:  # noqa: S310  # nosec B310
                raw = resp.read()
                return (json.loads(raw) if raw else None), list(resp.headers.items())
        except HTTPError as exc:
            raise _problem(exc) from None
        except URLError as exc:
            raise RemoteError("api_unreachable", f"{self.base_url}: {exc.reason}") from None
        except TimeoutError:
            raise RemoteError("api_unreachable", f"{self.base_url}: timed out") from None


def _problem(exc: HTTPError) -> RemoteError:
    try:
        problem = json.loads(exc.read() or b"{}")
    except ValueError:
        problem = {}
    if not isinstance(problem, dict):
        problem = {}
    code = str(problem.get("code") or f"http_{exc.code}")
    detail = str(problem.get("detail") or problem.get("title") or exc.reason)
    request_id = problem.get("request_id")
    if request_id:
        detail += f" (request {request_id})"
    return RemoteError(code, detail, exc.code)


def _session_token(headers: list[tuple[str, str]]) -> str | None:
    for name, value in headers:
        if name.lower() != "set-cookie":
            continue
        key, _, token = value.split(";", 1)[0].strip().partition("=")
        if key in _SESSION_COOKIES and token:
            return token.strip('"')
    return None


def _read_secret_file(path: str) -> str:
    value = Path(path).read_text(encoding="utf-8").strip()
    if not value:
        raise RemoteError("missing_credential", f"{path} is empty")
    return value


def _client(args: argparse.Namespace, *, credential: bool = True) -> RemoteClient:
    url = args.url or os.environ.get("AXENTRA_URL", "")
    if not url:
        raise RemoteError("invalid_url", "pass --url or set AXENTRA_URL to the API's base URL")
    token: str | None = None
    if credential:
        if args.api_key_file:
            token = _read_secret_file(args.api_key_file)
        elif args.session_token_file:
            token = _read_secret_file(args.session_token_file)
        else:
            token = os.environ.get("AXENTRA_API_KEY") or os.environ.get("AXENTRA_SESSION_TOKEN")
        if not token:
            raise RemoteError(
                "missing_credential",
                "set AXENTRA_API_KEY or AXENTRA_SESSION_TOKEN (or pass --api-key-file / --session-token-file);"
                " `axentra remote login` prints a session token",
            )
    return RemoteClient(url, token, timeout=args.timeout)


def _p(*parts: str) -> str:
    return "/".join(quote(part, safe="") for part in parts)


def _print(value: Any) -> int:
    print(json.dumps(value, indent=2, sort_keys=False))
    return 0


# -- commands --------------------------------------------------------------------------------------


def cmd_login(args: argparse.Namespace) -> int:
    client = _client(args, credential=False)
    password = os.environ.get("AXENTRA_PASSWORD") or getpass.getpass("Password: ")
    body, headers = client.request(
        "POST",
        "/v1/auth/login/password",
        body={"email": args.email, "password": password},
        authenticate=False,
    )
    token = _session_token(headers)
    if not token:
        raise RemoteError("no_session", "the server answered without a session cookie")
    # Only the token on stdout, so that `export AXENTRA_SESSION_TOKEN=$(axentra remote login ...)` works.
    print(token)
    user = (body or {}).get("user") or {}
    print(
        f"signed in as {user.get('email') or user.get('id')}; the session expires at {body.get('expires_at')}",
        file=sys.stderr,
    )
    return 0


def cmd_meta(args: argparse.Namespace) -> int:
    return _print(_client(args, credential=False).request("GET", "/v1/meta", authenticate=False)[0])


def cmd_whoami(args: argparse.Namespace) -> int:
    me = _client(args).request("GET", "/v1/me")[0]
    return _print({k: me.get(k) for k in ("user", "actor_kind", "platform_role", "platform_permissions")})


def cmd_products(args: argparse.Namespace) -> int:
    c = _client(args)
    if args.action == "list":
        return _print(c.request("GET", "/v1/products")[0])
    if args.action == "get":
        return _print(c.request("GET", "/v1/products/" + _p(args.product_id))[0])
    if args.action == "create":
        body = {"slug": args.slug, "name": args.name, "description": args.description or ""}
        return _print(c.request("POST", "/v1/products", body=body)[0])
    if args.action in ("archive", "restore"):
        return _print(c.request("POST", "/v1/products/" + _p(args.product_id, args.action))[0])
    raise AssertionError(args.action)  # pragma: no cover - argparse restricts the choices


def cmd_tenants(args: argparse.Namespace) -> int:
    c = _client(args)
    base = "/v1/products/" + _p(args.product_id, "tenants")
    if args.action == "list":
        params = {
            "q": args.q,
            "status": args.status,
            "limit": args.limit,
            "cursor": args.cursor,
            "sort": args.sort,
        }
        return _print(c.request("GET", base, params=params)[0])
    if args.action == "get":
        return _print(c.request("GET", base + "/" + _p(args.tenant_id))[0])
    if args.action == "create":
        return _print(c.request("POST", base, body={"slug": args.slug, "name": args.name})[0])
    if args.action in ("suspend", "activate"):
        status = "suspended" if args.action == "suspend" else "active"
        return _print(c.request("PATCH", base + "/" + _p(args.tenant_id), body={"status": status})[0])
    raise AssertionError(args.action)  # pragma: no cover


def cmd_keys(args: argparse.Namespace) -> int:
    c = _client(args)
    base = "/v1/products/" + _p(args.product_id, "api-keys")
    if args.action == "list":
        return _print(c.request("GET", base)[0])
    if args.action == "create":
        body: dict[str, Any] = {"name": args.name, "permissions": args.permission}
        if args.tenant_id:
            body["tenant_id"] = args.tenant_id
        if args.expires_at:
            body["expires_at"] = args.expires_at
        return _print(c.request("POST", base, body=body)[0])
    if args.action == "revoke":
        return _print(c.request("POST", base + "/" + _p(args.key_id, "revoke"))[0])
    if args.action == "rotate":
        body = {"grace_seconds": args.grace_seconds}
        return _print(c.request("POST", base + "/" + _p(args.key_id, "rotate"), body=body)[0])
    raise AssertionError(args.action)  # pragma: no cover


def cmd_users(args: argparse.Namespace) -> int:
    c = _client(args)
    if args.action == "list":
        params = {"q": args.q, "product_id": args.product_id, "limit": args.limit, "cursor": args.cursor}
        return _print(c.request("GET", "/v1/users", params=params)[0])
    path = "/v1/users/" + _p(args.user_id)
    if args.action in ("disable", "enable"):
        status = "disabled" if args.action == "disable" else "active"
        return _print(c.request("PATCH", path, body={"status": status})[0])
    if args.action == "revoke-sessions":
        return _print(c.request("POST", path + "/sessions/revoke")[0])
    raise AssertionError(args.action)  # pragma: no cover


def add_parser(sub: Any) -> None:
    """Register ``axentra remote ...`` on the CLI's sub-command parser."""
    r = sub.add_parser(
        "remote",
        help="administration over the HTTP API (no database access; credential from AXENTRA_API_KEY"
        " or AXENTRA_SESSION_TOKEN)",
    )
    r.add_argument("--url", help="API base URL (default: AXENTRA_URL)")
    cred = r.add_mutually_exclusive_group()
    cred.add_argument("--api-key-file", metavar="PATH", help="read the API key from this file")
    cred.add_argument("--session-token-file", metavar="PATH", help="read a session token from this file")
    r.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT_SECONDS, help="seconds per request")
    rsub = r.add_subparsers(dest="remote_command", required=True)

    lg = rsub.add_parser("login", help="sign in with email and password (prompted) and print a session token")
    lg.add_argument("email")
    lg.set_defaults(func=cmd_login)
    rsub.add_parser("meta", help="server version, API version, mode").set_defaults(func=cmd_meta)
    rsub.add_parser("whoami", help="who the credential belongs to").set_defaults(func=cmd_whoami)

    pr = rsub.add_parser("products", help="products (platform admins create, archive and restore)")
    prs = pr.add_subparsers(dest="action", required=True)
    prs.add_parser("list")
    for name in ("get", "archive", "restore"):
        prs.add_parser(name).add_argument("product_id")
    pc = prs.add_parser("create")
    pc.add_argument("slug")
    pc.add_argument("name")
    pc.add_argument("--description")
    pr.set_defaults(func=cmd_products)

    tn = rsub.add_parser("tenants", help="tenants of a product")
    tns = tn.add_subparsers(dest="action", required=True)
    tl = tns.add_parser("list")
    tl.add_argument("product_id")
    tl.add_argument("--q")
    tl.add_argument("--status", choices=["active", "suspended"])
    tl.add_argument("--limit", type=int)
    tl.add_argument("--cursor")
    tl.add_argument("--sort", choices=["id", "name"])
    for name in ("get", "suspend", "activate"):
        t = tns.add_parser(name)
        t.add_argument("product_id")
        t.add_argument("tenant_id")
    tc = tns.add_parser("create")
    tc.add_argument("product_id")
    tc.add_argument("slug")
    tc.add_argument("name")
    tn.set_defaults(func=cmd_tenants)

    ky = rsub.add_parser("keys", help="API keys of a product (a created or rotated secret is printed once)")
    kys = ky.add_subparsers(dest="action", required=True)
    kys.add_parser("list").add_argument("product_id")
    kc = kys.add_parser("create")
    kc.add_argument("product_id")
    kc.add_argument("name")
    kc.add_argument("--permission", action="append", required=True, help="repeat for several")
    kc.add_argument("--tenant-id", help="bind the key to one tenant")
    kc.add_argument("--expires-at", help="RFC 3339 timestamp")
    for name in ("revoke", "rotate"):
        k = kys.add_parser(name)
        k.add_argument("product_id")
        k.add_argument("key_id")
        if name == "rotate":
            k.add_argument("--grace-seconds", type=int, default=0)
    ky.set_defaults(func=cmd_keys)

    us = rsub.add_parser("users", help="users (platform users:read / users:manage)")
    uss = us.add_subparsers(dest="action", required=True)
    ul = uss.add_parser("list")
    ul.add_argument("--q")
    ul.add_argument("--product-id")
    ul.add_argument("--limit", type=int)
    ul.add_argument("--cursor")
    for name in ("disable", "enable", "revoke-sessions"):
        uss.add_parser(name).add_argument("user_id")
    us.set_defaults(func=cmd_users)
