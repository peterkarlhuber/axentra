# Generated from _async/client.py by scripts/unasync.py. Do not edit; edit the async source.
"""The synchronous Axentra client.

Generated from ``axentra_client/_async/client.py`` by ``scripts/unasync.py``; edit the async
source and regenerate. See that module for how to add endpoints.
"""

from __future__ import annotations

from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from datetime import datetime
from decimal import Decimal
from http.cookiejar import CookieJar, DefaultCookiePolicy
import os
from pathlib import Path
from types import TracebackType
from typing import IO, Any, TypeVar

import httpx
from pydantic import BaseModel, TypeAdapter

from axentra_client._base import (
    CSRF_HEADER,
    DEFAULT_TIMEOUT,
    api_error,
    assert_compatible,
    base_headers,
    check_idempotency_key,
    if_match,
    new_idempotency_key,
    query,
    session_token_from,
)
from axentra_client.models import (
    ApiKey,
    AuditEvent,
    DownloadUrl,
    EffectiveLimit,
    Entitlements,
    FileInfo,
    Invitation,
    Me,
    Membership,
    Message,
    Meta,
    Meter,
    MeterUsage,
    NewApiKey,
    NewInvitation,
    Page,
    Plan,
    Product,
    ProductMember,
    Record,
    Role,
    Session,
    SessionInfo,
    Subscription,
    Tenant,
    UsageEvent,
    UsageRecordResult,
    User,
)

M = TypeVar("M", bound=BaseModel)
Json = dict[str, Any]
FileContent = bytes | IO[bytes] | str | os.PathLike[str]

_adapters: dict[Any, TypeAdapter[Any]] = {}


def _parse(model: Any, data: Any) -> Any:
    adapter = _adapters.get(model)
    if adapter is None:
        adapter = _adapters[model] = TypeAdapter(model)
    return adapter.validate_python(data)


def _p(*parts: str) -> str:
    """Join path segments, percent-encoding each id."""
    from urllib.parse import quote

    return "/".join(quote(part, safe="") for part in parts)


def _body(**fields: Any) -> Json:
    """A request body without the fields left at ``None``."""
    return {k: v for k, v in fields.items() if v is not None}


class AxentraClient:
    """Client for one Axentra server.

    Authentication (pick one): ``api_key="axk_..."`` (machines), ``session_token=...`` (a user
    session as bearer token; no CSRF needed), or call ``auth.login_password(...)`` which stores
    the session token for you. Use as a context manager or call ``close()``.

    ``transport``/``http_client`` allow tests and custom setups (proxies, mTLS, ASGI apps).
    """

    def __init__(
        self,
        base_url: str,
        *,
        api_key: str | None = None,
        session_token: str | None = None,
        timeout: httpx.Timeout | float | None = DEFAULT_TIMEOUT,
        headers: Mapping[str, str] | None = None,
        transport: httpx.BaseTransport | None = None,
        http_client: httpx.Client | None = None,
        verify: bool | str = True,
    ) -> None:
        if api_key and session_token:
            raise ValueError("pass either api_key or session_token, not both")
        self.base_url = base_url.rstrip("/")
        self._token: str | None = api_key or session_token
        self._extra_headers = dict(headers or {})
        self._owns_http = http_client is None
        # No cookie jar: the client authenticates with bearer tokens only (a stored session
        # cookie would switch the server into cookie + CSRF mode after logout).
        self._http = http_client or httpx.Client(
            base_url=self.base_url,
            timeout=timeout,
            transport=transport,
            verify=verify,
            cookies=CookieJar(policy=DefaultCookiePolicy(allowed_domains=[])),
        )
        self.auth = Auth(self)
        self.me = MeResource(self)
        self.products = Products(self)
        self.tenants = Tenants(self)
        self.operators = Operators(self)
        self.members = Members(self)
        self.invitations = Invitations(self)
        self.roles = Roles(self)
        self.api_keys = ApiKeys(self)
        self.records = Records(self)
        self.files = Files(self)
        self.usage = Usage(self)
        self.billing = Billing(self)
        self.notify = Notify(self)
        self.audit = Audit(self)

    # -- lifecycle and credentials ---------------------------------------------------------------

    def __enter__(self) -> AxentraClient:
        return self

    def __exit__(
        self, exc_type: type[BaseException] | None, exc: BaseException | None, tb: TracebackType | None
    ) -> None:
        self.close()

    def close(self) -> None:
        if self._owns_http:
            self._http.close()

    @property
    def token(self) -> str | None:
        """The bearer token in use (API key or session token)."""
        return self._token

    def set_token(self, token: str | None) -> None:
        """Use another API key or session token from now on (``None``: unauthenticated)."""
        self._token = token

    # -- generic request helpers -----------------------------------------------------------------

    def _url(self, path: str) -> str:
        return path if path.startswith("/") else "/" + path

    def request(
        self,
        method: str,
        path: str,
        *,
        params: Mapping[str, Any] | None = None,
        json: Any = None,
        headers: Mapping[str, str] | None = None,
        files: Any = None,
        data: Mapping[str, Any] | None = None,
    ) -> httpx.Response:
        """Send any request (also to endpoints without a typed method yet).

        Returns the read ``httpx.Response`` for 2xx answers; raises ``AxentraApiError`` otherwise.
        """
        hdrs = base_headers(self._token, self._extra_headers)
        if headers:
            hdrs.update(headers)
        response = self._http.request(
            method,
            self._url(path),
            params=query(params or {}),
            json=json,
            headers=hdrs,
            files=files,
            data=data,
        )
        if response.status_code >= 400:
            raise api_error(response)
        return response

    def request_json(self, method: str, path: str, **kwargs: Any) -> Any:
        """``request(...)`` returning the decoded JSON body (``None`` for 204)."""
        response = self.request(method, path, **kwargs)
        return None if response.status_code == 204 or not response.content else response.json()

    @contextmanager
    def stream(
        self, method: str, path: str, *, params: Mapping[str, Any] | None = None
    ) -> Iterator[httpx.Response]:
        """A streamed response (body not read); raises ``AxentraApiError`` for non-2xx."""
        hdrs = base_headers(self._token, self._extra_headers)
        hdrs["Accept"] = "*/*"
        with self._http.stream(method, self._url(path), params=query(params or {}), headers=hdrs) as r:
            if r.status_code >= 400:
                r.read()
                raise api_error(r)
            yield r

    def _get(self, path: str, model: Any, params: Mapping[str, Any] | None = None) -> Any:
        return _parse(model, self.request_json("GET", path, params=params))

    def _send(
        self,
        method: str,
        path: str,
        model: Any,
        json: Any = None,
        headers: Mapping[str, str] | None = None,
        params: Mapping[str, Any] | None = None,
    ) -> Any:
        data = self.request_json(method, path, json=json, headers=headers, params=params)
        return None if model is None else _parse(model, data)

    def _iterate(
        self, path: str, model: type[M], params: Mapping[str, Any], page_size: int | None
    ) -> Iterator[M]:
        cursor: str | None = None
        seen: set[str] = set()
        while True:
            page_model: Any = Page[model]  # type: ignore[valid-type]
            page: Page[M] = self._get(
                path, page_model, {**params, "limit": page_size, "cursor": cursor}
            )
            for item in page.items:
                yield item
            if not page.next_cursor:
                return
            if page.next_cursor in seen:
                raise RuntimeError(f"the server returned cursor {page.next_cursor} twice")
            seen.add(page.next_cursor)
            cursor = page.next_cursor

    # -- meta ------------------------------------------------------------------------------------

    def meta(self) -> Meta:
        """``GET /v1/meta``: server version, API version, mode, modules, login options."""
        result: Meta = self._get("/v1/meta", Meta)
        return result

    def check_compatibility(self) -> Meta:
        """Fetch the meta and apply the version rule (same major, server minor >= client minor).

        Raises ``IncompatibleApiError`` with a clear message otherwise. Call it at startup.
        """
        meta = self.meta()
        assert_compatible(meta.api_version)
        return meta


class _Resource:
    def __init__(self, client: AxentraClient) -> None:
        self._c = client


def _product(pid: str, *rest: str) -> str:
    return "/v1/products/" + _p(pid, *rest)


def _tenant(pid: str, tid: str, *rest: str) -> str:
    return "/v1/products/" + _p(pid, "tenants", tid, *rest)


class Auth(_Resource):
    """Password login with the session token used as bearer token, logout, sessions."""

    def login_password(self, email: str, password: str) -> SessionInfo:
        """Log in and use the new session's token for all further requests of this client."""
        response = self._c.request(
            "POST", "/v1/auth/login/password", json={"email": email, "password": password}
        )
        token = session_token_from(response)
        if not token:
            raise RuntimeError("the login response carried no session cookie")
        self._c.set_token(token)
        result: SessionInfo = _parse(SessionInfo, response.json())
        return result

    def setup(self, setup_token: str, email: str, password: str, name: str = "") -> SessionInfo:
        """First run: register the first platform admin with a setup token; logs in as them."""
        response = self._c.request(
            "POST",
            "/v1/auth/setup",
            json={"setup_token": setup_token, "email": email, "name": name, "password": password},
        )
        token = session_token_from(response)
        if token:
            self._c.set_token(token)
        result: SessionInfo = _parse(SessionInfo, response.json())
        return result

    def session(self) -> SessionInfo:
        result: SessionInfo = self._c._get("/v1/auth/session", SessionInfo)
        return result

    def sessions(self) -> list[Session]:
        result: list[Session] = self._c._get("/v1/auth/sessions", list[Session])
        return result

    def logout(self) -> None:
        """End the current session on the server and forget the token."""
        self._c.request("POST", "/v1/auth/logout")
        self._c.set_token(None)


class MeResource(_Resource):
    def get(self) -> Me:
        """The caller: user (or ``None`` for API keys), platform role and accessible products."""
        result: Me = self._c._get("/v1/me", Me)
        return result

    def update(
        self, *, name: str | None = None, locale: str | None = None, preferences: Json | None = None
    ) -> User:
        result: User = self._c._send(
            "PATCH", "/v1/me", User, _body(name=name, locale=locale, preferences=preferences)
        )
        return result


class Products(_Resource):
    def list(self) -> list[Product]:
        result: list[Product] = self._c._get("/v1/products", list[Product])
        return result

    def get(self, product_id: str) -> Product:
        result: Product = self._c._get(_product(product_id), Product)
        return result

    def create(
        self,
        slug: str,
        name: str,
        *,
        description: str | None = None,
        settings: Json | None = None,
        owner_user_id: str | None = None,
    ) -> Product:
        body = _body(
            slug=slug, name=name, description=description, settings=settings, owner_user_id=owner_user_id
        )
        result: Product = self._c._send("POST", "/v1/products", Product, body)
        return result

    def update(
        self,
        product_id: str,
        *,
        name: str | None = None,
        description: str | None = None,
        settings: Json | None = None,
        version: int | None = None,
    ) -> Product:
        body = _body(name=name, description=description, settings=settings)
        result: Product = self._c._send("PATCH", _product(product_id), Product, body, if_match(version))
        return result


class Tenants(_Resource):
    def list(
        self,
        product_id: str,
        *,
        q: str | None = None,
        status: str | None = None,
        limit: int | None = None,
        cursor: str | None = None,
    ) -> Page[Tenant]:
        params = {"q": q, "status": status, "limit": limit, "cursor": cursor}
        result: Page[Tenant] = self._c._get(_product(product_id, "tenants"), Page[Tenant], params)
        return result

    def iter(
        self,
        product_id: str,
        *,
        q: str | None = None,
        status: str | None = None,
        page_size: int | None = None,
    ) -> Iterator[Tenant]:
        """All tenants, page by page (lazy)."""
        return self._c._iterate(
            _product(product_id, "tenants"), Tenant, {"q": q, "status": status}, page_size
        )

    def get(self, product_id: str, tenant_id: str) -> Tenant:
        result: Tenant = self._c._get(_tenant(product_id, tenant_id), Tenant)
        return result

    def create(
        self,
        product_id: str,
        slug: str,
        name: str,
        *,
        settings: Json | None = None,
        owner_user_id: str | None = None,
    ) -> Tenant:
        body = _body(slug=slug, name=name, settings=settings, owner_user_id=owner_user_id)
        result: Tenant = self._c._send("POST", _product(product_id, "tenants"), Tenant, body)
        return result

    def update(
        self,
        product_id: str,
        tenant_id: str,
        *,
        name: str | None = None,
        settings: Json | None = None,
        status: str | None = None,
        version: int | None = None,
    ) -> Tenant:
        body = _body(name=name, settings=settings, status=status)
        result: Tenant = self._c._send(
            "PATCH", _tenant(product_id, tenant_id), Tenant, body, if_match(version)
        )
        return result

    def delete(self, product_id: str, tenant_id: str) -> None:
        """Delete the tenant and ALL its data."""
        self._c.request("DELETE", _tenant(product_id, tenant_id))


class Operators(_Resource):
    """Product members (operators with product roles)."""

    def list(self, product_id: str) -> list[ProductMember]:
        result: list[ProductMember] = self._c._get(_product(product_id, "members"), list[ProductMember])
        return result

    def add(
        self, product_id: str, role: str, *, email: str | None = None, user_id: str | None = None
    ) -> ProductMember:
        body = _body(role=role, email=email, user_id=user_id)
        result: ProductMember = self._c._send(
            "POST", _product(product_id, "members"), ProductMember, body
        )
        return result

    def change(self, product_id: str, user_id: str, role: str) -> ProductMember:
        result: ProductMember = self._c._send(
            "PATCH", _product(product_id, "members", user_id), ProductMember, {"role": role}
        )
        return result

    def remove(self, product_id: str, user_id: str) -> None:
        self._c.request("DELETE", _product(product_id, "members", user_id))


class Members(_Resource):
    """Tenant members."""

    def list(self, product_id: str, tenant_id: str) -> list[Membership]:
        result: list[Membership] = self._c._get(
            _tenant(product_id, tenant_id, "members"), list[Membership]
        )
        return result

    def add(
        self,
        product_id: str,
        tenant_id: str,
        role: str,
        *,
        email: str | None = None,
        user_id: str | None = None,
    ) -> Membership:
        body = _body(role=role, email=email, user_id=user_id)
        result: Membership = self._c._send(
            "POST", _tenant(product_id, tenant_id, "members"), Membership, body
        )
        return result

    def change(self, product_id: str, tenant_id: str, user_id: str, role: str) -> Membership:
        result: Membership = self._c._send(
            "PATCH", _tenant(product_id, tenant_id, "members", user_id), Membership, {"role": role}
        )
        return result

    def remove(self, product_id: str, tenant_id: str, user_id: str) -> None:
        self._c.request("DELETE", _tenant(product_id, tenant_id, "members", user_id))


class Invitations(_Resource):
    def list(self, product_id: str, tenant_id: str) -> list[Invitation]:
        result: list[Invitation] = self._c._get(
            _tenant(product_id, tenant_id, "invitations"), list[Invitation]
        )
        return result

    def create(
        self, product_id: str, tenant_id: str, email: str, role: str | None = None
    ) -> NewInvitation:
        """Invite by email. The response holds the one-time ``token`` (and ``accept_url``)."""
        result: NewInvitation = self._c._send(
            "POST",
            _tenant(product_id, tenant_id, "invitations"),
            NewInvitation,
            _body(email=email, role=role),
        )
        return result

    def revoke(self, product_id: str, tenant_id: str, invitation_id: str) -> None:
        self._c.request("DELETE", _tenant(product_id, tenant_id, "invitations", invitation_id))

    def accept(self, token: str) -> Membership:
        """Accept an invitation as the logged-in user (email must match)."""
        result: Membership = self._c._send(
            "POST", "/v1/invitations/accept", Membership, {"token": token}
        )
        return result


class Roles(_Resource):
    def list(self, product_id: str) -> list[Role]:
        result: list[Role] = self._c._get(_product(product_id, "roles"), list[Role])
        return result

    def create(
        self,
        product_id: str,
        key: str,
        name: str,
        scope: str,
        permissions: Sequence[str],
        *,
        description: str | None = None,
    ) -> Role:
        body = _body(key=key, name=name, scope=scope, permissions=[*permissions], description=description)
        result: Role = self._c._send("POST", _product(product_id, "roles"), Role, body)
        return result

    def update(
        self,
        product_id: str,
        role_id: str,
        *,
        name: str | None = None,
        description: str | None = None,
        permissions: Sequence[str] | None = None,
        version: int | None = None,
    ) -> Role:
        body = _body(
            name=name, description=description, permissions=None if permissions is None else [*permissions]
        )
        result: Role = self._c._send(
            "PATCH", _product(product_id, "roles", role_id), Role, body, if_match(version)
        )
        return result

    def delete(self, product_id: str, role_id: str) -> None:
        self._c.request("DELETE", _product(product_id, "roles", role_id))


class ApiKeys(_Resource):
    def list(self, product_id: str) -> list[ApiKey]:
        result: list[ApiKey] = self._c._get(_product(product_id, "api-keys"), list[ApiKey])
        return result

    def get(self, product_id: str, key_id: str) -> ApiKey:
        result: ApiKey = self._c._get(_product(product_id, "api-keys", key_id), ApiKey)
        return result

    def create(
        self,
        product_id: str,
        name: str,
        permissions: Sequence[str],
        *,
        tenant_id: str | None = None,
        expires_at: datetime | None = None,
    ) -> NewApiKey:
        """Create a key. ``secret`` in the result is shown exactly once; store it safely."""
        body = _body(
            name=name,
            permissions=[*permissions],
            tenant_id=tenant_id,
            expires_at=expires_at.isoformat() if expires_at else None,
        )
        result: NewApiKey = self._c._send("POST", _product(product_id, "api-keys"), NewApiKey, body)
        return result

    def revoke(self, product_id: str, key_id: str) -> ApiKey:
        result: ApiKey = self._c._send(
            "POST", _product(product_id, "api-keys", key_id, "revoke"), ApiKey
        )
        return result

    def rotate(self, product_id: str, key_id: str, *, grace_seconds: int | None = None) -> NewApiKey:
        """A new secret; the old key keeps working for ``grace_seconds``."""
        result: NewApiKey = self._c._send(
            "POST",
            _product(product_id, "api-keys", key_id, "rotate"),
            NewApiKey,
            _body(grace_seconds=grace_seconds),
        )
        return result


class Records(_Resource):
    """JSON records in named collections inside one tenant."""

    def list(
        self,
        product_id: str,
        tenant_id: str,
        collection: str,
        *,
        where: Json | None = None,
        sort: str | None = None,
        limit: int | None = None,
        cursor: str | None = None,
    ) -> Page[Record]:
        params = {"where": where, "sort": sort, "limit": limit, "cursor": cursor}
        result: Page[Record] = self._c._get(
            _tenant(product_id, tenant_id, "records", collection), Page[Record], params
        )
        return result

    def iter(
        self,
        product_id: str,
        tenant_id: str,
        collection: str,
        *,
        where: Json | None = None,
        sort: str | None = None,
        page_size: int | None = None,
    ) -> Iterator[Record]:
        """All matching records, page by page (lazy)."""
        return self._c._iterate(
            _tenant(product_id, tenant_id, "records", collection),
            Record,
            {"where": where, "sort": sort},
            page_size,
        )

    def get(self, product_id: str, tenant_id: str, collection: str, record_id: str) -> Record:
        result: Record = self._c._get(
            _tenant(product_id, tenant_id, "records", collection, record_id), Record
        )
        return result

    def create(self, product_id: str, tenant_id: str, collection: str, data: Json) -> Record:
        result: Record = self._c._send(
            "POST", _tenant(product_id, tenant_id, "records", collection), Record, data
        )
        return result

    def replace(
        self,
        product_id: str,
        tenant_id: str,
        collection: str,
        record_id: str,
        data: Json,
        *,
        version: int | None = None,
    ) -> Record:
        """Replace ``data``. With ``version``, a concurrent change fails with 412."""
        result: Record = self._c._send(
            "PUT",
            _tenant(product_id, tenant_id, "records", collection, record_id),
            Record,
            data,
            if_match(version),
        )
        return result

    def delete(
        self, product_id: str, tenant_id: str, collection: str, record_id: str, *, version: int | None = None
    ) -> None:
        self._c.request(
            "DELETE",
            _tenant(product_id, tenant_id, "records", collection, record_id),
            headers=if_match(version),
        )


class Files(_Resource):
    def upload(
        self,
        product_id: str,
        tenant_id: str,
        content: FileContent,
        *,
        filename: str | None = None,
        content_type: str = "application/octet-stream",
        name: str | None = None,
        metadata: Json | None = None,
        expires_at: datetime | None = None,
    ) -> FileInfo:
        """Upload ``content`` (bytes, a binary file object or a path) as multipart/form-data.

        A file object or path is streamed from disk, not loaded into memory first.
        """
        import json as _json

        opened: IO[bytes] | None = None
        if isinstance(content, str | os.PathLike):
            path = Path(content)
            opened = path.open("rb")
            payload: bytes | IO[bytes] = opened
            filename = filename or path.name
        else:
            payload = content
        try:
            data = _body(
                name=name,
                metadata=_json.dumps(metadata) if metadata is not None else None,
                expires_at=expires_at.isoformat() if expires_at else None,
            )
            response = self._c.request(
                "POST",
                _tenant(product_id, tenant_id, "files"),
                files={"file": (filename or "upload", payload, content_type)},
                data=data,
            )
        finally:
            if opened is not None:
                opened.close()
        result: FileInfo = _parse(FileInfo, response.json())
        return result

    def get(self, product_id: str, tenant_id: str, file_id: str) -> FileInfo:
        result: FileInfo = self._c._get(_tenant(product_id, tenant_id, "files", file_id), FileInfo)
        return result

    def list(
        self,
        product_id: str,
        tenant_id: str,
        *,
        q: str | None = None,
        content_type: str | None = None,
        created_by: str | None = None,
        sort: str | None = None,
        limit: int | None = None,
        cursor: str | None = None,
    ) -> Page[FileInfo]:
        params = {
            "q": q,
            "content_type": content_type,
            "created_by": created_by,
            "sort": sort,
            "limit": limit,
            "cursor": cursor,
        }
        result: Page[FileInfo] = self._c._get(
            _tenant(product_id, tenant_id, "files"), Page[FileInfo], params
        )
        return result

    def iter(
        self, product_id: str, tenant_id: str, *, q: str | None = None, page_size: int | None = None
    ) -> Iterator[FileInfo]:
        return self._c._iterate(_tenant(product_id, tenant_id, "files"), FileInfo, {"q": q}, page_size)

    def update(
        self,
        product_id: str,
        tenant_id: str,
        file_id: str,
        *,
        name: str | None = None,
        metadata: Json | None = None,
        version: int | None = None,
    ) -> FileInfo:
        result: FileInfo = self._c._send(
            "PATCH",
            _tenant(product_id, tenant_id, "files", file_id),
            FileInfo,
            _body(name=name, metadata=metadata),
            if_match(version),
        )
        return result

    def delete(
        self, product_id: str, tenant_id: str, file_id: str, *, version: int | None = None
    ) -> None:
        self._c.request(
            "DELETE", _tenant(product_id, tenant_id, "files", file_id), headers=if_match(version)
        )

    @contextmanager
    def stream(self, product_id: str, tenant_id: str, file_id: str) -> Iterator[httpx.Response]:
        """The file content as a streamed response: ``for chunk in r.iter_bytes(): ...``."""
        with self._c.stream("GET", _tenant(product_id, tenant_id, "files", file_id, "content")) as r:
            yield r

    def download(self, product_id: str, tenant_id: str, file_id: str) -> bytes:
        """The whole file content in memory (prefer ``stream``/``download_to`` for large files)."""
        with self.stream(product_id, tenant_id, file_id) as r:
            return r.read()

    def download_to(
        self, product_id: str, tenant_id: str, file_id: str, destination: str | os.PathLike[str] | IO[bytes]
    ) -> int:
        """Stream the content into a path or binary file object; returns the number of bytes."""
        written = 0
        with self.stream(product_id, tenant_id, file_id) as r:
            if isinstance(destination, str | os.PathLike):
                with Path(destination).open("wb") as fh:
                    for chunk in r.iter_bytes():
                        fh.write(chunk)
                        written += len(chunk)
            else:
                for chunk in r.iter_bytes():
                    destination.write(chunk)
                    written += len(chunk)
        return written

    def download_url(
        self, product_id: str, tenant_id: str, file_id: str, *, ttl_seconds: int | None = None
    ) -> DownloadUrl:
        """A short-lived signed (or presigned) URL that needs no credentials."""
        result: DownloadUrl = self._c._send(
            "POST",
            _tenant(product_id, tenant_id, "files", file_id, "download-url"),
            DownloadUrl,
            _body(ttl_seconds=ttl_seconds),
        )
        return result


class Usage(_Resource):
    def record(
        self,
        product_id: str,
        tenant_id: str,
        meter: str,
        quantity: int | float | Decimal | str,
        *,
        idempotency_key: str | None = None,
        occurred_at: datetime | None = None,
        properties: Json | None = None,
        enforce: bool | None = None,
    ) -> UsageRecordResult:
        """Record usage. Pass a stable ``idempotency_key`` (e.g. your request or order id) so that
        retries are safe: repeating it returns the original event with ``replayed=True``. Without
        one, a random key is generated (the call is then NOT safe to retry). ``enforce=True``
        refuses with 429 ``quota_exceeded`` when a hard limit would be exceeded."""
        key = check_idempotency_key(idempotency_key or new_idempotency_key())
        body = _body(
            meter=meter,
            quantity=str(quantity) if isinstance(quantity, Decimal) else quantity,
            occurred_at=occurred_at.isoformat() if occurred_at else None,
            properties=properties,
            enforce=enforce,
        )
        result: UsageRecordResult = self._c._send(
            "POST",
            _tenant(product_id, tenant_id, "usage", "events"),
            UsageRecordResult,
            body,
            {"Idempotency-Key": key},
        )
        return result

    def events(
        self,
        product_id: str,
        tenant_id: str,
        *,
        meter: str | None = None,
        since: datetime | None = None,
        until: datetime | None = None,
        limit: int | None = None,
        cursor: str | None = None,
    ) -> Page[UsageEvent]:
        params = {"meter": meter, "since": since, "until": until, "limit": limit, "cursor": cursor}
        result: Page[UsageEvent] = self._c._get(
            _tenant(product_id, tenant_id, "usage", "events"), Page[UsageEvent], params
        )
        return result

    def iter_events(
        self,
        product_id: str,
        tenant_id: str,
        *,
        meter: str | None = None,
        since: datetime | None = None,
        until: datetime | None = None,
        page_size: int | None = None,
    ) -> Iterator[UsageEvent]:
        return self._c._iterate(
            _tenant(product_id, tenant_id, "usage", "events"),
            UsageEvent,
            {"meter": meter, "since": since, "until": until},
            page_size,
        )

    def summary(
        self, product_id: str, tenant_id: str, *, at: datetime | None = None
    ) -> list[MeterUsage]:
        """Current period per meter, with limits and remaining quota."""
        result: list[MeterUsage] = self._c._get(
            _tenant(product_id, tenant_id, "usage", "summary"), list[MeterUsage], {"at": at}
        )
        return result

    def quotas(self, product_id: str, tenant_id: str) -> list[EffectiveLimit]:
        result: list[EffectiveLimit] = self._c._get(
            _tenant(product_id, tenant_id, "usage", "quotas"), list[EffectiveLimit]
        )
        return result

    def set_quota(
        self,
        product_id: str,
        tenant_id: str,
        meter: str,
        limit: int | float | Decimal | str | None,
        *,
        enforcement: str | None = None,
    ) -> EffectiveLimit:
        """A per-tenant override; ``limit=None`` means unlimited."""
        body: Json = {"limit": str(limit) if isinstance(limit, Decimal) else limit}
        if enforcement is not None:
            body["enforcement"] = enforcement
        result: EffectiveLimit = self._c._send(
            "PUT", _tenant(product_id, tenant_id, "usage", "quotas", meter), EffectiveLimit, body
        )
        return result

    def delete_quota(self, product_id: str, tenant_id: str, meter: str) -> EffectiveLimit:
        result: EffectiveLimit = self._c._send(
            "DELETE", _tenant(product_id, tenant_id, "usage", "quotas", meter), EffectiveLimit
        )
        return result

    def meters(self, product_id: str) -> list[Meter]:
        result: list[Meter] = self._c._get(_product(product_id, "usage", "meters"), list[Meter])
        return result

    def create_meter(
        self,
        product_id: str,
        key: str,
        *,
        name: str | None = None,
        unit: str | None = None,
        aggregation: str | None = None,
        reset_period: str | None = None,
        description: str | None = None,
        default_limit: int | float | Decimal | str | None = None,
        default_enforcement: str | None = None,
    ) -> Meter:
        body = _body(
            key=key,
            name=name,
            unit=unit,
            aggregation=aggregation,
            reset_period=reset_period,
            description=description,
            default_limit=str(default_limit) if isinstance(default_limit, Decimal) else default_limit,
            default_enforcement=default_enforcement,
        )
        result: Meter = self._c._send("POST", _product(product_id, "usage", "meters"), Meter, body)
        return result


class Billing(_Resource):
    def plans(self, product_id: str) -> list[Plan]:
        result: list[Plan] = self._c._get(_product(product_id, "billing", "plans"), list[Plan])
        return result

    def tenant_plans(self, product_id: str, tenant_id: str) -> list[Plan]:
        """The active plans a tenant may choose."""
        result: list[Plan] = self._c._get(
            _tenant(product_id, tenant_id, "billing", "plans"), list[Plan]
        )
        return result

    def create_plan(
        self,
        product_id: str,
        key: str,
        name: str,
        *,
        description: str | None = None,
        prices: list[Json] | None = None,
        entitlements: dict[str, bool | int | float | None] | None = None,
        trial_days: int | None = None,
        active: bool | None = None,
    ) -> Plan:
        body = _body(
            key=key,
            name=name,
            description=description,
            prices=prices,
            entitlements=entitlements,
            trial_days=trial_days,
            active=active,
        )
        result: Plan = self._c._send("POST", _product(product_id, "billing", "plans"), Plan, body)
        return result

    def subscriptions(
        self,
        product_id: str,
        *,
        status: str | None = None,
        plan: str | None = None,
        limit: int | None = None,
        cursor: str | None = None,
    ) -> Page[Subscription]:
        params = {"status": status, "plan": plan, "limit": limit, "cursor": cursor}
        result: Page[Subscription] = self._c._get(
            _product(product_id, "billing", "subscriptions"), Page[Subscription], params
        )
        return result

    def subscription(self, product_id: str, tenant_id: str) -> Subscription:
        """The tenant's current subscription (else the latest canceled one); 404 when none."""
        result: Subscription = self._c._get(
            _tenant(product_id, tenant_id, "billing", "subscription"), Subscription
        )
        return result

    def subscribe(
        self, product_id: str, tenant_id: str, plan: str, *, price_id: str | None = None
    ) -> Subscription:
        result: Subscription = self._c._send(
            "POST",
            _tenant(product_id, tenant_id, "billing", "subscription"),
            Subscription,
            _body(plan=plan, price_id=price_id),
        )
        return result

    def change_plan(
        self,
        product_id: str,
        tenant_id: str,
        plan: str,
        *,
        price_id: str | None = None,
        version: int | None = None,
    ) -> Subscription:
        result: Subscription = self._c._send(
            "POST",
            _tenant(product_id, tenant_id, "billing", "subscription", "change-plan"),
            Subscription,
            _body(plan=plan, price_id=price_id),
            if_match(version),
        )
        return result

    def cancel(self, product_id: str, tenant_id: str, *, at_period_end: bool = True) -> Subscription:
        result: Subscription = self._c._send(
            "POST",
            _tenant(product_id, tenant_id, "billing", "subscription", "cancel"),
            Subscription,
            {"at_period_end": at_period_end},
        )
        return result

    def resume(self, product_id: str, tenant_id: str) -> Subscription:
        result: Subscription = self._c._send(
            "POST", _tenant(product_id, tenant_id, "billing", "subscription", "resume"), Subscription
        )
        return result

    def entitlements(self, product_id: str, tenant_id: str) -> Entitlements:
        result: Entitlements = self._c._get(
            _tenant(product_id, tenant_id, "billing", "entitlements"), Entitlements
        )
        return result


class Notify(_Resource):
    def send(
        self,
        product_id: str,
        tenant_id: str,
        template_key: str,
        *,
        to_email: str | None = None,
        to_user_id: str | None = None,
        variables: Json | None = None,
        locale: str | None = None,
        idempotency_key: str | None = None,
    ) -> Message:
        """Queue a notification (delivered asynchronously by the dispatcher). With an
        ``idempotency_key``, a repeated call returns the original message."""
        if (to_email is None) == (to_user_id is None):
            raise ValueError("pass exactly one of to_email or to_user_id")
        body = _body(
            template_key=template_key,
            to=_body(email=to_email, user_id=to_user_id),
            variables=variables,
            locale=locale,
        )
        headers = {"Idempotency-Key": check_idempotency_key(idempotency_key)} if idempotency_key else None
        result: Message = self._c._send(
            "POST", _tenant(product_id, tenant_id, "notify", "send"), Message, body, headers
        )
        return result

    def messages(
        self,
        product_id: str,
        *,
        tenant_id: str | None = None,
        status: str | None = None,
        template_key: str | None = None,
        recipient: str | None = None,
        since: datetime | None = None,
        limit: int | None = None,
        cursor: str | None = None,
    ) -> Page[Message]:
        params = {
            "tenant_id": tenant_id,
            "status": status,
            "template_key": template_key,
            "recipient": recipient,
            "since": since,
            "limit": limit,
            "cursor": cursor,
        }
        result: Page[Message] = self._c._get(
            _product(product_id, "notify", "messages"), Page[Message], params
        )
        return result

    def iter_messages(
        self,
        product_id: str,
        *,
        tenant_id: str | None = None,
        status: str | None = None,
        page_size: int | None = None,
    ) -> Iterator[Message]:
        return self._c._iterate(
            _product(product_id, "notify", "messages"),
            Message,
            {"tenant_id": tenant_id, "status": status},
            page_size,
        )

    def message(self, product_id: str, message_id: str) -> Message:
        result: Message = self._c._get(_product(product_id, "notify", "messages", message_id), Message)
        return result


class Audit(_Resource):
    def list(
        self,
        *,
        product_id: str | None = None,
        tenant_id: str | None = None,
        action: str | None = None,
        actor_id: str | None = None,
        outcome: str | None = None,
        since: datetime | None = None,
        until: datetime | None = None,
        q: str | None = None,
        limit: int | None = None,
        cursor: str | None = None,
    ) -> Page[AuditEvent]:
        params = {
            "product_id": product_id,
            "tenant_id": tenant_id,
            "action": action,
            "actor_id": actor_id,
            "outcome": outcome,
            "since": since,
            "until": until,
            "q": q,
            "limit": limit,
            "cursor": cursor,
        }
        result: Page[AuditEvent] = self._c._get("/v1/audit", Page[AuditEvent], params)
        return result

    def iter(
        self,
        *,
        product_id: str | None = None,
        tenant_id: str | None = None,
        action: str | None = None,
        page_size: int | None = None,
    ) -> Iterator[AuditEvent]:
        params = {"product_id": product_id, "tenant_id": tenant_id, "action": action}
        return self._c._iterate("/v1/audit", AuditEvent, params, page_size)

    def get(self, event_id: str) -> AuditEvent:
        result: AuditEvent = self._c._get("/v1/audit/" + _p(event_id), AuditEvent)
        return result


__all__ = ["CSRF_HEADER", "AxentraClient"]
