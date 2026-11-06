"""The asynchronous Axentra client.

This module is the single source of the client code: ``axentra_client/_sync/client.py`` is
generated from it by ``scripts/unasync.py`` (``async``/``await`` removed, ``Async`` prefixes
dropped). Edit this file, then run ``python scripts/unasync.py``; a unit test fails when the
generated file is stale.

Adding an endpoint: add a method to the resource class it belongs to (or a new resource class
registered in ``AsyncAxentraClient.__init__``), using ``self._c._get/_post/...`` with a model
from ``axentra_client.models``; then regenerate the sync client and add a contract test.
Until then, every endpoint is reachable through ``client.request(...)``.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Mapping, Sequence
from contextlib import asynccontextmanager
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
    Delivery,
    DownloadUrl,
    EffectiveLimit,
    EnqueueableKinds,
    Entitlements,
    Event,
    FileInfo,
    Invitation,
    Job,
    JobStats,
    Me,
    Membership,
    Message,
    Meta,
    Meter,
    MeterUsage,
    NewApiKey,
    NewInvitation,
    NewWebhookSecret,
    Page,
    PermissionInfo,
    Plan,
    Product,
    ProductMember,
    Record,
    Role,
    Schedule,
    SearchDocument,
    SearchHit,
    SearchKindCount,
    Session,
    SessionInfo,
    Subscription,
    Tenant,
    UsageEvent,
    UsageRecordResult,
    User,
    WebhookEndpoint,
)

M = TypeVar("M", bound=BaseModel)
PermissionList = list[PermissionInfo]
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


class AsyncAxentraClient:
    """Client for one Axentra server.

    Authentication (pick one): ``api_key="axk_..."`` (machines), ``session_token=...`` (a user
    session as bearer token; no CSRF needed), or call ``auth.login_password(...)`` which stores
    the session token for you. Use as a context manager or call ``aclose()``.

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
        transport: httpx.AsyncBaseTransport | None = None,
        http_client: httpx.AsyncClient | None = None,
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
        self._http = http_client or httpx.AsyncClient(
            base_url=self.base_url,
            timeout=timeout,
            transport=transport,
            verify=verify,
            cookies=CookieJar(policy=DefaultCookiePolicy(allowed_domains=[])),
        )
        self.auth = AsyncAuth(self)
        self.me = AsyncMeResource(self)
        self.products = AsyncProducts(self)
        self.tenants = AsyncTenants(self)
        self.operators = AsyncOperators(self)
        self.members = AsyncMembers(self)
        self.invitations = AsyncInvitations(self)
        self.roles = AsyncRoles(self)
        self.api_keys = AsyncApiKeys(self)
        self.records = AsyncRecords(self)
        self.files = AsyncFiles(self)
        self.usage = AsyncUsage(self)
        self.billing = AsyncBilling(self)
        self.notify = AsyncNotify(self)
        self.audit = AsyncAudit(self)
        self.events = AsyncEvents(self)
        self.jobs = AsyncJobs(self)
        self.schedules = AsyncSchedules(self)
        self.webhooks = AsyncWebhooks(self)
        self.search = AsyncSearch(self)

    # -- lifecycle and credentials ---------------------------------------------------------------

    async def __aenter__(self) -> AsyncAxentraClient:
        return self

    async def __aexit__(
        self, exc_type: type[BaseException] | None, exc: BaseException | None, tb: TracebackType | None
    ) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        if self._owns_http:
            await self._http.aclose()

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

    async def request(
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
        response = await self._http.request(
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

    async def request_json(self, method: str, path: str, **kwargs: Any) -> Any:
        """``request(...)`` returning the decoded JSON body (``None`` for 204)."""
        response = await self.request(method, path, **kwargs)
        return None if response.status_code == 204 or not response.content else response.json()

    @asynccontextmanager
    async def stream(
        self, method: str, path: str, *, params: Mapping[str, Any] | None = None
    ) -> AsyncIterator[httpx.Response]:
        """A streamed response (body not read); raises ``AxentraApiError`` for non-2xx."""
        hdrs = base_headers(self._token, self._extra_headers)
        hdrs["Accept"] = "*/*"
        async with self._http.stream(method, self._url(path), params=query(params or {}), headers=hdrs) as r:
            if r.status_code >= 400:
                await r.aread()
                raise api_error(r)
            yield r

    async def _get(self, path: str, model: Any, params: Mapping[str, Any] | None = None) -> Any:
        return _parse(model, await self.request_json("GET", path, params=params))

    async def _send(
        self,
        method: str,
        path: str,
        model: Any,
        json: Any = None,
        headers: Mapping[str, str] | None = None,
        params: Mapping[str, Any] | None = None,
    ) -> Any:
        data = await self.request_json(method, path, json=json, headers=headers, params=params)
        return None if model is None else _parse(model, data)

    async def _iterate(
        self, path: str, model: type[M], params: Mapping[str, Any], page_size: int | None
    ) -> AsyncIterator[M]:
        cursor: str | None = None
        seen: set[str] = set()
        while True:
            page_model: Any = Page[model]  # type: ignore[valid-type]
            page: Page[M] = await self._get(
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

    async def meta(self) -> Meta:
        """``GET /v1/meta``: server version, API version, mode, modules, login options."""
        result: Meta = await self._get("/v1/meta", Meta)
        return result

    async def check_compatibility(self) -> Meta:
        """Fetch the meta and apply the version rule (same major, server minor >= client minor).

        Raises ``IncompatibleApiError`` with a clear message otherwise. Call it at startup.
        """
        meta = await self.meta()
        assert_compatible(meta.api_version)
        return meta


class _Resource:
    def __init__(self, client: AsyncAxentraClient) -> None:
        self._c = client


def _product(pid: str, *rest: str) -> str:
    return "/v1/products/" + _p(pid, *rest)


def _tenant(pid: str, tid: str, *rest: str) -> str:
    return "/v1/products/" + _p(pid, "tenants", tid, *rest)


class AsyncAuth(_Resource):
    """Password login with the session token used as bearer token, logout, sessions."""

    async def login_password(self, email: str, password: str) -> SessionInfo:
        """Log in and use the new session's token for all further requests of this client."""
        response = await self._c.request(
            "POST", "/v1/auth/login/password", json={"email": email, "password": password}
        )
        token = session_token_from(response)
        if not token:
            raise RuntimeError("the login response carried no session cookie")
        self._c.set_token(token)
        result: SessionInfo = _parse(SessionInfo, response.json())
        return result

    async def setup(self, setup_token: str, email: str, password: str, name: str = "") -> SessionInfo:
        """First run: register the first platform admin with a setup token; logs in as them."""
        response = await self._c.request(
            "POST",
            "/v1/auth/setup",
            json={"setup_token": setup_token, "email": email, "name": name, "password": password},
        )
        token = session_token_from(response)
        if token:
            self._c.set_token(token)
        result: SessionInfo = _parse(SessionInfo, response.json())
        return result

    async def session(self) -> SessionInfo:
        result: SessionInfo = await self._c._get("/v1/auth/session", SessionInfo)
        return result

    async def sessions(self) -> list[Session]:
        result: list[Session] = await self._c._get("/v1/auth/sessions", list[Session])
        return result

    async def logout(self) -> None:
        """End the current session on the server and forget the token."""
        await self._c.request("POST", "/v1/auth/logout")
        self._c.set_token(None)

    async def request_password_reset(self, email: str, *, product_id: str | None = None) -> None:
        """Ask for a reset link by email. The server answers the same whether or not the address
        has an account; ``product_id`` picks the product that sends it (when the user belongs to it)."""
        await self._c.request(
            "POST", "/v1/auth/password-reset", json=_body(email=email, product_id=product_id)
        )

    async def confirm_password_reset(self, token: str, new_password: str) -> None:
        """Set a new password with the token from a reset link (ends all sessions of the user;
        ``InvalidToken`` problem, code ``invalid_token``, for a bad link)."""
        await self._c.request(
            "POST", "/v1/auth/password-reset/confirm", json={"token": token, "new_password": new_password}
        )

    async def confirm_email_verification(self, token: str) -> None:
        """Confirm an email address with the token from a verification link (no session needed)."""
        await self._c.request("POST", "/v1/auth/email-verification/confirm", json={"token": token})


class AsyncMeResource(_Resource):
    async def get(self) -> Me:
        """The caller: user (or ``None`` for API keys), platform role and accessible products."""
        result: Me = await self._c._get("/v1/me", Me)
        return result

    async def update(
        self, *, name: str | None = None, locale: str | None = None, preferences: Json | None = None
    ) -> User:
        result: User = await self._c._send(
            "PATCH", "/v1/me", User, _body(name=name, locale=locale, preferences=preferences)
        )
        return result

    async def request_email_verification(self, *, product_id: str | None = None) -> None:
        """Send the signed-in user a link that confirms their address (``409`` when already
        verified, ``429`` within a minute of the last link)."""
        await self._c.request("POST", "/v1/me/email-verification", json=_body(product_id=product_id))


class AsyncProducts(_Resource):
    async def list(self) -> list[Product]:
        result: list[Product] = await self._c._get("/v1/products", list[Product])
        return result

    async def get(self, product_id: str) -> Product:
        result: Product = await self._c._get(_product(product_id), Product)
        return result

    async def create(
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
        result: Product = await self._c._send("POST", "/v1/products", Product, body)
        return result

    async def update(
        self,
        product_id: str,
        *,
        name: str | None = None,
        description: str | None = None,
        settings: Json | None = None,
        version: int | None = None,
    ) -> Product:
        body = _body(name=name, description=description, settings=settings)
        result: Product = await self._c._send("PATCH", _product(product_id), Product, body, if_match(version))
        return result


class AsyncTenants(_Resource):
    async def list(
        self,
        product_id: str,
        *,
        q: str | None = None,
        status: str | None = None,
        limit: int | None = None,
        cursor: str | None = None,
    ) -> Page[Tenant]:
        params = {"q": q, "status": status, "limit": limit, "cursor": cursor}
        result: Page[Tenant] = await self._c._get(_product(product_id, "tenants"), Page[Tenant], params)
        return result

    def iter(
        self,
        product_id: str,
        *,
        q: str | None = None,
        status: str | None = None,
        page_size: int | None = None,
    ) -> AsyncIterator[Tenant]:
        """All tenants, page by page (lazy)."""
        return self._c._iterate(
            _product(product_id, "tenants"), Tenant, {"q": q, "status": status}, page_size
        )

    async def get(self, product_id: str, tenant_id: str) -> Tenant:
        result: Tenant = await self._c._get(_tenant(product_id, tenant_id), Tenant)
        return result

    async def create(
        self,
        product_id: str,
        slug: str,
        name: str,
        *,
        settings: Json | None = None,
        owner_user_id: str | None = None,
    ) -> Tenant:
        body = _body(slug=slug, name=name, settings=settings, owner_user_id=owner_user_id)
        result: Tenant = await self._c._send("POST", _product(product_id, "tenants"), Tenant, body)
        return result

    async def update(
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
        result: Tenant = await self._c._send(
            "PATCH", _tenant(product_id, tenant_id), Tenant, body, if_match(version)
        )
        return result

    async def delete(self, product_id: str, tenant_id: str) -> None:
        """Delete the tenant and ALL its data."""
        await self._c.request("DELETE", _tenant(product_id, tenant_id))


class AsyncOperators(_Resource):
    """Product members (operators with product roles)."""

    async def list(self, product_id: str) -> list[ProductMember]:
        result: list[ProductMember] = await self._c._get(_product(product_id, "members"), list[ProductMember])
        return result

    async def add(
        self, product_id: str, role: str, *, email: str | None = None, user_id: str | None = None
    ) -> ProductMember:
        body = _body(role=role, email=email, user_id=user_id)
        result: ProductMember = await self._c._send(
            "POST", _product(product_id, "members"), ProductMember, body
        )
        return result

    async def change(self, product_id: str, user_id: str, role: str) -> ProductMember:
        result: ProductMember = await self._c._send(
            "PATCH", _product(product_id, "members", user_id), ProductMember, {"role": role}
        )
        return result

    async def remove(self, product_id: str, user_id: str) -> None:
        await self._c.request("DELETE", _product(product_id, "members", user_id))


class AsyncMembers(_Resource):
    """Tenant members."""

    async def list(self, product_id: str, tenant_id: str) -> list[Membership]:
        result: list[Membership] = await self._c._get(
            _tenant(product_id, tenant_id, "members"), list[Membership]
        )
        return result

    async def add(
        self,
        product_id: str,
        tenant_id: str,
        role: str,
        *,
        email: str | None = None,
        user_id: str | None = None,
    ) -> Membership:
        body = _body(role=role, email=email, user_id=user_id)
        result: Membership = await self._c._send(
            "POST", _tenant(product_id, tenant_id, "members"), Membership, body
        )
        return result

    async def change(self, product_id: str, tenant_id: str, user_id: str, role: str) -> Membership:
        result: Membership = await self._c._send(
            "PATCH", _tenant(product_id, tenant_id, "members", user_id), Membership, {"role": role}
        )
        return result

    async def remove(self, product_id: str, tenant_id: str, user_id: str) -> None:
        await self._c.request("DELETE", _tenant(product_id, tenant_id, "members", user_id))


class AsyncInvitations(_Resource):
    async def list(self, product_id: str, tenant_id: str) -> list[Invitation]:
        result: list[Invitation] = await self._c._get(
            _tenant(product_id, tenant_id, "invitations"), list[Invitation]
        )
        return result

    async def create(
        self, product_id: str, tenant_id: str, email: str, role: str | None = None
    ) -> NewInvitation:
        """Invite by email. The response holds the one-time ``token`` (and ``accept_url``)."""
        result: NewInvitation = await self._c._send(
            "POST",
            _tenant(product_id, tenant_id, "invitations"),
            NewInvitation,
            _body(email=email, role=role),
        )
        return result

    async def revoke(self, product_id: str, tenant_id: str, invitation_id: str) -> None:
        await self._c.request("DELETE", _tenant(product_id, tenant_id, "invitations", invitation_id))

    async def accept(self, token: str) -> Membership:
        """Accept an invitation as the logged-in user (email must match)."""
        result: Membership = await self._c._send(
            "POST", "/v1/invitations/accept", Membership, {"token": token}
        )
        return result


class AsyncRoles(_Resource):
    async def list(self, product_id: str) -> list[Role]:
        result: list[Role] = await self._c._get(_product(product_id, "roles"), list[Role])
        return result

    async def permissions(self, product_id: str, *, include_retired: bool = False) -> PermissionList:
        """Permissions grantable in the product: built-in ones, then the product's own."""
        result: PermissionList = await self._c._get(
            _product(product_id, "permissions"),
            PermissionList,
            {"include_retired": include_retired or None},
        )
        return result

    async def create(
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
        result: Role = await self._c._send("POST", _product(product_id, "roles"), Role, body)
        return result

    async def update(
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
        result: Role = await self._c._send(
            "PATCH", _product(product_id, "roles", role_id), Role, body, if_match(version)
        )
        return result

    async def delete(self, product_id: str, role_id: str) -> None:
        await self._c.request("DELETE", _product(product_id, "roles", role_id))


class AsyncApiKeys(_Resource):
    async def list(self, product_id: str) -> list[ApiKey]:
        result: list[ApiKey] = await self._c._get(_product(product_id, "api-keys"), list[ApiKey])
        return result

    async def get(self, product_id: str, key_id: str) -> ApiKey:
        result: ApiKey = await self._c._get(_product(product_id, "api-keys", key_id), ApiKey)
        return result

    async def create(
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
        result: NewApiKey = await self._c._send("POST", _product(product_id, "api-keys"), NewApiKey, body)
        return result

    async def revoke(self, product_id: str, key_id: str) -> ApiKey:
        result: ApiKey = await self._c._send(
            "POST", _product(product_id, "api-keys", key_id, "revoke"), ApiKey
        )
        return result

    async def rotate(self, product_id: str, key_id: str, *, grace_seconds: int | None = None) -> NewApiKey:
        """A new secret; the old key keeps working for ``grace_seconds``."""
        result: NewApiKey = await self._c._send(
            "POST",
            _product(product_id, "api-keys", key_id, "rotate"),
            NewApiKey,
            _body(grace_seconds=grace_seconds),
        )
        return result


class AsyncRecords(_Resource):
    """JSON records in named collections inside one tenant."""

    async def list(
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
        result: Page[Record] = await self._c._get(
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
    ) -> AsyncIterator[Record]:
        """All matching records, page by page (lazy)."""
        return self._c._iterate(
            _tenant(product_id, tenant_id, "records", collection),
            Record,
            {"where": where, "sort": sort},
            page_size,
        )

    async def get(self, product_id: str, tenant_id: str, collection: str, record_id: str) -> Record:
        result: Record = await self._c._get(
            _tenant(product_id, tenant_id, "records", collection, record_id), Record
        )
        return result

    async def create(self, product_id: str, tenant_id: str, collection: str, data: Json) -> Record:
        result: Record = await self._c._send(
            "POST", _tenant(product_id, tenant_id, "records", collection), Record, data
        )
        return result

    async def replace(
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
        result: Record = await self._c._send(
            "PUT",
            _tenant(product_id, tenant_id, "records", collection, record_id),
            Record,
            data,
            if_match(version),
        )
        return result

    async def delete(
        self, product_id: str, tenant_id: str, collection: str, record_id: str, *, version: int | None = None
    ) -> None:
        await self._c.request(
            "DELETE",
            _tenant(product_id, tenant_id, "records", collection, record_id),
            headers=if_match(version),
        )


class AsyncFiles(_Resource):
    async def upload(
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
            response = await self._c.request(
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

    async def get(self, product_id: str, tenant_id: str, file_id: str) -> FileInfo:
        result: FileInfo = await self._c._get(_tenant(product_id, tenant_id, "files", file_id), FileInfo)
        return result

    async def list(
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
        result: Page[FileInfo] = await self._c._get(
            _tenant(product_id, tenant_id, "files"), Page[FileInfo], params
        )
        return result

    def iter(
        self, product_id: str, tenant_id: str, *, q: str | None = None, page_size: int | None = None
    ) -> AsyncIterator[FileInfo]:
        return self._c._iterate(_tenant(product_id, tenant_id, "files"), FileInfo, {"q": q}, page_size)

    async def update(
        self,
        product_id: str,
        tenant_id: str,
        file_id: str,
        *,
        name: str | None = None,
        metadata: Json | None = None,
        version: int | None = None,
    ) -> FileInfo:
        result: FileInfo = await self._c._send(
            "PATCH",
            _tenant(product_id, tenant_id, "files", file_id),
            FileInfo,
            _body(name=name, metadata=metadata),
            if_match(version),
        )
        return result

    async def delete(
        self, product_id: str, tenant_id: str, file_id: str, *, version: int | None = None
    ) -> None:
        await self._c.request(
            "DELETE", _tenant(product_id, tenant_id, "files", file_id), headers=if_match(version)
        )

    @asynccontextmanager
    async def stream(self, product_id: str, tenant_id: str, file_id: str) -> AsyncIterator[httpx.Response]:
        """The file content as a streamed response: ``async for chunk in r.aiter_bytes(): ...``."""
        async with self._c.stream("GET", _tenant(product_id, tenant_id, "files", file_id, "content")) as r:
            yield r

    async def download(self, product_id: str, tenant_id: str, file_id: str) -> bytes:
        """The whole file content in memory (prefer ``stream``/``download_to`` for large files)."""
        async with self.stream(product_id, tenant_id, file_id) as r:
            return await r.aread()

    async def download_to(
        self, product_id: str, tenant_id: str, file_id: str, destination: str | os.PathLike[str] | IO[bytes]
    ) -> int:
        """Stream the content into a path or binary file object; returns the number of bytes."""
        written = 0
        async with self.stream(product_id, tenant_id, file_id) as r:
            if isinstance(destination, str | os.PathLike):
                with Path(destination).open("wb") as fh:
                    async for chunk in r.aiter_bytes():
                        fh.write(chunk)
                        written += len(chunk)
            else:
                async for chunk in r.aiter_bytes():
                    destination.write(chunk)
                    written += len(chunk)
        return written

    async def download_url(
        self, product_id: str, tenant_id: str, file_id: str, *, ttl_seconds: int | None = None
    ) -> DownloadUrl:
        """A short-lived signed (or presigned) URL that needs no credentials."""
        result: DownloadUrl = await self._c._send(
            "POST",
            _tenant(product_id, tenant_id, "files", file_id, "download-url"),
            DownloadUrl,
            _body(ttl_seconds=ttl_seconds),
        )
        return result


class AsyncUsage(_Resource):
    async def record(
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
        result: UsageRecordResult = await self._c._send(
            "POST",
            _tenant(product_id, tenant_id, "usage", "events"),
            UsageRecordResult,
            body,
            {"Idempotency-Key": key},
        )
        return result

    async def events(
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
        result: Page[UsageEvent] = await self._c._get(
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
    ) -> AsyncIterator[UsageEvent]:
        return self._c._iterate(
            _tenant(product_id, tenant_id, "usage", "events"),
            UsageEvent,
            {"meter": meter, "since": since, "until": until},
            page_size,
        )

    async def summary(
        self, product_id: str, tenant_id: str, *, at: datetime | None = None
    ) -> list[MeterUsage]:
        """Current period per meter, with limits and remaining quota."""
        result: list[MeterUsage] = await self._c._get(
            _tenant(product_id, tenant_id, "usage", "summary"), list[MeterUsage], {"at": at}
        )
        return result

    async def quotas(self, product_id: str, tenant_id: str) -> list[EffectiveLimit]:
        result: list[EffectiveLimit] = await self._c._get(
            _tenant(product_id, tenant_id, "usage", "quotas"), list[EffectiveLimit]
        )
        return result

    async def set_quota(
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
        result: EffectiveLimit = await self._c._send(
            "PUT", _tenant(product_id, tenant_id, "usage", "quotas", meter), EffectiveLimit, body
        )
        return result

    async def delete_quota(self, product_id: str, tenant_id: str, meter: str) -> EffectiveLimit:
        result: EffectiveLimit = await self._c._send(
            "DELETE", _tenant(product_id, tenant_id, "usage", "quotas", meter), EffectiveLimit
        )
        return result

    async def meters(self, product_id: str) -> list[Meter]:
        result: list[Meter] = await self._c._get(_product(product_id, "usage", "meters"), list[Meter])
        return result

    async def create_meter(
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
        result: Meter = await self._c._send("POST", _product(product_id, "usage", "meters"), Meter, body)
        return result


class AsyncBilling(_Resource):
    async def plans(self, product_id: str) -> list[Plan]:
        result: list[Plan] = await self._c._get(_product(product_id, "billing", "plans"), list[Plan])
        return result

    async def tenant_plans(self, product_id: str, tenant_id: str) -> list[Plan]:
        """The active plans a tenant may choose."""
        result: list[Plan] = await self._c._get(
            _tenant(product_id, tenant_id, "billing", "plans"), list[Plan]
        )
        return result

    async def create_plan(
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
        result: Plan = await self._c._send("POST", _product(product_id, "billing", "plans"), Plan, body)
        return result

    async def subscriptions(
        self,
        product_id: str,
        *,
        status: str | None = None,
        plan: str | None = None,
        limit: int | None = None,
        cursor: str | None = None,
    ) -> Page[Subscription]:
        params = {"status": status, "plan": plan, "limit": limit, "cursor": cursor}
        result: Page[Subscription] = await self._c._get(
            _product(product_id, "billing", "subscriptions"), Page[Subscription], params
        )
        return result

    async def subscription(self, product_id: str, tenant_id: str) -> Subscription:
        """The tenant's current subscription (else the latest canceled one); 404 when none."""
        result: Subscription = await self._c._get(
            _tenant(product_id, tenant_id, "billing", "subscription"), Subscription
        )
        return result

    async def subscribe(
        self, product_id: str, tenant_id: str, plan: str, *, price_id: str | None = None
    ) -> Subscription:
        result: Subscription = await self._c._send(
            "POST",
            _tenant(product_id, tenant_id, "billing", "subscription"),
            Subscription,
            _body(plan=plan, price_id=price_id),
        )
        return result

    async def change_plan(
        self,
        product_id: str,
        tenant_id: str,
        plan: str,
        *,
        price_id: str | None = None,
        version: int | None = None,
    ) -> Subscription:
        result: Subscription = await self._c._send(
            "POST",
            _tenant(product_id, tenant_id, "billing", "subscription", "change-plan"),
            Subscription,
            _body(plan=plan, price_id=price_id),
            if_match(version),
        )
        return result

    async def cancel(self, product_id: str, tenant_id: str, *, at_period_end: bool = True) -> Subscription:
        result: Subscription = await self._c._send(
            "POST",
            _tenant(product_id, tenant_id, "billing", "subscription", "cancel"),
            Subscription,
            {"at_period_end": at_period_end},
        )
        return result

    async def resume(self, product_id: str, tenant_id: str) -> Subscription:
        result: Subscription = await self._c._send(
            "POST", _tenant(product_id, tenant_id, "billing", "subscription", "resume"), Subscription
        )
        return result

    async def entitlements(self, product_id: str, tenant_id: str) -> Entitlements:
        result: Entitlements = await self._c._get(
            _tenant(product_id, tenant_id, "billing", "entitlements"), Entitlements
        )
        return result


class AsyncNotify(_Resource):
    async def send(
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
        result: Message = await self._c._send(
            "POST", _tenant(product_id, tenant_id, "notify", "send"), Message, body, headers
        )
        return result

    async def messages(
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
        result: Page[Message] = await self._c._get(
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
    ) -> AsyncIterator[Message]:
        return self._c._iterate(
            _product(product_id, "notify", "messages"),
            Message,
            {"tenant_id": tenant_id, "status": status},
            page_size,
        )

    async def message(self, product_id: str, message_id: str) -> Message:
        result: Message = await self._c._get(_product(product_id, "notify", "messages", message_id), Message)
        return result


class AsyncAudit(_Resource):
    async def list(
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
        result: Page[AuditEvent] = await self._c._get("/v1/audit", Page[AuditEvent], params)
        return result

    def iter(
        self,
        *,
        product_id: str | None = None,
        tenant_id: str | None = None,
        action: str | None = None,
        page_size: int | None = None,
    ) -> AsyncIterator[AuditEvent]:
        params = {"product_id": product_id, "tenant_id": tenant_id, "action": action}
        return self._c._iterate("/v1/audit", AuditEvent, params, page_size)

    async def get(self, event_id: str) -> AuditEvent:
        result: AuditEvent = await self._c._get("/v1/audit/" + _p(event_id), AuditEvent)
        return result


__all__ = ["CSRF_HEADER", "AsyncAxentraClient"]


class AsyncEvents(_Resource):
    """Domain events: publish into a tenant, list and read (``events:read``/``events:publish``).
    The live stream (``GET .../events/stream``, server-sent events) is reachable through
    ``client.stream(...)``."""

    async def publish(
        self,
        product_id: str,
        tenant_id: str,
        type: str,
        data: Json | None = None,
        *,
        idempotency_key: str | None = None,
    ) -> Event:
        """Publish an event; matching webhooks are delivered asynchronously. With an
        ``idempotency_key``, a repeated call returns the original event."""
        headers = {"Idempotency-Key": check_idempotency_key(idempotency_key)} if idempotency_key else None
        result: Event = await self._c._send(
            "POST", _tenant(product_id, tenant_id, "events"), Event, _body(type=type, data=data), headers
        )
        return result

    async def list(
        self,
        product_id: str,
        *,
        tenant_id: str | None = None,
        type: str | None = None,
        limit: int | None = None,
        cursor: str | None = None,
    ) -> Page[Event]:
        """Newest first. ``type`` is an exact type or a prefix ending in ``*``."""
        params = {"tenant_id": tenant_id, "type": type, "limit": limit, "cursor": cursor}
        result: Page[Event] = await self._c._get(_product(product_id, "events"), Page[Event], params)
        return result

    def iter(
        self,
        product_id: str,
        *,
        tenant_id: str | None = None,
        type: str | None = None,
        page_size: int | None = None,
    ) -> AsyncIterator[Event]:
        return self._c._iterate(
            _product(product_id, "events"), Event, {"tenant_id": tenant_id, "type": type}, page_size
        )

    async def get(self, product_id: str, event_id: str) -> Event:
        result: Event = await self._c._get(_product(product_id, "events", event_id), Event)
        return result


class AsyncJobs(_Resource):
    """Background jobs of a product: enqueue, list, inspect, retry and cancel."""

    async def enqueue(
        self,
        product_id: str,
        kind: str,
        payload: Json | None = None,
        *,
        tenant_id: str | None = None,
        priority: int | None = None,
        delay_seconds: float | None = None,
        run_after: datetime | None = None,
        max_attempts: int | None = None,
        idempotency_key: str | None = None,
    ) -> Job:
        """Enqueue a job. Callers without ``jobs:manage`` need a ``tenant_id`` and a kind opened
        to them (see ``kinds()``). With an ``idempotency_key``, a repeated call returns the
        original job."""
        body = _body(
            kind=kind,
            payload=payload,
            tenant_id=tenant_id,
            priority=priority,
            delay_seconds=delay_seconds,
            run_after=run_after.isoformat() if run_after else None,
            max_attempts=max_attempts,
        )
        headers = {"Idempotency-Key": check_idempotency_key(idempotency_key)} if idempotency_key else None
        result: Job = await self._c._send("POST", _product(product_id, "jobs"), Job, body, headers)
        return result

    async def list(
        self,
        product_id: str,
        *,
        status: str | None = None,
        kind: str | None = None,
        tenant_id: str | None = None,
        limit: int | None = None,
        cursor: str | None = None,
    ) -> Page[Job]:
        """Newest first."""
        params = {"status": status, "kind": kind, "tenant_id": tenant_id, "limit": limit, "cursor": cursor}
        result: Page[Job] = await self._c._get(_product(product_id, "jobs"), Page[Job], params)
        return result

    def iter(
        self,
        product_id: str,
        *,
        status: str | None = None,
        kind: str | None = None,
        tenant_id: str | None = None,
        page_size: int | None = None,
    ) -> AsyncIterator[Job]:
        return self._c._iterate(
            _product(product_id, "jobs"),
            Job,
            {"status": status, "kind": kind, "tenant_id": tenant_id},
            page_size,
        )

    async def get(self, product_id: str, job_id: str) -> Job:
        result: Job = await self._c._get(_product(product_id, "jobs", job_id), Job)
        return result

    async def retry(self, product_id: str, job_id: str) -> Job:
        """Re-queue a failed or dead job."""
        result: Job = await self._c._send("POST", _product(product_id, "jobs", job_id, "retry"), Job)
        return result

    async def cancel(self, product_id: str, job_id: str) -> Job:
        """Cancel a queued job, or ask a running one to stop (``cancel_requested``)."""
        result: Job = await self._c._send("POST", _product(product_id, "jobs", job_id, "cancel"), Job)
        return result

    async def stats(self, product_id: str, *, tenant_id: str | None = None) -> JobStats:
        result: JobStats = await self._c._get(
            _product(product_id, "jobs", "stats"), JobStats, {"tenant_id": tenant_id}
        )
        return result

    async def kinds(self, product_id: str, *, tenant_id: str | None = None) -> EnqueueableKinds:
        """The job kinds the caller may enqueue (in ``tenant_id`` when given)."""
        result: EnqueueableKinds = await self._c._get(
            _product(product_id, "jobs", "kinds"), EnqueueableKinds, {"tenant_id": tenant_id}
        )
        return result


class AsyncSchedules(_Resource):
    """Recurring jobs (an interval or a cron expression)."""

    async def create(
        self,
        product_id: str,
        name: str,
        kind: str,
        *,
        interval_seconds: int | None = None,
        cron: str | None = None,
        payload: Json | None = None,
        tenant_id: str | None = None,
        enabled: bool | None = None,
        priority: int | None = None,
        max_attempts: int | None = None,
    ) -> Schedule:
        """Pass exactly one of ``interval_seconds`` and ``cron``."""
        if (interval_seconds is None) == (cron is None):
            raise ValueError("pass exactly one of interval_seconds or cron")
        body = _body(
            name=name,
            kind=kind,
            interval_seconds=interval_seconds,
            cron=cron,
            payload=payload,
            tenant_id=tenant_id,
            enabled=enabled,
            priority=priority,
            max_attempts=max_attempts,
        )
        result: Schedule = await self._c._send("POST", _product(product_id, "schedules"), Schedule, body)
        return result

    async def list(
        self,
        product_id: str,
        *,
        tenant_id: str | None = None,
        limit: int | None = None,
        cursor: str | None = None,
    ) -> Page[Schedule]:
        params = {"tenant_id": tenant_id, "limit": limit, "cursor": cursor}
        result: Page[Schedule] = await self._c._get(_product(product_id, "schedules"), Page[Schedule], params)
        return result

    def iter(
        self, product_id: str, *, tenant_id: str | None = None, page_size: int | None = None
    ) -> AsyncIterator[Schedule]:
        return self._c._iterate(
            _product(product_id, "schedules"), Schedule, {"tenant_id": tenant_id}, page_size
        )

    async def get(self, product_id: str, schedule_id: str) -> Schedule:
        result: Schedule = await self._c._get(_product(product_id, "schedules", schedule_id), Schedule)
        return result

    async def update(
        self,
        product_id: str,
        schedule_id: str,
        *,
        name: str | None = None,
        kind: str | None = None,
        interval_seconds: int | None = None,
        cron: str | None = None,
        payload: Json | None = None,
        enabled: bool | None = None,
        priority: int | None = None,
        max_attempts: int | None = None,
        version: int | None = None,
    ) -> Schedule:
        """Change the given fields. Setting ``cron`` switches an interval schedule to cron and
        the other way round. With ``version``, a concurrent change fails with 412."""
        body = _body(
            name=name,
            kind=kind,
            interval_seconds=interval_seconds,
            cron=cron,
            payload=payload,
            enabled=enabled,
            priority=priority,
            max_attempts=max_attempts,
        )
        result: Schedule = await self._c._send(
            "PATCH", _product(product_id, "schedules", schedule_id), Schedule, body, if_match(version)
        )
        return result

    async def delete(self, product_id: str, schedule_id: str, *, version: int | None = None) -> None:
        await self._c.request(
            "DELETE", _product(product_id, "schedules", schedule_id), headers=if_match(version)
        )


class AsyncWebhooks(_Resource):
    """Webhook endpoints and their deliveries. The signing secret is returned only by
    ``create()`` and ``rotate_secret()``."""

    async def create(
        self,
        product_id: str,
        url: str,
        event_types: Sequence[str],
        *,
        tenant_id: str | None = None,
        description: str | None = None,
        enabled: bool | None = None,
    ) -> NewWebhookSecret:
        body = _body(
            url=url,
            event_types=list(event_types),
            tenant_id=tenant_id,
            description=description,
            enabled=enabled,
        )
        result: NewWebhookSecret = await self._c._send(
            "POST", _product(product_id, "webhooks"), NewWebhookSecret, body
        )
        return result

    async def list(
        self, product_id: str, *, limit: int | None = None, cursor: str | None = None
    ) -> Page[WebhookEndpoint]:
        result: Page[WebhookEndpoint] = await self._c._get(
            _product(product_id, "webhooks"), Page[WebhookEndpoint], {"limit": limit, "cursor": cursor}
        )
        return result

    def iter(self, product_id: str, *, page_size: int | None = None) -> AsyncIterator[WebhookEndpoint]:
        return self._c._iterate(_product(product_id, "webhooks"), WebhookEndpoint, {}, page_size)

    async def get(self, product_id: str, webhook_id: str) -> WebhookEndpoint:
        result: WebhookEndpoint = await self._c._get(
            _product(product_id, "webhooks", webhook_id), WebhookEndpoint
        )
        return result

    async def update(
        self,
        product_id: str,
        webhook_id: str,
        *,
        url: str | None = None,
        event_types: Sequence[str] | None = None,
        description: str | None = None,
        enabled: bool | None = None,
        version: int | None = None,
    ) -> WebhookEndpoint:
        body = _body(
            url=url,
            event_types=list(event_types) if event_types is not None else None,
            description=description,
            enabled=enabled,
        )
        result: WebhookEndpoint = await self._c._send(
            "PATCH", _product(product_id, "webhooks", webhook_id), WebhookEndpoint, body, if_match(version)
        )
        return result

    async def delete(self, product_id: str, webhook_id: str, *, version: int | None = None) -> None:
        await self._c.request(
            "DELETE", _product(product_id, "webhooks", webhook_id), headers=if_match(version)
        )

    async def rotate_secret(
        self, product_id: str, webhook_id: str, *, grace_seconds: int | None = None
    ) -> NewWebhookSecret:
        """A new signing secret; with ``grace_seconds``, the old one also signs until then."""
        result: NewWebhookSecret = await self._c._send(
            "POST",
            _product(product_id, "webhooks", webhook_id, "rotate-secret"),
            NewWebhookSecret,
            _body(grace_seconds=grace_seconds),
        )
        return result

    async def test(self, product_id: str, webhook_id: str) -> Delivery:
        """Send a test event to the endpoint now and return the delivery."""
        result: Delivery = await self._c._send(
            "POST", _product(product_id, "webhooks", webhook_id, "test"), Delivery
        )
        return result

    async def deliveries(
        self,
        product_id: str,
        webhook_id: str,
        *,
        status: str | None = None,
        limit: int | None = None,
        cursor: str | None = None,
    ) -> Page[Delivery]:
        result: Page[Delivery] = await self._c._get(
            _product(product_id, "webhooks", webhook_id, "deliveries"),
            Page[Delivery],
            {"status": status, "limit": limit, "cursor": cursor},
        )
        return result

    def iter_deliveries(
        self,
        product_id: str,
        webhook_id: str,
        *,
        status: str | None = None,
        page_size: int | None = None,
    ) -> AsyncIterator[Delivery]:
        return self._c._iterate(
            _product(product_id, "webhooks", webhook_id, "deliveries"),
            Delivery,
            {"status": status},
            page_size,
        )

    async def delivery(self, product_id: str, webhook_id: str, delivery_id: str) -> Delivery:
        result: Delivery = await self._c._get(
            _product(product_id, "webhooks", webhook_id, "deliveries", delivery_id), Delivery
        )
        return result

    async def redeliver(self, product_id: str, webhook_id: str, delivery_id: str) -> Delivery:
        """Queue the delivery again (202)."""
        result: Delivery = await self._c._send(
            "POST",
            _product(product_id, "webhooks", webhook_id, "deliveries", delivery_id, "redeliver"),
            Delivery,
        )
        return result


class AsyncSearch(_Resource):
    """Full-text search inside one tenant (``search:query``) and its index (``search:index``)."""

    async def query(
        self,
        product_id: str,
        tenant_id: str,
        q: str,
        *,
        kinds: Sequence[str] | None = None,
        limit: int | None = None,
        cursor: str | None = None,
    ) -> Page[SearchHit]:
        """Best matches first. ``q`` takes words, "phrases" and -exclusions."""
        params = {"q": q, "kind": list(kinds) if kinds else None, "limit": limit, "cursor": cursor}
        result: Page[SearchHit] = await self._c._get(
            _tenant(product_id, tenant_id, "search"), Page[SearchHit], params
        )
        return result

    def iter(
        self,
        product_id: str,
        tenant_id: str,
        q: str,
        *,
        kinds: Sequence[str] | None = None,
        page_size: int | None = None,
    ) -> AsyncIterator[SearchHit]:
        return self._c._iterate(
            _tenant(product_id, tenant_id, "search"),
            SearchHit,
            {"q": q, "kind": list(kinds) if kinds else None},
            page_size,
        )

    async def index(
        self,
        product_id: str,
        tenant_id: str,
        kind: str,
        ref_id: str,
        *,
        title: str = "",
        body: str = "",
        metadata: Json | None = None,
    ) -> SearchDocument:
        """Add or replace the document for ``(kind, ref_id)``."""
        result: SearchDocument = await self._c._send(
            "PUT",
            _tenant(product_id, tenant_id, "search", "documents", kind, ref_id),
            SearchDocument,
            _body(title=title, body=body, metadata=metadata),
        )
        return result

    async def document(self, product_id: str, tenant_id: str, kind: str, ref_id: str) -> SearchDocument:
        result: SearchDocument = await self._c._get(
            _tenant(product_id, tenant_id, "search", "documents", kind, ref_id), SearchDocument
        )
        return result

    async def remove(self, product_id: str, tenant_id: str, kind: str, ref_id: str) -> None:
        """Remove the document from the index."""
        await self._c.request("DELETE", _tenant(product_id, tenant_id, "search", "documents", kind, ref_id))

    async def kinds(self, product_id: str, tenant_id: str) -> list[SearchKindCount]:
        """The tenant's indexed kinds with their document counts."""
        result: list[SearchKindCount] = await self._c._get(
            _tenant(product_id, tenant_id, "search", "kinds"), list[SearchKindCount]
        )
        return result
