"""OpenID Connect logins: authorization code flow with PKCE (S256), ``state`` and ``nonce``.

A login has two halves. :meth:`OidcService.start` creates a login state (random ``state``,
``nonce`` and PKCE ``code_verifier``), stores it in ``axentra_login_states`` for ten minutes (the
``state`` only as its SHA-256 hash, the nonce, verifier and invitation token encrypted with the
secret box) and returns the provider's authorization URL. The HTTP layer also gives the browser a
short-lived login cookie holding the ``state``.

:meth:`OidcService.finish` handles the provider's callback: it consumes the login state exactly
once (``DELETE ... RETURNING``), checks that the browser holds the login cookie for exactly this
``state`` (no login CSRF with a callback URL started in another browser), exchanges the code at
the token endpoint (with the PKCE verifier), verifies the ID token (signature with the provider's
published keys, asymmetric algorithms only, exact issuer, audience, expiry, ``nonce``, ``azp``),
finds or creates the user through :meth:`IdentityService.link_external_identity` and starts a
normal Axentra session. An external identity is the pair (issuer, subject); the email address
is only used (to link an existing account or to sign up) when the provider says
``email_verified: true``.

Errors are :class:`OidcLoginError` with a short, stable ``code`` that may be shown to the user;
the detail is only logged.
"""

# Adapted from peterkarlhuber/nodestro-api src/nodestro_api/identity.py at e7fb1dba1f5521d13ab2d90ac41e101f2c6f5bea (MIT, Copyright (c) 2026 Peter Karlhuber)

from __future__ import annotations

import base64
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from datetime import timedelta
import hashlib
import hmac
import logging
import threading
import time
from typing import Any
from urllib.parse import quote_plus, urlencode, urlsplit

import httpx
import jwt

from axentra.config.secrets import SecretBox, resolve_secret
from axentra.config.settings import OidcProviderSettings, Settings
from axentra.core.clock import utcnow
from axentra.core.context import Actor, ActorKind, Principal
from axentra.core.errors import AxentraError, Forbidden, NotFound
from axentra.core.ids import new_token
from axentra.data.database import Database, DbScope
from axentra.identity.models import NewSession
from axentra.identity.service import IdentityService
from axentra.identity.tokens import hash_token

logger = logging.getLogger(__name__)

#: Signature algorithms accepted for ID tokens: asymmetric only, never ``none`` or a shared secret.
ALGORITHMS = ("RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512", "EdDSA")
#: How long a started login may take (state row and login cookie).
LOGIN_TTL = timedelta(minutes=10)
#: Allowed clock difference to the provider, in seconds.
LEEWAY_SECONDS = 60
#: Largest accepted answer of a provider endpoint.
MAX_RESPONSE_BYTES = 1024 * 1024
#: Error codes a login can end with (shown to the user as ``?login_error=<code>``).
ERROR_CODES = frozenset(
    {
        "login_expired",  # unknown, used, expired state, or a browser without the matching login cookie
        "access_denied",  # the provider sent an error instead of a code
        "provider_unavailable",  # discovery, keys or token endpoint unreachable or misconfigured
        "login_failed",  # the code exchange or the ID token was refused
        "email_not_verified",
        "domain_not_allowed",
        "signup_disabled",
        "account_disabled",
        "rate_limited",
    }
)
_LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})


class OidcLoginError(Exception):
    """A login that cannot continue: ``code`` is safe to show, the message is only logged."""

    def __init__(self, code: str, detail: str, *, return_to: str | None = None) -> None:
        assert code in ERROR_CODES, code
        super().__init__(detail)
        self.code = code
        self.return_to = return_to


# -- URL helpers -------------------------------------------------------------------------------------


def is_loopback_http(url: str) -> bool:
    parts = urlsplit(url)
    return parts.scheme == "http" and (parts.hostname or "") in _LOOPBACK_HOSTS


def endpoint_allowed(url: str, *, production: bool) -> bool:
    """https, or plain http on loopback outside production (development and tests)."""
    parts = urlsplit(url)
    if parts.scheme == "https" and parts.hostname:
        return True
    return not production and is_loopback_http(url)


def _origin(url: str) -> str | None:
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.hostname or "@" in parts.netloc:
        return None
    return f"{parts.scheme}://{parts.netloc}".lower()


def safe_return_to(value: str | None, allowed_origins: Iterable[str]) -> str:
    """Where to continue after the login, never another site (no open redirect).

    Accepted: a path on this site starting with a single ``/`` (not ``//``, no backslashes or
    control characters, no scheme), or an absolute ``http(s)`` URL whose origin is one of
    ``allowed_origins`` (e.g. Axentra Studio on its own origin). Anything else becomes ``/``.
    """
    if not value or len(value) > 2000:
        return "/"
    if any(ch in value for ch in "\\") or any(ord(ch) < 0x21 or ord(ch) == 0x7F for ch in value):
        return "/"
    if value.startswith("/"):
        if value.startswith("//") or ":" in value.split("?", 1)[0].split("#", 1)[0]:
            return "/"
        return value
    origin = _origin(value)
    allowed = {o.rstrip("/").lower() for o in allowed_origins if o and o != "*"}
    if origin is None or origin not in allowed:
        return "/"
    return value


def login_error_url(login_page: str, return_to: str | None, code: str) -> str:
    """The login page for ``code``: on the origin of ``return_to`` when that is an absolute URL."""
    page = login_page or "/login"
    page_parts = urlsplit(page)
    if return_to and not return_to.startswith("/"):
        origin = _origin(return_to)
        if origin:
            path = page_parts.path or "/login"
            page = origin + path + (f"?{page_parts.query}" if page_parts.query else "")
    sep = "&" if "?" in page else "?"
    return f"{page}{sep}{urlencode({'login_error': code})}"


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def pkce_challenge(verifier: str) -> str:
    return _b64url(hashlib.sha256(verifier.encode("ascii")).digest())


# -- one provider ------------------------------------------------------------------------------------


@dataclass
class _Key:
    kid: str | None
    alg: str | None
    key: Any


@dataclass
class OidcClient:
    """The authorization code flow against one provider (synchronous ``httpx``; thread-safe)."""

    provider: OidcProviderSettings
    redirect_uri: str
    client_secret: str | None = field(default=None, repr=False)
    production: bool = False
    transport: httpx.BaseTransport | None = None
    cache_ttl_seconds: float = 3600.0
    min_jwks_refresh_seconds: float = 10.0
    clock: Callable[[], float] = time.monotonic

    def __post_init__(self) -> None:
        if not endpoint_allowed(self.provider.issuer, production=self.production):
            raise OidcLoginError(
                "provider_unavailable",
                f"issuer {self.provider.issuer!r} must use https (http only on loopback)",
            )
        self.http = httpx.Client(timeout=10.0, follow_redirects=False, transport=self.transport)
        self._metadata: dict[str, Any] | None = None
        self._metadata_at = 0.0
        self._keys: list[_Key] | None = None
        self._keys_at = 0.0
        self._lock = threading.RLock()

    def close(self) -> None:
        self.http.close()

    # discovery and keys

    def metadata(self) -> dict[str, Any]:
        with self._lock:
            if self._metadata is None or self.clock() - self._metadata_at > self.cache_ttl_seconds:
                self._metadata = self._discover()
                self._metadata_at = self.clock()
            return self._metadata

    def _discover(self) -> dict[str, Any]:
        issuer = self.provider.issuer
        data = self._get_json(issuer.rstrip("/") + "/.well-known/openid-configuration")
        if data.get("issuer") != issuer:
            raise OidcLoginError("provider_unavailable", f"discovery names issuer {data.get('issuer')!r}")
        for key in ("authorization_endpoint", "token_endpoint", "jwks_uri"):
            endpoint = data.get(key)
            if not isinstance(endpoint, str) or not endpoint_allowed(endpoint, production=self.production):
                raise OidcLoginError("provider_unavailable", f"the provider's {key} is missing or not https")
            # An https issuer never hands us plain-http endpoints, not even on loopback.
            if issuer.startswith("https://") and not endpoint.startswith("https://"):
                raise OidcLoginError("provider_unavailable", f"the provider's {key} is not https")
        return data

    def _get_json(self, url: str) -> dict[str, Any]:
        try:
            answer = self.http.get(url, headers={"Accept": "application/json"})
        except httpx.HTTPError as exc:
            raise OidcLoginError("provider_unavailable", f"reading {url} failed: {exc}") from exc
        return self._json(answer, url, "provider_unavailable")

    @staticmethod
    def _json(answer: httpx.Response, url: str, code: str) -> dict[str, Any]:
        if len(answer.content) > MAX_RESPONSE_BYTES:
            raise OidcLoginError(code, f"{url} answered with too much data")
        if answer.status_code != 200:
            raise OidcLoginError(code, f"{url} answered {answer.status_code}: {answer.text[:200]}")
        try:
            data = answer.json()
        except ValueError as exc:
            raise OidcLoginError(code, f"{url} did not answer with JSON") from exc
        if not isinstance(data, dict):
            raise OidcLoginError(code, f"{url} did not answer with an object")
        return data

    def _fetch_keys(self) -> list[_Key]:
        data = self._get_json(str(self.metadata()["jwks_uri"]))
        keys: list[_Key] = []
        for item in data.get("keys") or []:
            if not isinstance(item, dict) or item.get("use") not in (None, "sig"):
                continue
            if item.get("kty") == "oct":
                continue  # shared secrets are never accepted
            try:
                jwk = jwt.PyJWK(item)
            except (jwt.PyJWTError, ValueError, TypeError, KeyError):
                continue
            keys.append(_Key(item.get("kid"), item.get("alg"), jwk.key))
        if not keys:
            raise OidcLoginError("provider_unavailable", "the provider publishes no usable signing keys")
        return keys

    def _key(self, kid: str | None, alg: str) -> Any:
        """The key that signed a token; the key set is read again when ``kid`` is unknown (rotation)."""
        with self._lock:
            if self._keys is None or self.clock() - self._keys_at > self.cache_ttl_seconds:
                self._keys, self._keys_at = self._fetch_keys(), self.clock()
            found = self._find_key(self._keys, kid, alg)
            # Unknown key: read the key set again, but not more often than min_jwks_refresh_seconds
            # (a flood of tokens with invented kids must not hammer the provider).
            if found is None and self.clock() - self._keys_at >= self.min_jwks_refresh_seconds:
                self._keys, self._keys_at = self._fetch_keys(), self.clock()
                found = self._find_key(self._keys, kid, alg)
        if found is None:
            raise OidcLoginError("login_failed", f"the ID token was signed with an unknown key ({kid!r})")
        return found

    @staticmethod
    def _find_key(keys: list[_Key], kid: str | None, alg: str) -> Any | None:
        candidates = [k for k in keys if k.alg in (None, alg)]
        if kid is None:
            return candidates[0].key if len(candidates) == 1 else None
        for k in candidates:
            if k.kid == kid:
                return k.key
        return None

    # the flow

    def authorization_url(self, *, state: str, nonce: str, code_verifier: str) -> str:
        query = urlencode(
            {
                "response_type": "code",
                "client_id": self.provider.client_id,
                "redirect_uri": self.redirect_uri,
                "scope": " ".join(self.provider.scopes),
                "state": state,
                "nonce": nonce,
                "code_challenge": pkce_challenge(code_verifier),
                "code_challenge_method": "S256",
            }
        )
        endpoint = str(self.metadata()["authorization_endpoint"])
        return f"{endpoint}{'&' if '?' in endpoint else '?'}{query}"

    def exchange(self, *, code: str, code_verifier: str) -> str:
        """Trade the code for tokens; returns the (not yet verified) ID token."""
        form = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": self.redirect_uri,
            "code_verifier": code_verifier,
        }
        headers = {"Accept": "application/json"}
        method = self.provider.token_endpoint_auth_method
        if method == "client_secret_basic":
            # RFC 6749 2.3.1: both parts form-encoded before base64.
            pair = f"{quote_plus(self.provider.client_id)}:{quote_plus(self.client_secret or '')}"
            headers["Authorization"] = "Basic " + base64.b64encode(pair.encode()).decode()
        elif method == "client_secret_post":
            form["client_id"] = self.provider.client_id
            form["client_secret"] = self.client_secret or ""
        else:
            form["client_id"] = self.provider.client_id
        url = str(self.metadata()["token_endpoint"])
        try:
            answer = self.http.post(url, data=form, headers=headers)
        except httpx.HTTPError as exc:
            raise OidcLoginError("provider_unavailable", f"the token request failed: {exc}") from exc
        if answer.status_code in (400, 401):
            raise OidcLoginError("login_failed", f"the token endpoint refused the code: {answer.text[:200]}")
        tokens = self._json(answer, url, "provider_unavailable")
        id_token = tokens.get("id_token")
        if not isinstance(id_token, str) or not id_token:
            raise OidcLoginError("login_failed", "the provider sent no ID token")
        return id_token

    def verify(self, id_token: str, *, nonce: str) -> dict[str, Any]:
        """The claims of a valid ID token for this client and this login."""
        try:
            header = jwt.get_unverified_header(id_token)
        except jwt.PyJWTError as exc:
            raise OidcLoginError("login_failed", f"unreadable ID token: {exc}") from exc
        alg = header.get("alg")
        if alg not in ALGORITHMS:
            raise OidcLoginError("login_failed", f"ID token algorithm {alg!r} is not accepted")
        kid = header.get("kid")
        key = self._key(kid if isinstance(kid, str) else None, alg)
        try:
            claims: dict[str, Any] = jwt.decode(
                id_token,
                key,
                algorithms=[alg],
                audience=self.provider.client_id,
                issuer=self.provider.issuer,
                leeway=LEEWAY_SECONDS,
                options={"require": ["exp", "iat", "iss", "aud", "sub"]},
            )
        except jwt.PyJWTError as exc:
            raise OidcLoginError("login_failed", f"invalid ID token: {exc}") from exc
        if claims.get("iss") != self.provider.issuer:
            raise OidcLoginError("login_failed", "the ID token has another issuer")
        token_nonce = claims.get("nonce")
        if not isinstance(token_nonce, str) or not hmac.compare_digest(token_nonce.encode(), nonce.encode()):
            raise OidcLoginError("login_failed", "the ID token belongs to another login (nonce)")
        audience = claims["aud"]
        azp = claims.get("azp")
        if isinstance(audience, list) and len(audience) > 1 and azp is None:
            raise OidcLoginError("login_failed", "the ID token has several audiences and no azp")
        if azp is not None and azp != self.provider.client_id:
            raise OidcLoginError("login_failed", "the ID token was issued to another client (azp)")
        sub = claims.get("sub")
        if not isinstance(sub, str) or not sub or len(sub) > 255:
            raise OidcLoginError("login_failed", "the ID token has no usable subject")
        return claims


# -- the service -----------------------------------------------------------------------------------------


@dataclass(frozen=True)
class LoginStart:
    """A started login: send the browser to ``authorization_url`` and bind ``state`` to it."""

    state: str
    authorization_url: str
    return_to: str


@dataclass(frozen=True)
class LoginResult:
    session: NewSession
    user_id: str
    return_to: str
    invitation_accepted: bool = False


AcceptInvitation = Callable[[Principal, str], Any]


class OidcService:
    """All configured providers (``settings.oidc``). ``transport`` replaces the network in tests."""

    def __init__(
        self,
        db: Database,
        settings: Settings,
        identity: IdentityService,
        secrets: SecretBox,
        *,
        transport: httpx.BaseTransport | None = None,
        accept_invitation: AcceptInvitation | None = None,
    ) -> None:
        self.db = db
        self.settings = settings
        self.identity = identity
        self.secrets = secrets
        self.accept_invitation = accept_invitation
        self._transport = transport
        self._client_options: dict[str, Any] = {}
        self._clients: dict[str, OidcClient] = {}
        self._lock = threading.Lock()

    def use_transport(self, transport: httpx.BaseTransport | None, **client_options: Any) -> None:
        """Route all provider requests through ``transport`` (tests); resets the cached clients."""
        with self._lock:
            for c in self._clients.values():
                c.close()
            self._clients.clear()
            self._transport = transport
            self._client_options = client_options

    def provider(self, provider_id: str) -> OidcProviderSettings:
        for p in self.settings.oidc:
            if p.id == provider_id:
                return p
        raise NotFound("unknown login provider")

    def redirect_uri(self, provider_id: str) -> str:
        return f"{self.settings.security.public_url.rstrip('/')}/v1/auth/oidc/{provider_id}/callback"

    def client(self, provider_id: str) -> OidcClient:
        provider = self.provider(provider_id)
        with self._lock:
            existing = self._clients.get(provider_id)
            if existing is not None:
                return existing
            secret = provider.client_secret
            if provider.client_secret_ref:
                secret = resolve_secret(provider.client_secret_ref)
            created = OidcClient(
                provider,
                redirect_uri=self.redirect_uri(provider_id),
                client_secret=secret,
                production=self.settings.is_production,
                transport=self._transport,
                **self._client_options,
            )
            self._clients[provider_id] = created
            return created

    def close(self) -> None:
        with self._lock:
            for c in self._clients.values():
                c.close()
            self._clients.clear()

    # -- start ---------------------------------------------------------------------------------------

    def _allowed_origins(self) -> list[str]:
        return [*self.settings.security.allowed_origins, self.settings.security.public_url]

    def safe_return_to(self, value: str | None) -> str:
        return safe_return_to(value, self._allowed_origins())

    def start(
        self, provider_id: str, *, return_to: str | None, invitation: str | None = None, ip: str | None = None
    ) -> LoginStart:
        client = self.client(provider_id)  # NotFound for unknown providers
        target = self.safe_return_to(return_to)
        bucket = f"oidc:start:{ip}"
        try:
            self.identity.hit(bucket, self.settings.security.login_rate_per_minute * 6)
        except AxentraError as exc:
            raise OidcLoginError("rate_limited", str(exc), return_to=target) from exc
        state = new_token(32)
        nonce = new_token(24)
        verifier = new_token(48)
        try:
            url = client.authorization_url(state=state, nonce=nonce, code_verifier=verifier)
        except OidcLoginError as exc:
            exc.return_to = target
            raise
        state_hash = hash_token(state)
        ctx = f"axentra_login_states:{state_hash}"
        with self.db.transaction(DbScope.platform()) as tx:
            tx.execute("DELETE FROM axentra_login_states WHERE expires_at < now()")
            tx.execute(
                "INSERT INTO axentra_login_states"
                " (state_hash, provider, nonce, code_verifier, return_to, invitation_token, expires_at)"
                " VALUES (%s, %s, %s, %s, %s, %s, %s)",
                (
                    state_hash,
                    provider_id,
                    self.secrets.encrypt(nonce, ctx + ":nonce"),
                    self.secrets.encrypt(verifier, ctx + ":code_verifier"),
                    target,
                    self.secrets.encrypt(invitation, ctx + ":invitation") if invitation else None,
                    utcnow() + LOGIN_TTL,
                ),
            )
        return LoginStart(state=state, authorization_url=url, return_to=target)

    # -- callback ------------------------------------------------------------------------------------

    def finish(
        self,
        provider_id: str,
        *,
        state: str | None,
        code: str | None,
        error: str | None,
        browser_state: str | None,
        ip: str | None,
        user_agent: str,
    ) -> LoginResult:
        """Complete a login; raises :class:`OidcLoginError` (``return_to`` set once known)."""
        provider = self.provider(provider_id)
        if not state:
            raise OidcLoginError("login_expired", "the callback has no state")
        state_hash = hash_token(state)
        with self.db.transaction(DbScope.platform()) as tx:
            # Consumed before anything else is checked: a callback URL works at most once.
            row = tx.one("DELETE FROM axentra_login_states WHERE state_hash = %s RETURNING *", (state_hash,))
        if row is None:
            raise OidcLoginError("login_expired", "unknown or already used login state")
        return_to: str = row["return_to"]
        try:
            return self._finish(provider, row, state, code, error, browser_state, ip, user_agent)
        except OidcLoginError as exc:
            exc.return_to = return_to
            self._audit_denied(provider_id, exc.code)
            raise

    def _finish(
        self,
        provider: OidcProviderSettings,
        row: dict[str, Any],
        state: str,
        code: str | None,
        error: str | None,
        browser_state: str | None,
        ip: str | None,
        user_agent: str,
    ) -> LoginResult:
        if not browser_state or not hmac.compare_digest(browser_state.encode(), state.encode()):
            # A callback URL started in another browser (login CSRF) or a lost login cookie.
            raise OidcLoginError("login_expired", "the browser does not hold the login cookie of this state")
        if row["provider"] != provider.id:
            raise OidcLoginError("login_expired", "the login state belongs to another provider")
        if row["expires_at"] <= utcnow():
            raise OidcLoginError("login_expired", "the login state expired")
        if error:
            safe = "".join(ch for ch in error[:64] if ch.isalnum() or ch in "_-.")
            raise OidcLoginError("access_denied", f"the provider answered error={safe}")
        if not code:
            raise OidcLoginError("login_failed", "the callback has neither code nor error")
        ctx = f"axentra_login_states:{row['state_hash']}"
        try:
            nonce = self.secrets.decrypt(row["nonce"], ctx + ":nonce")
            verifier = self.secrets.decrypt(row["code_verifier"], ctx + ":code_verifier")
            invitation = (
                self.secrets.decrypt(row["invitation_token"], ctx + ":invitation")
                if row["invitation_token"]
                else None
            )
        except Exception as exc:  # wrong key after a keyring change, tampered row
            raise OidcLoginError("login_expired", f"the login state cannot be read: {exc}") from exc

        client = self.client(provider.id)
        id_token = client.exchange(code=code, code_verifier=verifier)
        claims = client.verify(id_token, nonce=nonce)

        email = ""
        raw_email = claims.get("email")
        if claims.get("email_verified") is True and isinstance(raw_email, str):
            email = raw_email.strip()
        allowed_domains = [d.strip().lower() for d in provider.allowed_email_domains if d.strip()]
        if allowed_domains:
            # Checked on every login, not only on the first one, so tightening the list takes effect.
            if not email:
                raise OidcLoginError(
                    "email_not_verified", "a verified email is required by allowed_email_domains"
                )
            if email.rpartition("@")[2].lower() not in allowed_domains:
                raise OidcLoginError("domain_not_allowed", "the email domain is not allowed")
        name = claims.get("name") or claims.get("preferred_username") or ""
        allow_signup = provider.allow_signup or bool(
            invitation and email and self._invited(invitation, email)
        )
        try:
            user_id = self.identity.link_external_identity(
                provider=provider.issuer,
                subject=str(claims["sub"]),
                email=email,
                name=str(name)[:200],
                email_verified=bool(email),
                allow_signup=allow_signup,
                allowed_domains=allowed_domains,
                link_by_verified_email=provider.link_by_verified_email,
                allow_signup_without_email=provider.allow_signup_without_email,
            )
        except Forbidden as exc:
            reason = str(exc.extra.get("reason", "login_failed"))
            raise OidcLoginError(reason if reason in ERROR_CODES else "login_failed", exc.detail) from exc
        except AxentraError as exc:
            raise OidcLoginError("login_failed", exc.detail) from exc

        session = self.identity.start_session(user_id, f"oidc:{provider.id}", ip=ip, user_agent=user_agent)
        accepted = False
        if invitation and self.accept_invitation is not None:
            principal = Principal(
                actor=Actor(ActorKind.USER, user_id, session.info.user.display),
                session_id=session.info.session_id,
                ip=ip,
            )
            try:
                self.accept_invitation(principal, invitation)
                accepted = True
            except AxentraError as exc:
                # The login stands; the invitation can still be accepted explicitly.
                logger.info("invitation not accepted after OIDC login: %s", exc.detail)
        return LoginResult(
            session=session, user_id=user_id, return_to=row["return_to"], invitation_accepted=accepted
        )

    def _invited(self, invitation: str, email: str) -> bool:
        with self.db.transaction(DbScope.platform(), read_only=True) as tx:
            inv_email = tx.scalar(
                "SELECT email FROM axentra_invitations WHERE token_hash = %s AND accepted_at IS NULL"
                " AND revoked_at IS NULL AND expires_at > now()",
                (hash_token(invitation),),
            )
        return isinstance(inv_email, str) and inv_email.lower() == email.lower()

    def _audit_denied(self, provider_id: str, code: str) -> None:
        try:
            self.identity.audit.record_standalone(
                None,
                "identity.login",
                outcome="denied",
                details={"method": "oidc", "provider": provider_id, "reason": code},
                actor_override=("anonymous", "", ""),
            )
        except Exception:  # auditing a refusal must not hide the refusal
            logger.exception("could not audit a refused OIDC login")
