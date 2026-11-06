"""Users, sessions, password logins, first-run setup and login throttling.

Sessions are server-side: the browser holds a random 256 bit token, the database only its
SHA-256 hash, plus a per-session CSRF token. A session ends at ``expires_at`` (absolute
lifetime), after ``session_idle_minutes`` without use, on logout, on revocation, or when the
user is disabled. Changing the password revokes all other sessions of the user.

Login throttling counts failed attempts per IP and per account in fixed one-minute windows in
PostgreSQL, so the limit holds across API processes.
"""

from __future__ import annotations

from datetime import datetime, timedelta
import logging
from typing import Any

from psycopg.types.json import Jsonb

from axentra.audit.log import AuditLog
from axentra.config.settings import Settings
from axentra.core.clock import utcnow
from axentra.core.context import Actor, ActorKind, PlatformRole, Principal
from axentra.core.errors import (
    Conflict,
    EmailTaken,
    Forbidden,
    InvalidToken,
    NotFound,
    RateLimited,
    ReauthenticationRequired,
    SetupAlreadyCompleted,
    Unauthenticated,
    ValidationFailed,
)
from axentra.core.ids import new_id, new_token
from axentra.core.pagination import Page, clamp_limit, decode_cursor, encode_cursor
from axentra.data.database import Database, DbScope, Row, Tx
from axentra.identity.models import AccountEmail, NewSession, Session, SessionInfo, User
from axentra.identity.passwords import check_policy, hash_password, needs_rehash, verify_password
from axentra.identity.tokens import hash_token

logger = logging.getLogger(__name__)

_USER_COLUMNS = (
    "u.id, u.email, u.name, u.status, u.locale, u.preferences, u.created_at, u.updated_at, u.last_login_at,"
    " (u.password_hash IS NOT NULL) AS has_password, (u.email_verified_at IS NOT NULL) AS email_verified,"
    " pr.role AS platform_role"
)
#: Token prefixes (recognizable in logs and by secret scanners; the rest is 256 random bits).
RESET_TOKEN_PREFIX = "axpwr_"  # noqa: S105 (a prefix, not a secret)
VERIFY_TOKEN_PREFIX = "axemv_"  # noqa: S105
#: A new reset or verification email for the same account is sent at most once per this period.
ACCOUNT_EMAIL_COOLDOWN = timedelta(seconds=60)
_USER_FROM = "axentra_users u LEFT JOIN axentra_platform_roles pr ON pr.user_id = u.id"
_LAST_SEEN_RESOLUTION = timedelta(seconds=60)


def normalize_email(email: str) -> str:
    email = email.strip()
    if "@" not in email or len(email) > 320 or email.startswith("@") or email.endswith("@") or " " in email:
        raise ValidationFailed("invalid email address")
    local, _, domain = email.rpartition("@")
    return f"{local}@{domain.lower()}"


class IdentityService:
    def __init__(self, db: Database, settings: Settings, audit: AuditLog) -> None:
        self.db = db
        self.settings = settings
        self.audit = audit

    # -- users -------------------------------------------------------------------------------

    @staticmethod
    def _user(row: Row) -> User:
        return User.model_validate(row)

    def get_user(self, user_id: str) -> User:
        with self.db.transaction(DbScope.platform(), read_only=True) as tx:
            row = tx.one_or_404(
                f"SELECT {_USER_COLUMNS} FROM {_USER_FROM} WHERE u.id = %s", (user_id,), what="user"
            )
        return self._user(row)

    def find_user_by_email(self, tx: Tx, email: str) -> Row | None:
        return tx.one(f"SELECT {_USER_COLUMNS} FROM {_USER_FROM} WHERE lower(u.email) = lower(%s)", (email,))

    def create_user(
        self,
        tx: Tx,
        *,
        email: str | None,
        name: str = "",
        password: str | None = None,
        locale: str = "en",
        email_verified: bool = False,
    ) -> str:
        """Create a user; ``email=None`` creates a user without an email address (no password).
        ``email_verified``: an identity provider confirmed the address."""
        if email is None:
            if password is not None:
                raise ValidationFailed("a password needs an email address")
        else:
            email = normalize_email(email)
            if password is not None:
                check_policy(password, min_length=self.settings.security.password_min_length, email=email)
            if self.find_user_by_email(tx, email):
                raise EmailTaken("a user with this email address exists")
        user_id = new_id("usr")
        tx.execute(
            "INSERT INTO axentra_users (id, email, name, password_hash, locale, email_verified_at)"
            " VALUES (%s, %s, %s, %s, %s, CASE WHEN %s THEN now() END)",
            (
                user_id,
                email,
                name.strip()[:200],
                hash_password(password) if password else None,
                locale,
                bool(email and email_verified),
            ),
        )
        return user_id

    def list_users(
        self,
        *,
        product_id: str | None = None,
        q: str | None = None,
        status: str | None = None,
        limit: int | None = None,
        cursor: str | None = None,
    ) -> Page[User]:
        """All users, or (with ``product_id``) the users related to one product. Caller authorizes."""
        limit = clamp_limit(limit)
        where: list[str] = []
        params: list[Any] = []
        if product_id:
            where.append(
                "(u.id IN (SELECT user_id FROM axentra_memberships WHERE product_id = %s)"
                " OR u.id IN (SELECT user_id FROM axentra_product_members WHERE product_id = %s))"
            )
            params += [product_id, product_id]
        if q:
            like = "%" + q.replace("%", r"\%").replace("_", r"\_") + "%"
            where.append("(u.email ILIKE %s OR u.name ILIKE %s)")
            params += [like, like]
        if status:
            where.append("u.status = %s")
            params.append(status)
        after = decode_cursor(cursor, ("str",))
        if after:
            where.append("u.id > %s")
            params.append(after[0])
        sql = f"SELECT {_USER_COLUMNS} FROM {_USER_FROM}"
        if where:
            sql += " WHERE " + " AND ".join(where)
        sql += " ORDER BY u.id LIMIT %s"
        params.append(limit + 1)
        scope = DbScope.product(product_id) if product_id else DbScope.platform()
        with self.db.transaction(scope, read_only=True) as tx:
            rows = tx.all(sql, params)
        items = [self._user(r) for r in rows[:limit]]
        return Page[User](
            items=items, next_cursor=encode_cursor([items[-1].id]) if len(rows) > limit else None
        )

    def update_profile(
        self,
        principal: Principal,
        *,
        name: str | None,
        locale: str | None,
        preferences: dict[str, Any] | None,
    ) -> User:
        user_id = self._require_user(principal)
        sets: list[str] = []
        params: list[Any] = []
        if name is not None:
            sets.append("name = %s")
            params.append(name.strip()[:200])
        if locale is not None:
            if locale not in ("en", "de") and not (
                2 <= len(locale) <= 10 and locale.replace("-", "").isalpha()
            ):
                raise ValidationFailed("invalid locale")
            sets.append("locale = %s")
            params.append(locale)
        if preferences is not None:
            if len(str(preferences)) > 8000:
                raise ValidationFailed("preferences are too large")
            sets.append("preferences = %s")
            params.append(Jsonb(preferences))
        if sets:
            with self.db.transaction(DbScope.platform()) as tx:
                tx.execute(
                    f"UPDATE axentra_users SET {', '.join(sets)}, updated_at = now() WHERE id = %s",
                    [*params, user_id],
                )
        return self.get_user(user_id)

    def change_password(self, principal: Principal, current: str, new: str) -> None:
        """Change the password (the current one is required), or set a first password.

        A user without a password (OIDC-only) has no current password to prove; setting one turns
        a session into a permanent login that bypasses the identity provider. It is therefore only
        allowed within ``security.fresh_login_minutes`` of the session's login (``403``
        ``reauthentication_required`` otherwise: log in again and retry), and never with
        ``security.first_password = "disabled"``."""
        user_id = self._require_user(principal)
        with self.db.transaction(DbScope.platform()) as tx:
            row = tx.one_or_404(
                "SELECT email, password_hash FROM axentra_users WHERE id = %s FOR UPDATE", (user_id,)
            )
            if not row["email"]:
                raise Forbidden("users without an email address cannot use a password")
            if not row["password_hash"]:
                self_service_mode = self.settings.security.first_password  # a mode, not a secret
                if self_service_mode == "disabled":
                    raise Forbidden("users who log in through an identity provider cannot set a password")
                fresh = tx.one(
                    "SELECT 1 FROM axentra_sessions WHERE id = %s AND user_id = %s AND revoked_at IS NULL"
                    " AND created_at > now() - make_interval(mins => %s)",
                    (principal.session_id or "", user_id, self.settings.security.fresh_login_minutes),
                )
                if fresh is None:
                    self.audit.record(
                        tx,
                        principal,
                        "identity.password.change",
                        target_type="user",
                        target_id=user_id,
                        outcome="denied",
                        details={"reason": "stale_session"},
                    )
                    raise ReauthenticationRequired(
                        "log in again to set a password (the login must be at most"
                        f" {self.settings.security.fresh_login_minutes} minutes old)"
                    )
            elif not verify_password(row["password_hash"], current):
                self.audit.record(
                    tx,
                    principal,
                    "identity.password.change",
                    target_type="user",
                    target_id=user_id,
                    outcome="denied",
                )
                raise Forbidden("the current password is wrong")
            check_policy(
                new,
                min_length=self.settings.security.password_min_length,
                email=row["email"],
                field="new_password",
            )
            tx.execute(
                "UPDATE axentra_users SET password_hash = %s, updated_at = now() WHERE id = %s",
                (hash_password(new), user_id),
            )
            tx.execute(  # a reset link sent before the change must not undo it
                "UPDATE axentra_account_tokens SET used_at = now()"
                " WHERE user_id = %s AND purpose = 'password_reset' AND used_at IS NULL",
                (user_id,),
            )
            tx.execute(
                "UPDATE axentra_sessions SET revoked_at = now() WHERE user_id = %s AND revoked_at IS NULL AND id <> %s",
                (user_id, principal.session_id or ""),
            )
            self.audit.record(
                tx, principal, "identity.password.change", target_type="user", target_id=user_id
            )

    def set_user_status(self, principal: Principal, user_id: str, status: str) -> User:
        if status not in ("active", "disabled"):
            raise ValidationFailed("status must be active or disabled")
        if user_id == principal.user_id and status == "disabled":
            raise Conflict("you cannot disable yourself")
        with self.db.transaction(DbScope.platform()) as tx:
            tx.one_or_404("SELECT id FROM axentra_users WHERE id = %s FOR UPDATE", (user_id,), what="user")
            if status == "disabled":
                admins = tx.scalar(
                    "SELECT count(*) FROM axentra_platform_roles pr JOIN axentra_users u ON u.id = pr.user_id"
                    " WHERE pr.role = 'platform_admin' AND u.status = 'active' AND u.id <> %s",
                    (user_id,),
                )
                is_admin = tx.one(
                    "SELECT 1 FROM axentra_platform_roles WHERE user_id = %s AND role = 'platform_admin'",
                    (user_id,),
                )
                if is_admin and admins == 0:
                    raise Conflict("the last platform admin cannot be disabled")
                tx.execute(
                    "UPDATE axentra_sessions SET revoked_at = now() WHERE user_id = %s AND revoked_at IS NULL",
                    (user_id,),
                )
            tx.execute(
                "UPDATE axentra_users SET status = %s, updated_at = now() WHERE id = %s", (status, user_id)
            )
            self.audit.record(
                tx,
                principal,
                f"identity.user.{'disable' if status == 'disabled' else 'enable'}",
                target_type="user",
                target_id=user_id,
            )
        return self.get_user(user_id)

    def set_platform_role(self, principal: Principal, user_id: str, role: str | None) -> User:
        if role not in (None, "platform_admin", "platform_viewer"):
            raise ValidationFailed("invalid platform role")
        with self.db.transaction(DbScope.platform()) as tx:
            tx.one_or_404("SELECT id FROM axentra_users WHERE id = %s", (user_id,), what="user")
            if role != "platform_admin":
                others = tx.scalar(
                    "SELECT count(*) FROM axentra_platform_roles WHERE role = 'platform_admin' AND user_id <> %s",
                    (user_id,),
                )
                current = tx.one("SELECT role FROM axentra_platform_roles WHERE user_id = %s", (user_id,))
                if current and current["role"] == "platform_admin" and others == 0:
                    raise Conflict("the last platform admin cannot lose the role")
            if role is None:
                tx.execute("DELETE FROM axentra_platform_roles WHERE user_id = %s", (user_id,))
            else:
                tx.execute(
                    "INSERT INTO axentra_platform_roles (user_id, role) VALUES (%s, %s)"
                    " ON CONFLICT (user_id) DO UPDATE SET role = EXCLUDED.role",
                    (user_id, role),
                )
            self.audit.record(
                tx,
                principal,
                "identity.platform_role.set",
                target_type="user",
                target_id=user_id,
                details={"role": role},
            )
        return self.get_user(user_id)

    @staticmethod
    def _require_user(principal: Principal) -> str:
        if principal.user_id is None:
            raise Forbidden("only users can do this")
        return principal.user_id

    # -- first-run setup -----------------------------------------------------------------------

    def setup_required(self) -> bool:
        with self.db.transaction(DbScope.platform(), read_only=True) as tx:
            return (
                tx.one("SELECT 1 FROM axentra_platform_roles WHERE role = 'platform_admin' LIMIT 1") is None
            )

    def create_setup_token(self) -> str:
        token = "axsetup_" + new_token()
        with self.db.transaction(DbScope.platform()) as tx:
            tx.execute(
                "INSERT INTO axentra_setup_tokens (token_hash, expires_at)"
                " VALUES (%s, now() + make_interval(mins => %s))",
                (hash_token(token), self.settings.security.setup_token_ttl_minutes),
            )
            self.audit.record(tx, Principal.system("cli"), "identity.setup_token.create")
        return token

    def complete_setup(
        self,
        token: str,
        *,
        email: str,
        name: str,
        password: str,
        ip: str | None,
        user_agent: str,
        request_id: str | None = None,
    ) -> NewSession:
        self.hit(f"setup:{ip}", self.settings.security.login_rate_per_minute)
        with self.db.transaction(DbScope.platform()) as tx:
            row = tx.one(
                "SELECT token_hash FROM axentra_setup_tokens WHERE token_hash = %s AND used_at IS NULL"
                " AND expires_at > now() FOR UPDATE",
                (hash_token(token),),
            )
            if row is None:
                raise Unauthenticated("the setup token is invalid or expired")
            if tx.one("SELECT 1 FROM axentra_platform_roles WHERE role = 'platform_admin' LIMIT 1"):
                raise SetupAlreadyCompleted("setup was already completed")
            user_id = self.create_user(tx, email=email, name=name, password=password)
            tx.execute(
                "INSERT INTO axentra_platform_roles (user_id, role) VALUES (%s, 'platform_admin')", (user_id,)
            )
            tx.execute(
                "UPDATE axentra_setup_tokens SET used_at = now() WHERE token_hash = %s", (row["token_hash"],)
            )
            self.audit.record(
                tx,
                None,
                "identity.setup.complete",
                target_type="user",
                target_id=user_id,
                actor_override=("user", user_id, email),
                ip=ip,
                request_id=request_id,
            )
        return self.start_session(user_id, "password", ip=ip, user_agent=user_agent, request_id=request_id)

    # -- throttling ------------------------------------------------------------------------------

    def _window(self) -> datetime:
        return utcnow().replace(second=0, microsecond=0)

    def hit(self, bucket: str, limit: int) -> None:
        """Count one attempt and refuse it when the bucket is over ``limit`` in this minute.

        Atomic (one ``INSERT ... ON CONFLICT ... RETURNING``): concurrent attempts cannot exceed
        the budget. Use :meth:`refund` to give back the attempt when it turned out fine (e.g. a
        successful login), so that only failures use up the budget."""
        with self.db.transaction(DbScope.platform()) as tx:
            hits = tx.scalar(
                "INSERT INTO axentra_rate_limits (bucket, window_start, hits) VALUES (%s, %s, 1)"
                " ON CONFLICT (bucket, window_start) DO UPDATE SET hits = axentra_rate_limits.hits + 1"
                " RETURNING hits",
                (bucket, self._window()),
            )
            tx.execute("DELETE FROM axentra_rate_limits WHERE window_start < now() - interval '10 minutes'")
        if hits is not None and hits > limit:
            raise RateLimited("too many attempts; try again in a minute")

    def refund(self, bucket: str) -> None:
        """Give back one attempt counted by :meth:`hit` in the current window."""
        with self.db.transaction(DbScope.platform()) as tx:
            tx.execute(
                "UPDATE axentra_rate_limits SET hits = greatest(hits - 1, 0) WHERE bucket = %s AND window_start = %s",
                (bucket, self._window()),
            )

    def throttle(self, bucket: str, limit: int) -> None:
        """Check without counting (prefer :meth:`hit`; check-then-count is not atomic)."""
        with self.db.transaction(DbScope.platform(), read_only=True) as tx:
            hits = tx.scalar(
                "SELECT hits FROM axentra_rate_limits WHERE bucket = %s AND window_start = %s",
                (bucket, self._window()),
            )
        if hits is not None and hits >= limit:
            raise RateLimited("too many attempts; try again in a minute")

    def count_failure(self, bucket: str) -> None:
        with self.db.transaction(DbScope.platform()) as tx:
            tx.execute(
                "INSERT INTO axentra_rate_limits (bucket, window_start, hits) VALUES (%s, %s, 1)"
                " ON CONFLICT (bucket, window_start) DO UPDATE SET hits = axentra_rate_limits.hits + 1",
                (bucket, self._window()),
            )
            tx.execute("DELETE FROM axentra_rate_limits WHERE window_start < now() - interval '10 minutes'")

    # -- password login -------------------------------------------------------------------------

    def login_password(
        self, email: str, password: str, *, ip: str | None, user_agent: str, request_id: str | None = None
    ) -> NewSession:
        if not self.settings.security.password_login:
            raise Forbidden("password login is disabled")
        limit = self.settings.security.login_rate_per_minute
        account_bucket = f"login:acct:{email.strip().lower()}"
        ip_bucket = f"login:ip:{ip}"
        # Count first, verify afterwards (atomic, so parallel attempts cannot exceed the budget);
        # a successful login gives its attempts back. Trade-off: the per-account bucket lets anyone
        # who knows an email block password logins for that account for up to a minute
        # (see docs/architecture/SECURITY_MODEL.md, "Login throttling").
        self.hit(ip_bucket, limit * 3)
        try:
            self.hit(account_bucket, limit)
        except RateLimited:
            self.refund(ip_bucket)
            raise
        with self.db.transaction(DbScope.platform()) as tx:
            row = tx.one(
                "SELECT id, email, status, password_hash FROM axentra_users WHERE lower(email) = lower(%s)",
                (email.strip(),),
            )
            ok = verify_password(row["password_hash"] if row else None, password)
            if not ok or row is None or row["status"] != "active":
                self.audit.record(
                    tx,
                    None,
                    "identity.login",
                    outcome="denied",
                    target_type="user",
                    target_id=row["id"] if row else "",
                    details={"method": "password", "reason": "disabled" if ok else "bad_credentials"},
                    actor_override=("anonymous", "", email[:200]),
                    ip=ip,
                    request_id=request_id,
                )
                denied = True
            else:
                denied = False
                if needs_rehash(row["password_hash"]):
                    tx.execute(
                        "UPDATE axentra_users SET password_hash = %s WHERE id = %s",
                        (hash_password(password), row["id"]),
                    )
        if denied:
            raise Unauthenticated("wrong email or password")
        assert row is not None
        self.refund(ip_bucket)
        self.refund(account_bucket)
        return self.start_session(row["id"], "password", ip=ip, user_agent=user_agent, request_id=request_id)

    # -- sessions -------------------------------------------------------------------------------

    def start_session(
        self, user_id: str, method: str, *, ip: str | None, user_agent: str, request_id: str | None = None
    ) -> NewSession:
        """Create a session and record ``identity.login`` with the user's email (else name, else
        id) as ``actor_display`` and the request's ``ip`` and ``request_id``."""
        token = new_token()
        session_id = new_id("ses")
        csrf = new_token(24)
        with self.db.transaction(DbScope.platform()) as tx:
            # Expiry is computed and later checked on the database clock (never the app host's),
            # so clock skew between API hosts and PostgreSQL cannot lengthen or shorten sessions.
            expires = tx.scalar(
                "INSERT INTO axentra_sessions (id, user_id, token_hash, csrf_token, auth_method, ip, user_agent, expires_at)"
                " VALUES (%s, %s, %s, %s, %s, %s, %s, now() + make_interval(hours => %s)) RETURNING expires_at",
                (
                    session_id,
                    user_id,
                    hash_token(token),
                    csrf,
                    method,
                    ip,
                    user_agent[:400],
                    self.settings.security.session_ttl_hours,
                ),
            )
            user_row = tx.one(
                "UPDATE axentra_users SET last_login_at = now() WHERE id = %s RETURNING email, name",
                (user_id,),
            )
            display = (user_row["email"] or user_row["name"] or user_id) if user_row else user_id
            self.audit.record(
                tx,
                None,
                "identity.login",
                target_type="session",
                target_id=session_id,
                details={"method": method},
                actor_override=("user", user_id, display),
                ip=ip,
                request_id=request_id,
            )
        user = self.get_user(user_id)
        return NewSession(
            token=token,
            info=SessionInfo(
                user=user,
                session_id=session_id,
                csrf_token=csrf,
                expires_at=expires,
                platform_role=user.platform_role,
            ),
        )

    def resolve_session(
        self, token: str, *, request_id: str | None = None, ip: str | None = None
    ) -> tuple[Principal, SessionInfo]:
        with self.db.transaction(DbScope.platform()) as tx:
            # Absolute and idle expiry are compared with the database clock (see start_session).
            row = tx.one(
                "SELECT s.id, s.user_id, s.csrf_token, s.expires_at, s.revoked_at, u.status,"
                " s.expires_at > now() AND s.last_seen_at + make_interval(mins => %s) > now() AS live,"
                " now() - s.last_seen_at > %s AS touch"
                " FROM axentra_sessions s JOIN axentra_users u ON u.id = s.user_id WHERE s.token_hash = %s",
                (self.settings.security.session_idle_minutes, _LAST_SEEN_RESOLUTION, hash_token(token)),
            )
            if row is None or row["revoked_at"] is not None or row["status"] != "active" or not row["live"]:
                raise Unauthenticated("the session is invalid or expired")
            if row["touch"]:
                tx.execute("UPDATE axentra_sessions SET last_seen_at = now() WHERE id = %s", (row["id"],))
            # The user in the same transaction (one snapshot, one round trip of transaction control fewer per
            # request than a separate get_user).
            user = self._user(
                tx.one_or_404(
                    f"SELECT {_USER_COLUMNS} FROM {_USER_FROM} WHERE u.id = %s",
                    (row["user_id"],),
                    what="user",
                )
            )
        role = PlatformRole(user.platform_role) if user.platform_role else None
        principal = Principal(
            actor=Actor(ActorKind.USER, user.id, user.display),
            platform_role=role,
            session_id=row["id"],
            request_id=request_id,
            ip=ip,
        )
        info = SessionInfo(
            user=user,
            session_id=row["id"],
            csrf_token=row["csrf_token"],
            expires_at=row["expires_at"],
            platform_role=user.platform_role,
        )
        return principal, info

    def logout(self, principal: Principal) -> None:
        if principal.session_id is None:
            return
        with self.db.transaction(DbScope.platform()) as tx:
            tx.execute(
                "UPDATE axentra_sessions SET revoked_at = now() WHERE id = %s AND revoked_at IS NULL",
                (principal.session_id,),
            )
            self.audit.record(
                tx, principal, "identity.logout", target_type="session", target_id=principal.session_id
            )

    def list_sessions(
        self, user_id: str, *, current_session: str | None = None, active_only: bool = True
    ) -> list[Session]:
        sql = "SELECT * FROM axentra_sessions WHERE user_id = %s"
        if active_only:
            sql += " AND revoked_at IS NULL AND expires_at > now()"
        sql += " ORDER BY created_at DESC LIMIT 200"
        with self.db.transaction(DbScope.platform(), read_only=True) as tx:
            rows = tx.all(sql, (user_id,))
        return [Session.model_validate({**r, "current": r["id"] == current_session}) for r in rows]

    def revoke_session(self, principal: Principal, user_id: str, session_id: str) -> None:
        with self.db.transaction(DbScope.platform()) as tx:
            n = tx.execute(
                "UPDATE axentra_sessions SET revoked_at = now() WHERE id = %s AND user_id = %s"
                " AND revoked_at IS NULL",
                (session_id, user_id),
            )
            if n == 0:
                raise NotFound("session not found")
            self.audit.record(
                tx,
                principal,
                "identity.session.revoke",
                target_type="session",
                target_id=session_id,
                details={"user_id": user_id},
            )

    def revoke_all_sessions(self, principal: Principal, user_id: str) -> int:
        with self.db.transaction(DbScope.platform()) as tx:
            tx.one_or_404("SELECT id FROM axentra_users WHERE id = %s", (user_id,), what="user")
            n = tx.execute(
                "UPDATE axentra_sessions SET revoked_at = now() WHERE user_id = %s AND revoked_at IS NULL",
                (user_id,),
            )
            self.audit.record(
                tx,
                principal,
                "identity.session.revoke_all",
                target_type="user",
                target_id=user_id,
                details={"count": n},
            )
        return n

    def purge_expired(self) -> int:
        with self.db.transaction(DbScope.platform()) as tx:
            n = tx.execute("DELETE FROM axentra_sessions WHERE expires_at < now() - interval '7 days'")
            tx.execute("DELETE FROM axentra_login_states WHERE expires_at < now()")
            tx.execute("DELETE FROM axentra_setup_tokens WHERE expires_at < now() - interval '1 day'")
            tx.execute("DELETE FROM axentra_account_tokens WHERE expires_at < now() - interval '1 day'")
        return n

    # -- password reset and email verification ------------------------------------------------------
    #
    # Both send a single-use link by email. Only the token's SHA-256 is stored; a token expires
    # (``security.password_reset_minutes`` / ``email_verification_hours``), is bound to the address
    # it was sent to, and answers every refusal with the same ``invalid_token`` problem. A reset
    # request never tells whether an account exists: the API answers ``202`` before this runs
    # (see :meth:`request_password_reset`).

    def throttle_password_reset(self, email: str, ip: str | None) -> None:
        """Count one reset request per IP (the same budget for known and unknown addresses)."""
        if not self.settings.security.password_login:
            raise Forbidden("password login is disabled")
        self.hit(f"pwreset-ip:{ip}", self.settings.security.login_rate_per_minute * 3)

    def _account_product(self, tx: Tx, user_id: str, hint: str | None) -> str | None:
        """The product whose notification settings deliver an account email: ``hint`` when the
        user belongs to it (as an operator, or as a member of an active tenant), else the configured product (single mode), else the oldest active
        product the user belongs to. ``None``: no product can deliver it."""
        member = (
            " p.status = 'active' AND (EXISTS (SELECT 1 FROM axentra_product_members pm"
            " WHERE pm.product_id = p.id AND pm.user_id = %(u)s) OR EXISTS (SELECT 1 FROM"
            " axentra_memberships m JOIN axentra_tenants t ON t.product_id = m.product_id AND t.id = m.tenant_id"
            " WHERE m.product_id = p.id AND m.user_id = %(u)s AND t.status = 'active'))"
        )
        if hint:
            row = tx.one(
                f"SELECT p.id FROM axentra_products p WHERE p.id = %(h)s AND {member}",
                {"h": hint, "u": user_id},
            )
            if row:
                return str(row["id"])
        if self.settings.mode == "single":
            row = tx.one(
                "SELECT id FROM axentra_products WHERE slug = %s AND status = 'active'",
                (self.settings.product.slug,),
            )
            if row:
                return str(row["id"])
        row = tx.one(
            f"SELECT p.id FROM axentra_products p WHERE {member} ORDER BY p.created_at, p.id LIMIT 1",
            {"u": user_id},
        )
        return str(row["id"]) if row else None

    def _issue_account_token(
        self, tx: Tx, user_id: str, email: str, purpose: str, prefix: str, ttl: timedelta
    ) -> tuple[str, str, datetime]:
        """Spend the user's open tokens of ``purpose`` and store a new one (hash only)."""
        tx.execute(
            "UPDATE axentra_account_tokens SET used_at = now()"
            " WHERE user_id = %s AND purpose = %s AND used_at IS NULL",
            (user_id, purpose),
        )
        token = prefix + new_token(32)
        token_id = new_id("act")
        expires_at = utcnow() + ttl
        tx.execute(
            "INSERT INTO axentra_account_tokens (id, user_id, purpose, token_hash, email, expires_at)"
            " VALUES (%s, %s, %s, %s, %s, %s)",
            (token_id, user_id, purpose, hash_token(token), email, expires_at),
        )
        return token_id, token, expires_at

    @staticmethod
    def _recently_sent(tx: Tx, user_id: str, purpose: str) -> bool:
        return (
            tx.one(
                "SELECT 1 FROM axentra_account_tokens WHERE user_id = %s AND purpose = %s"
                " AND created_at > now() - make_interval(secs => %s) LIMIT 1",
                (user_id, purpose, ACCOUNT_EMAIL_COOLDOWN.total_seconds()),
            )
            is not None
        )

    def request_password_reset(
        self,
        email: str,
        *,
        ip: str | None,
        request_id: str | None = None,
        product_hint: str | None = None,
    ) -> AccountEmail | None:
        """Create a reset token for an active user with a password and this address.

        Returns ``None`` (and sends nothing) for an unknown address, a disabled user, a user
        without a password (OIDC-only: a reset must not create a password that bypasses the
        identity provider), a request within the cooldown of the last one, or when no product can
        deliver the email. The API runs this after answering ``202``, so neither the answer nor its
        timing tells which case applied. Refusals are audited without the address."""
        if not self.settings.security.password_login:
            return None
        with self.db.transaction(DbScope.platform()) as tx:
            row = tx.one(
                "SELECT id, email, status, password_hash, locale FROM axentra_users"
                " WHERE lower(email) = lower(%s) FOR UPDATE",
                (email.strip(),),
            )
            reason = None
            if row is None:
                reason = "unknown_email"
            elif row["status"] != "active":
                reason = "user_disabled"
            elif not row["password_hash"]:
                reason = "no_password"
            elif self._recently_sent(tx, row["id"], "password_reset"):
                reason = "cooldown"
            product_id = None
            if reason is None and row is not None:
                product_id = self._account_product(tx, row["id"], product_hint)
                if product_id is None:
                    reason = "no_delivery_product"
            if reason is not None:
                self.audit.record(
                    tx,
                    None,
                    "identity.password.reset_request",
                    target_type="user",
                    target_id=row["id"] if row else "",
                    outcome="denied",
                    details={"reason": reason},
                    ip=ip,
                    request_id=request_id,
                )
                return None
            assert row is not None
            assert product_id is not None
            token_id, token, expires_at = self._issue_account_token(
                tx,
                row["id"],
                row["email"],
                "password_reset",
                RESET_TOKEN_PREFIX,
                timedelta(minutes=self.settings.security.password_reset_minutes),
            )
            self.audit.record(
                tx,
                None,
                "identity.password.reset_request",
                target_type="user",
                target_id=row["id"],
                actor_override=("user", row["id"], row["email"]),
                details={"product_id": product_id},
                ip=ip,
                request_id=request_id,
            )
        return AccountEmail(
            purpose="password_reset",
            token_id=token_id,
            token=token,
            user_id=row["id"],
            email=row["email"],
            locale=row["locale"],
            product_id=product_id,
            expires_at=expires_at,
        )

    def _consume_account_token(self, tx: Tx, token: str, purpose: str) -> Row:
        """Lock and check a token; any refusal is the same :class:`InvalidToken`."""
        row = tx.one(
            "SELECT t.id, t.user_id, t.email, t.expires_at, t.used_at, u.email AS current_email,"
            " u.status, u.password_hash FROM axentra_account_tokens t"
            " JOIN axentra_users u ON u.id = t.user_id"
            " WHERE t.token_hash = %s AND t.purpose = %s FOR UPDATE OF t, u",
            (hash_token(token), purpose),
        )
        if (
            row is None
            or row["used_at"] is not None
            or row["expires_at"] <= utcnow()
            or row["status"] != "active"
            or not row["current_email"]
            or row["current_email"].lower() != row["email"].lower()
        ):
            raise InvalidToken()
        return row

    def confirm_password_reset(
        self, token: str, new_password: str, *, ip: str | None, request_id: str | None = None
    ) -> None:
        """Set a new password with a reset token. Spends the token (and every other open reset
        token of the user), marks the address verified (the link arrived there) and ends all
        sessions of the user. A password the policy refuses keeps the token usable."""
        if not self.settings.security.password_login:
            raise Forbidden("password login is disabled")
        bucket = f"pwreset-confirm:{ip}"
        self.hit(bucket, self.settings.security.login_rate_per_minute)
        with self.db.transaction(DbScope.platform()) as tx:
            row = self._consume_account_token(tx, token, "password_reset")
            if not row["password_hash"]:
                raise InvalidToken()
            check_policy(
                new_password,
                min_length=self.settings.security.password_min_length,
                email=row["current_email"],
                field="new_password",
            )
            user_id = row["user_id"]
            tx.execute(
                "UPDATE axentra_users SET password_hash = %s,"
                " email_verified_at = coalesce(email_verified_at, now()), updated_at = now() WHERE id = %s",
                (hash_password(new_password), user_id),
            )
            tx.execute(
                "UPDATE axentra_account_tokens SET used_at = now()"
                " WHERE user_id = %s AND purpose = 'password_reset' AND used_at IS NULL",
                (user_id,),
            )
            ended = tx.execute(
                "UPDATE axentra_sessions SET revoked_at = now() WHERE user_id = %s AND revoked_at IS NULL",
                (user_id,),
            )
            self.audit.record(
                tx,
                None,
                "identity.password.reset",
                target_type="user",
                target_id=user_id,
                actor_override=("user", user_id, row["current_email"]),
                details={"sessions_ended": ended},
                ip=ip,
                request_id=request_id,
            )
        self.refund(bucket)

    def request_email_verification(
        self, principal: Principal, *, product_hint: str | None = None, request_id: str | None = None
    ) -> AccountEmail:
        """Send the signed-in user a link that confirms their address (``409`` when it is already
        confirmed, ``429`` within a minute of the last link)."""
        user_id = self._require_user(principal)
        with self.db.transaction(DbScope.platform()) as tx:
            row = tx.one_or_404(
                "SELECT email, email_verified_at, locale FROM axentra_users WHERE id = %s FOR UPDATE",
                (user_id,),
            )
            if not row["email"]:
                raise Forbidden("this account has no email address")
            if row["email_verified_at"] is not None:
                raise Conflict("the email address is already verified")
            if self._recently_sent(tx, user_id, "email_verification"):
                raise RateLimited(
                    "a verification email was sent less than a minute ago",
                    retry_after=int(ACCOUNT_EMAIL_COOLDOWN.total_seconds()),
                )
            product_id = self._account_product(tx, user_id, product_hint)
            if product_id is None:
                raise Conflict("no product of this account can send email")
            token_id, token, expires_at = self._issue_account_token(
                tx,
                user_id,
                row["email"],
                "email_verification",
                VERIFY_TOKEN_PREFIX,
                timedelta(hours=self.settings.security.email_verification_hours),
            )
            self.audit.record(
                tx,
                principal,
                "identity.email.verification_request",
                target_type="user",
                target_id=user_id,
                details={"product_id": product_id},
            )
        return AccountEmail(
            purpose="email_verification",
            token_id=token_id,
            token=token,
            user_id=user_id,
            email=row["email"],
            locale=row["locale"],
            product_id=product_id,
            expires_at=expires_at,
        )

    def confirm_email_verification(
        self, token: str, *, ip: str | None, request_id: str | None = None
    ) -> None:
        """Mark the address verified with a verification token (no session needed)."""
        bucket = f"verify-confirm:{ip}"
        self.hit(bucket, self.settings.security.login_rate_per_minute)
        with self.db.transaction(DbScope.platform()) as tx:
            row = self._consume_account_token(tx, token, "email_verification")
            user_id = row["user_id"]
            tx.execute(
                "UPDATE axentra_users SET email_verified_at = coalesce(email_verified_at, now()),"
                " updated_at = now() WHERE id = %s",
                (user_id,),
            )
            tx.execute(
                "UPDATE axentra_account_tokens SET used_at = now()"
                " WHERE user_id = %s AND purpose = 'email_verification' AND used_at IS NULL",
                (user_id,),
            )
            self.audit.record(
                tx,
                None,
                "identity.email.verify",
                target_type="user",
                target_id=user_id,
                actor_override=("user", user_id, row["current_email"]),
                ip=ip,
                request_id=request_id,
            )
        self.refund(bucket)

    # -- external identities (OIDC) ----------------------------------------------------------------

    def link_external_identity(
        self,
        *,
        provider: str,
        subject: str,
        email: str,
        name: str,
        email_verified: bool,
        allow_signup: bool,
        allowed_domains: list[str],
        link_by_verified_email: bool = True,
        allow_signup_without_email: bool = False,
        ip: str | None = None,
        request_id: str | None = None,
    ) -> str:
        """Find the user for an external identity ``(provider, subject)``; for an unknown one,
        link an existing user or create one:

        - With a verified email and ``link_by_verified_email`` (default), an existing user with
          that email is linked. Otherwise a new user is created when ``allow_signup`` is set or an
          open invitation exists for the email.
        - With ``link_by_verified_email=False``, an unknown identity is never linked to an existing
          user. A new user is created (``allow_signup`` or an invitation); if another user already
          has the email, the new user is created *without* an email address (only
          ``allow_signup``; the identity keeps the email for reference), so the existing account is
          never taken over and never merged.
        - Without a verified email, a user without an email address is created only when both
          ``allow_signup`` and ``allow_signup_without_email`` are set; otherwise ``403
          email_not_verified``.
        """
        with self.db.transaction(DbScope.platform()) as tx:
            row = tx.one(
                "SELECT user_id FROM axentra_user_identities WHERE provider = %s AND subject = %s",
                (provider, subject),
            )
            if row:
                user_id: str = row["user_id"]
            else:
                verified = bool(email and email_verified)
                if verified:
                    email = normalize_email(email)
                    if allowed_domains and email.rpartition("@")[2] not in allowed_domains:
                        raise Forbidden(
                            "this email domain may not log in", extra={"reason": "domain_not_allowed"}
                        )
                elif not (allow_signup and allow_signup_without_email):
                    raise Forbidden(
                        "the identity provider did not confirm an email address",
                        extra={"reason": "email_not_verified"},
                    )
                existing = self.find_user_by_email(tx, email) if verified else None
                user_email: str | None = email if verified else None
                how = "created"
                if existing and link_by_verified_email:
                    user_id = existing["id"]
                    how = "linked_by_email"
                elif existing:
                    if not allow_signup:
                        raise Forbidden(
                            "no account exists for this login", extra={"reason": "signup_disabled"}
                        )
                    user_id = self.create_user(tx, email=None, name=name)
                    user_email = None
                    how = "created_without_email"
                elif (
                    not verified
                    or allow_signup
                    or tx.one(
                        "SELECT 1 FROM axentra_invitations WHERE lower(email) = lower(%s) AND accepted_at IS NULL"
                        " AND revoked_at IS NULL AND expires_at > now() LIMIT 1",
                        (email,),
                    )
                ):
                    user_id = self.create_user(tx, email=user_email, name=name, email_verified=verified)
                else:
                    raise Forbidden("no account exists for this login", extra={"reason": "signup_disabled"})
                tx.execute(
                    "INSERT INTO axentra_user_identities (id, user_id, provider, subject, email)"
                    " VALUES (%s, %s, %s, %s, %s)",
                    (new_id("uid"), user_id, provider, subject, email if verified else ""),
                )
                self.audit.record(
                    tx,
                    None,
                    "identity.external.link",
                    target_type="user",
                    target_id=user_id,
                    details={"provider": provider, "how": how},
                    actor_override=("user", user_id, user_email or name[:200]),
                    ip=ip,
                    request_id=request_id,
                )
            status = tx.scalar("SELECT status FROM axentra_users WHERE id = %s", (user_id,))
            if status != "active":
                raise Forbidden("this account is disabled", extra={"reason": "account_disabled"})
        return user_id

    # -- explicit linking (migrations, imports) ---------------------------------------------------

    @staticmethod
    def _require_platform_admin(principal: Principal) -> None:
        if principal.platform_role is not PlatformRole.ADMIN:
            raise Forbidden("only platform admins can manage external identities")

    @staticmethod
    def _check_identity(provider: str, subject: str) -> None:
        if not provider or len(provider) > 500 or not subject or len(subject) > 500:
            raise ValidationFailed("provider and subject must be 1-500 characters")

    def create_external_user(
        self,
        principal: Principal,
        *,
        provider: str,
        subject: str,
        email: str | None = None,
        email_verified: bool = False,
        name: str = "",
    ) -> User:
        """Create a user together with its external identity (for migrations and imports).

        ``provider`` is the issuer the OIDC login uses (``oidc[].issuer``). The email becomes the
        user's address only when ``email_verified``; otherwise the user has no email address and
        the identity row keeps the unverified value for reference. Refuses an identity that
        exists (``409``) and a verified email that another user has (``409``). Platform admins
        (or a system principal) only; audited as ``identity.external.create``."""
        self._require_platform_admin(principal)
        self._check_identity(provider, subject)
        user_email = normalize_email(email) if email and email_verified else None
        with self.db.transaction(DbScope.platform()) as tx:
            if tx.one(
                "SELECT 1 FROM axentra_user_identities WHERE provider = %s AND subject = %s",
                (provider, subject),
            ):
                raise Conflict("this external identity is already linked")
            user_id = self.create_user(tx, email=user_email, name=name, email_verified=True)
            tx.execute(
                "INSERT INTO axentra_user_identities (id, user_id, provider, subject, email)"
                " VALUES (%s, %s, %s, %s, %s)",
                (new_id("uid"), user_id, provider, subject, (email or "").strip()[:320]),
            )
            self.audit.record(
                tx,
                principal,
                "identity.external.create",
                target_type="user",
                target_id=user_id,
                details={"provider": provider, "email_verified": user_email is not None},
            )
        return self.get_user(user_id)

    def link_identity(self, principal: Principal, user_id: str, *, provider: str, subject: str) -> None:
        """Link an external identity to an existing user (for migrations and imports).

        Refuses an identity that is already linked (to this or another user, ``409``) and an
        unknown user (``404``). Platform admins (or a system principal) only; audited as
        ``identity.external.link``."""
        self._require_platform_admin(principal)
        self._check_identity(provider, subject)
        with self.db.transaction(DbScope.platform()) as tx:
            tx.one_or_404("SELECT id FROM axentra_users WHERE id = %s FOR UPDATE", (user_id,), what="user")
            inserted = tx.one(
                "INSERT INTO axentra_user_identities (id, user_id, provider, subject) VALUES (%s, %s, %s, %s)"
                " ON CONFLICT (provider, subject) DO NOTHING RETURNING id",
                (new_id("uid"), user_id, provider, subject),
            )
            if inserted is None:
                raise Conflict("this external identity is already linked")
            self.audit.record(
                tx,
                principal,
                "identity.external.link",
                target_type="user",
                target_id=user_id,
                details={"provider": provider, "how": "explicit"},
            )

    def list_identities(self, user_id: str) -> list[Row]:
        """The external identities of a user (provider, subject, email, created_at)."""
        with self.db.transaction(DbScope.platform(), read_only=True) as tx:
            return tx.all(
                "SELECT provider, subject, email, created_at FROM axentra_user_identities WHERE user_id = %s"
                " ORDER BY created_at, id",
                (user_id,),
            )
