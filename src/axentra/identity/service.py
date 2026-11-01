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
from axentra.core.errors import Conflict, Forbidden, NotFound, RateLimited, Unauthenticated, ValidationFailed
from axentra.core.ids import new_id, new_token
from axentra.core.pagination import Page, clamp_limit, decode_cursor, encode_cursor
from axentra.data.database import Database, DbScope, Row, Tx
from axentra.identity.models import NewSession, Session, SessionInfo, User
from axentra.identity.passwords import check_policy, hash_password, needs_rehash, verify_password
from axentra.identity.tokens import hash_token

logger = logging.getLogger(__name__)

_USER_COLUMNS = (
    "u.id, u.email, u.name, u.status, u.locale, u.preferences, u.created_at, u.updated_at, u.last_login_at,"
    " (u.password_hash IS NOT NULL) AS has_password, pr.role AS platform_role"
)
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
        self, tx: Tx, *, email: str, name: str = "", password: str | None = None, locale: str = "en"
    ) -> str:
        email = normalize_email(email)
        if password is not None:
            check_policy(password, min_length=self.settings.security.password_min_length, email=email)
        if self.find_user_by_email(tx, email):
            raise Conflict("a user with this email address exists")
        user_id = new_id("usr")
        tx.execute(
            "INSERT INTO axentra_users (id, email, name, password_hash, locale) VALUES (%s, %s, %s, %s, %s)",
            (user_id, email, name.strip()[:200], hash_password(password) if password else None, locale),
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
        after = decode_cursor(cursor)
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
        user_id = self._require_user(principal)
        with self.db.transaction(DbScope.platform()) as tx:
            row = tx.one_or_404(
                "SELECT email, password_hash FROM axentra_users WHERE id = %s FOR UPDATE", (user_id,)
            )
            if row["password_hash"] and not verify_password(row["password_hash"], current):
                self.audit.record(
                    tx,
                    principal,
                    "identity.password.change",
                    target_type="user",
                    target_id=user_id,
                    outcome="denied",
                )
                raise Forbidden("the current password is wrong")
            check_policy(new, min_length=self.settings.security.password_min_length, email=row["email"])
            tx.execute(
                "UPDATE axentra_users SET password_hash = %s, updated_at = now() WHERE id = %s",
                (hash_password(new), user_id),
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
        expires = utcnow() + timedelta(minutes=self.settings.security.setup_token_ttl_minutes)
        with self.db.transaction(DbScope.platform()) as tx:
            tx.execute(
                "INSERT INTO axentra_setup_tokens (token_hash, expires_at) VALUES (%s, %s)",
                (hash_token(token), expires),
            )
            self.audit.record(tx, Principal.system("cli"), "identity.setup_token.create")
        return token

    def complete_setup(
        self, token: str, *, email: str, name: str, password: str, ip: str | None, user_agent: str
    ) -> NewSession:
        self.throttle(f"setup:{ip}", self.settings.security.login_rate_per_minute)
        with self.db.transaction(DbScope.platform()) as tx:
            row = tx.one(
                "SELECT token_hash FROM axentra_setup_tokens WHERE token_hash = %s AND used_at IS NULL"
                " AND expires_at > now() FOR UPDATE",
                (hash_token(token),),
            )
            if row is None:
                self.count_failure(f"setup:{ip}")
                raise Unauthenticated("the setup token is invalid or expired")
            if tx.one("SELECT 1 FROM axentra_platform_roles WHERE role = 'platform_admin' LIMIT 1"):
                raise Conflict("setup was already completed")
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
            )
        return self.start_session(user_id, "password", ip=ip, user_agent=user_agent)

    # -- throttling ------------------------------------------------------------------------------

    def _window(self) -> datetime:
        return utcnow().replace(second=0, microsecond=0)

    def throttle(self, bucket: str, limit: int) -> None:
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

    def login_password(self, email: str, password: str, *, ip: str | None, user_agent: str) -> NewSession:
        if not self.settings.security.password_login:
            raise Forbidden("password login is disabled")
        limit = self.settings.security.login_rate_per_minute
        account_bucket = f"login:acct:{email.strip().lower()}"
        ip_bucket = f"login:ip:{ip}"
        self.throttle(ip_bucket, limit * 3)
        self.throttle(account_bucket, limit)
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
            self.count_failure(ip_bucket)
            self.count_failure(account_bucket)
            raise Unauthenticated("wrong email or password")
        assert row is not None
        return self.start_session(row["id"], "password", ip=ip, user_agent=user_agent)

    # -- sessions -------------------------------------------------------------------------------

    def start_session(self, user_id: str, method: str, *, ip: str | None, user_agent: str) -> NewSession:
        token = new_token()
        session_id = new_id("ses")
        csrf = new_token(24)
        expires = utcnow() + timedelta(hours=self.settings.security.session_ttl_hours)
        with self.db.transaction(DbScope.platform()) as tx:
            tx.execute(
                "INSERT INTO axentra_sessions (id, user_id, token_hash, csrf_token, auth_method, ip, user_agent, expires_at)"
                " VALUES (%s, %s, %s, %s, %s, %s, %s, %s)",
                (session_id, user_id, hash_token(token), csrf, method, ip, user_agent[:400], expires),
            )
            tx.execute("UPDATE axentra_users SET last_login_at = now() WHERE id = %s", (user_id,))
            self.audit.record(
                tx,
                None,
                "identity.login",
                target_type="session",
                target_id=session_id,
                details={"method": method},
                actor_override=("user", user_id, ""),
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
        idle = timedelta(minutes=self.settings.security.session_idle_minutes)
        now = utcnow()
        with self.db.transaction(DbScope.platform()) as tx:
            row = tx.one(
                "SELECT s.id, s.user_id, s.csrf_token, s.expires_at, s.last_seen_at, s.revoked_at, u.status"
                " FROM axentra_sessions s JOIN axentra_users u ON u.id = s.user_id WHERE s.token_hash = %s",
                (hash_token(token),),
            )
            if (
                row is None
                or row["revoked_at"] is not None
                or row["status"] != "active"
                or row["expires_at"] <= now
                or row["last_seen_at"] + idle <= now
            ):
                raise Unauthenticated("the session is invalid or expired")
            if now - row["last_seen_at"] > _LAST_SEEN_RESOLUTION:
                tx.execute("UPDATE axentra_sessions SET last_seen_at = now() WHERE id = %s", (row["id"],))
        user = self.get_user(row["user_id"])
        role = PlatformRole(user.platform_role) if user.platform_role else None
        principal = Principal(
            actor=Actor(ActorKind.USER, user.id, user.email),
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
        return n

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
    ) -> str:
        """Find the user for an external identity; link by verified email or create when allowed."""
        with self.db.transaction(DbScope.platform()) as tx:
            row = tx.one(
                "SELECT user_id FROM axentra_user_identities WHERE provider = %s AND subject = %s",
                (provider, subject),
            )
            if row:
                user_id: str = row["user_id"]
            else:
                if not email or not email_verified:
                    raise Forbidden("the identity provider did not confirm an email address")
                email = normalize_email(email)
                if allowed_domains and email.rpartition("@")[2] not in allowed_domains:
                    raise Forbidden("this email domain may not log in")
                existing = self.find_user_by_email(tx, email)
                if existing:
                    user_id = existing["id"]
                elif allow_signup or tx.one(
                    "SELECT 1 FROM axentra_invitations WHERE lower(email) = lower(%s) AND accepted_at IS NULL"
                    " AND revoked_at IS NULL AND expires_at > now() LIMIT 1",
                    (email,),
                ):
                    user_id = self.create_user(tx, email=email, name=name)
                else:
                    raise Forbidden("no account exists for this login")
                tx.execute(
                    "INSERT INTO axentra_user_identities (id, user_id, provider, subject, email)"
                    " VALUES (%s, %s, %s, %s, %s)",
                    (new_id("uid"), user_id, provider, subject, email),
                )
                self.audit.record(
                    tx,
                    None,
                    "identity.external.link",
                    target_type="user",
                    target_id=user_id,
                    details={"provider": provider},
                    actor_override=("user", user_id, email),
                )
            status = tx.scalar("SELECT status FROM axentra_users WHERE id = %s", (user_id,))
            if status != "active":
                raise Forbidden("this account is disabled")
        return user_id
