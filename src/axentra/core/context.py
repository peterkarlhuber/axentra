"""The security context that every service call receives explicitly.

A :class:`Principal` is *who* acts (a user with a session, or a machine with an API key) and
what it was granted. Authorization decisions are made by :mod:`axentra.access` from this
object; services never read ambient state (no globals, no thread locals).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum


class ActorKind(StrEnum):
    USER = "user"
    API_KEY = "api_key"
    SYSTEM = "system"


class PlatformRole(StrEnum):
    """Installation-wide roles; ``None`` for ordinary users."""

    ADMIN = "platform_admin"
    VIEWER = "platform_viewer"


@dataclass(frozen=True, slots=True)
class Actor:
    kind: ActorKind
    id: str
    display: str = ""


@dataclass(frozen=True, slots=True)
class Principal:
    """An authenticated caller.

    ``api_key_product_id`` / ``api_key_tenant_id`` / ``api_key_permissions`` are set only for API
    keys and bound the key to one product (and optionally one tenant) with an explicit permission
    list. Users get their permissions from memberships, resolved by the authorizer.
    """

    actor: Actor
    platform_role: PlatformRole | None = None
    session_id: str | None = None
    api_key_product_id: str | None = None
    api_key_tenant_id: str | None = None
    api_key_permissions: frozenset[str] = field(default_factory=frozenset)
    request_id: str | None = None
    ip: str | None = None

    @property
    def user_id(self) -> str | None:
        return self.actor.id if self.actor.kind is ActorKind.USER else None

    @property
    def is_platform_admin(self) -> bool:
        return self.platform_role is PlatformRole.ADMIN

    @classmethod
    def system(cls, reason: str = "system") -> Principal:
        """A trusted in-process caller (CLI, workers). Never created from a request."""
        return cls(actor=Actor(ActorKind.SYSTEM, "system", reason), platform_role=PlatformRole.ADMIN)
