"""The subscription state machine: only these transitions are allowed (same -> same is a no-op)."""

from __future__ import annotations

from axentra.core.errors import Conflict

STATUSES = ("incomplete", "trialing", "active", "past_due", "canceled")

TRANSITIONS: dict[str, frozenset[str]] = {
    "incomplete": frozenset({"trialing", "active", "canceled"}),
    "trialing": frozenset({"active", "past_due", "canceled"}),
    "active": frozenset({"past_due", "canceled"}),
    "past_due": frozenset({"active", "canceled"}),
    "canceled": frozenset(),
}

#: Statuses in which the plan's entitlements apply (past_due is a grace state).
ENTITLED = frozenset({"trialing", "active", "past_due"})

#: Provider (Stripe-compatible) subscription statuses mapped to Axentra statuses.
PROVIDER_STATUS = {
    "trialing": "trialing",
    "active": "active",
    "past_due": "past_due",
    "unpaid": "past_due",
    "paused": "past_due",
    "canceled": "canceled",
    "incomplete": "incomplete",
    "incomplete_expired": "canceled",
}


def can_transition(current: str, target: str) -> bool:
    return current == target or target in TRANSITIONS.get(current, frozenset())


def check_transition(current: str, target: str) -> None:
    if not can_transition(current, target):
        raise Conflict(f"a subscription cannot change from {current} to {target}")
