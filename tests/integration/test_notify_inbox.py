"""In-app inbox notifications (channel ``inbox``): stored for the recipient user, never delivered externally."""

from __future__ import annotations

import pytest

from axentra.core.context import Actor, ActorKind, Principal
from axentra.core.errors import Conflict, Forbidden, ValidationFailed
from axentra.data.database import DbScope
from tests.integration.conftest import World
from tests.integration.test_notify import _member, _product, _template, _tenant

INBOX = {"subject": "Run {{ name }} failed", "text": "The run {{ name }} failed."}


def _user(uid: str) -> Principal:
    return Principal(actor=Actor(ActorKind.USER, uid, "user"))


class Recording:
    name = "recording"

    def __init__(self) -> None:
        self.sent: list[object] = []

    def send(self, message: object) -> str:  # pragma: no cover - must never be called for the inbox
        self.sent.append(message)
        return "never"

    def check(self) -> bool:
        return True


def test_inbox_messages_are_stored_for_the_user_and_never_reach_a_provider(world: World) -> None:
    ax = world.ax
    provider = Recording()
    ax.notify.set_provider(provider)
    pid = _product(world)
    tid = _tenant(world, pid)
    other_tid = _tenant(world, pid, "globex")
    _template(world, pid, key="run.failed", channel="inbox", category="runs", variants={"en": INBOX})
    bob = _member(world, pid, tid, "bob@example.com")
    alice = _member(world, pid, tid, "alice@example.com")
    _member(world, pid, other_tid, "carl@example.com")

    sent = ax.notify.enqueue_system(
        pid, tid, template_key="run.failed", to_user_id=bob, variables={"name": "R1"}, idempotency_key="ev-1"
    )
    assert (
        sent.message.status == "sent" and sent.message.channel == "inbox" and sent.message.provider == "inbox"
    )
    assert sent.message.recipient == "" and not sent.replayed
    # The same event again (a retried worker): nothing new.
    again = ax.notify.enqueue_system(
        pid, tid, template_key="run.failed", to_user_id=bob, variables={"name": "R1"}, idempotency_key="ev-1"
    )
    assert again.replayed and again.message.id == sent.message.id
    with pytest.raises(Conflict):  # the same key for different content is refused, never sent twice
        ax.notify.enqueue_system(
            pid,
            tid,
            template_key="run.failed",
            to_user_id=bob,
            variables={"name": "R2"},
            idempotency_key="ev-1",
        )
    with pytest.raises(ValidationFailed):  # an inbox has no address
        ax.notify.enqueue_system(pid, tid, template_key="run.failed", to_email="bob@example.com")
    ax.notify.enqueue_system(pid, tid, template_key="run.failed", to_user_id=bob, variables={"name": "R3"})

    # The dispatcher never claims an inbox message: no external side effect.
    assert ax.notify.dispatcher().run_once(10).claimed == 0
    assert provider.sent == []

    page = ax.notify.list_inbox(_user(bob), pid, tid)
    assert [item.subject for item in page.items] == ["Run R3 failed", "Run R1 failed"]
    assert page.items[0].text == "The run R3 failed." and page.items[0].read_at is None
    assert ax.notify.unread_count(_user(bob), pid, tid) == 2
    # Alice sees nothing of Bob's; marking Bob's message as Alice changes nothing.
    assert ax.notify.list_inbox(_user(alice), pid, tid).items == []
    assert ax.notify.mark_read(_user(alice), pid, tid, message_ids=[sent.message.id]) == 0
    assert ax.notify.mark_read(_user(bob), pid, tid, message_ids=[sent.message.id]) == 1
    assert ax.notify.mark_read(_user(bob), pid, tid, message_ids=[sent.message.id]) == 0
    assert ax.notify.unread_count(_user(bob), pid, tid) == 1
    assert [i.subject for i in ax.notify.list_inbox(_user(bob), pid, tid, unread_only=True).items] == [
        "Run R3 failed"
    ]
    assert ax.notify.mark_read(_user(bob), pid, tid) == 1
    assert ax.notify.unread_count(_user(bob), pid, tid) == 0
    # Pagination.
    first = ax.notify.list_inbox(_user(bob), pid, tid, limit=1)
    assert len(first.items) == 1 and first.next_cursor
    assert len(ax.notify.list_inbox(_user(bob), pid, tid, cursor=first.next_cursor).items) == 1
    # Only users have an inbox.
    with pytest.raises(Forbidden):
        ax.notify.list_inbox(Principal.system(), pid, tid)
    # Content is encrypted at rest like any message.
    with ax.db.transaction(DbScope.platform()) as tx:
        row = tx.one("SELECT subject_enc FROM axentra_notify_messages WHERE id = %s", (sent.message.id,))
    assert row["subject_enc"].startswith("axs1.") and "R1" not in row["subject_enc"]


def test_inbox_respects_opt_outs_and_users_without_email(world: World) -> None:
    ax = world.ax
    pid = _product(world)
    tid = _tenant(world, pid)
    _template(world, pid, key="run.failed", channel="inbox", category="runs", variants={"en": INBOX})
    bob = _member(world, pid, tid, "bob@example.com")
    ax.notify.set_preferences(_user(bob), pid, tid, opted_out=["runs"])
    result = ax.notify.enqueue_system(
        pid, tid, template_key="run.failed", to_user_id=bob, variables={"name": "x"}
    )
    assert result.message.status == "suppressed"
    assert ax.notify.list_inbox(_user(bob), pid, tid).items == []
    # A user without an e-mail address (external identity) still gets inbox notifications.
    nomail = ax.identity.create_external_user(
        Principal.system(), provider="https://id.example", subject="s-1", name="N"
    ).id
    ax.tenancy.set_member(Principal.system(), pid, tid, role="member", user_id=nomail)
    stored = ax.notify.enqueue_system(
        pid, tid, template_key="run.failed", to_user_id=nomail, variables={"name": "y"}
    )
    assert stored.message.status == "sent"
    assert [i.subject for i in ax.notify.list_inbox(_user(nomail), pid, tid).items] == ["Run y failed"]
