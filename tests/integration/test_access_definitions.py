"""Versioned access definitions: deterministic, idempotent, conflict-aware registration (no "last start wins")."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import threading

import pytest

from axentra.access.definitions import AccessDefinitions, RoleDefinition
from axentra.access.product_permissions import ProductPermission
from axentra.core.context import Actor, ActorKind, Principal
from axentra.core.errors import Conflict, NotFound, ValidationFailed
from axentra.data.database import DbScope
from axentra.platform import Axentra

READ = ProductPermission("crm.deals:read", "tenant", "Read deals", default_roles=("viewer",))
EDIT = ProductPermission("crm.deals:edit", "tenant", "Change deals")
EXPORT = ProductPermission("crm.reports:export", "tenant", "Export reports")
SALES = RoleDefinition("sales", "Sales", "tenant", ("crm.deals:read", "crm.deals:edit", "tenant:read"))

V1 = AccessDefinitions(1, (READ, EDIT), (SALES,))
V2 = AccessDefinitions(
    2,
    (READ, EXPORT),
    (RoleDefinition("sales", "Sales", "tenant", ("crm.deals:read", "crm.reports:export", "tenant:read")),),
)


def _product(ax: Axentra) -> str:
    product = ax.tenancy.single_product()
    assert product is not None
    return product.id


def _role(ax: Axentra, pid: str, key: str) -> dict:
    with ax.db.transaction(DbScope.platform(), read_only=True) as tx:
        return tx.one("SELECT * FROM axentra_roles WHERE product_id = %s AND key = %s", (pid, key))


def _active(ax: Axentra, pid: str) -> list[str]:
    return sorted(r.permission.name for r in ax.permissions.records(pid))


def _events(ax: Axentra, pid: str) -> list[dict]:
    with ax.db.transaction(DbScope.platform(), read_only=True) as tx:
        return tx.all(
            "SELECT outcome, details FROM axentra_audit_events WHERE action = 'access.definitions.apply'"
            " AND product_id = %s ORDER BY occurred_at, id",
            (pid,),
        )


@pytest.fixture
def ax(ax_factory) -> Axentra:  # type: ignore[no-untyped-def]
    return ax_factory(mode="single", product={"slug": "crm", "name": "CRM"})


def test_the_first_application_writes_permissions_roles_and_an_audit_event(ax: Axentra) -> None:
    pid = _product(ax)
    result = ax.access_definitions.apply("crm", V1, applied_by="crm 1.0")
    assert result.outcome == "applied" and result.stored_revision is None
    assert result.permissions["added"] == ["crm.deals:edit", "crm.deals:read"]
    assert result.roles["created"] == ["sales"]
    assert _active(ax, pid) == ["crm.deals:edit", "crm.deals:read"]
    assert sorted(_role(ax, pid, "sales")["permissions"]) == [
        "crm.deals:edit",
        "crm.deals:read",
        "tenant:read",
    ]
    stored = ax.access_definitions.current(pid)
    assert stored is not None and stored.revision == 1 and stored.content_hash == V1.content_hash
    assert stored.roles == ("sales",) and stored.applied_by == "crm 1.0"
    [event] = _events(ax, pid)
    assert event["outcome"] == "success" and event["details"]["revision"] == 1
    assert event["details"]["previous_revision"] is None


def test_the_same_revision_again_is_a_no_op(ax: Axentra) -> None:
    pid = _product(ax)
    ax.access_definitions.apply(pid, V1)
    before = _role(ax, pid, "sales")["version"]
    again = ax.access_definitions.apply(pid, V1)
    assert again.outcome == "unchanged" and again.stored_revision == 1
    assert _role(ax, pid, "sales")["version"] == before
    assert len(_events(ax, pid)) == 1


def test_the_order_of_definitions_does_not_change_the_hash() -> None:
    shuffled = AccessDefinitions(1, (EDIT, READ), (SALES,))
    reordered_role = AccessDefinitions(
        1,
        (READ, EDIT),
        (RoleDefinition("sales", "Sales", "tenant", ("tenant:read", "crm.deals:edit", "crm.deals:read")),),
    )
    assert shuffled.content_hash == V1.content_hash == reordered_role.content_hash
    assert V2.content_hash != V1.content_hash


def test_a_newer_revision_applies_and_an_older_process_never_downgrades(ax: Axentra) -> None:
    pid = _product(ax)
    ax.access_definitions.apply(pid, V1)
    newer = ax.access_definitions.apply(pid, V2)
    assert newer.outcome == "applied" and newer.stored_revision == 1
    assert newer.permissions == {
        "added": ["crm.reports:export"],
        "updated": [],
        "reactivated": [],
        "retired": ["crm.deals:edit"],
    }
    assert newer.roles["updated"] == ["sales"]
    # An old process (revision 1) starts again during a rolling deployment: nothing changes.
    old = ax.access_definitions.apply(pid, V1)
    assert old.outcome == "stale" and old.stored_revision == 2
    assert _active(ax, pid) == ["crm.deals:read", "crm.reports:export"]
    assert "crm.deals:edit" not in _role(ax, pid, "sales")["permissions"]
    assert ax.access_definitions.current(pid).revision == 2  # type: ignore[union-attr]
    assert [e["details"]["revision"] for e in _events(ax, pid)] == [1, 2]


def test_the_same_revision_with_other_content_is_refused_and_audited(ax: Axentra) -> None:
    pid = _product(ax)
    ax.access_definitions.apply(pid, V1)
    other = AccessDefinitions(1, (READ,), (SALES,))
    with pytest.raises(Conflict):
        ax.access_definitions.apply(pid, other)
    assert _active(ax, pid) == ["crm.deals:edit", "crm.deals:read"]
    events = _events(ax, pid)
    assert [e["outcome"] for e in events] == ["success", "denied"]
    assert events[1]["details"]["reason"] == "conflict"


def test_concurrent_applications_apply_a_revision_once(ax: Axentra) -> None:
    pid = _product(ax)
    barrier = threading.Barrier(6)

    def apply(definitions: AccessDefinitions) -> str:
        barrier.wait()
        return ax.access_definitions.apply(pid, definitions).outcome

    with ThreadPoolExecutor(6) as pool:
        outcomes = list(pool.map(apply, [V1, V2, V1, V2, V1, V2]))
    # Whatever the order, revision 2 wins and is applied exactly once; revision 1 at most once (before it).
    assert outcomes.count("applied") in (1, 2)
    assert ax.access_definitions.current(pid).revision == 2  # type: ignore[union-attr]
    assert _active(ax, pid) == ["crm.deals:read", "crm.reports:export"]
    assert [e["details"]["revision"] for e in _events(ax, pid)][-1] == 2
    assert len([e for e in _events(ax, pid) if e["details"]["revision"] == 2]) == 1


def test_managed_roles_are_changed_only_by_code(ax: Axentra) -> None:
    pid = _product(ax)
    ax.access_definitions.apply(pid, V1)
    role_id = _role(ax, pid, "sales")["id"]
    system = Principal.system("test")
    with pytest.raises(Conflict):
        ax.roles.update_role(system, pid, role_id, permissions=["tenant:read"])
    with pytest.raises(Conflict):
        ax.roles.delete_role(system, pid, role_id)
    # Other custom roles stay editable.
    other = ax.roles.create_role(
        system, pid, key="helper", name="Helper", scope="tenant", permissions=["tenant:read"]
    )
    ax.roles.update_role(system, pid, other.id or "", permissions=["tenant:read", "crm.deals:read"])


def test_a_released_role_is_kept_and_becomes_editable(ax: Axentra) -> None:
    pid = _product(ax)
    ax.access_definitions.apply(pid, V1)
    result = ax.access_definitions.apply(pid, AccessDefinitions(2, (READ, EDIT), ()))
    assert result.roles["released"] == ["sales"]
    role = _role(ax, pid, "sales")
    assert role is not None
    ax.roles.update_role(Principal.system("test"), pid, role["id"], permissions=["tenant:read"])


def test_the_unversioned_registration_never_overwrites_versioned_definitions(ax: Axentra) -> None:
    pid = _product(ax)
    ax.access_definitions.apply(pid, V2)
    ax.permissions.register("crm", [EDIT])  # an old build that still registers in process
    [report] = ax.permissions.sync("crm")
    assert report.skipped and not report.changed
    assert _active(ax, pid) == ["crm.deals:read", "crm.reports:export"]


def test_role_grants_follow_the_applied_revision_at_once(ax: Axentra) -> None:
    pid = _product(ax)
    tenant = ax.tenancy.create_tenant(Principal.system("test"), pid, slug="acme", name="Acme")
    user = ax.identity.create_external_user(Principal.system("test"), provider="https://idp", subject="s1")
    ax.access_definitions.apply(pid, V1)
    ax.tenancy.set_member(Principal.system("test"), pid, tenant.id, role="sales", user_id=user.id)
    principal = Principal(actor=Actor(ActorKind.USER, user.id))
    assert ax.authz.has(principal, "crm.deals:edit", pid, tenant.id)
    ax.access_definitions.apply(pid, V2)
    assert not ax.authz.has(principal, "crm.deals:edit", pid, tenant.id)
    assert ax.authz.has(principal, "crm.reports:export", pid, tenant.id)


@pytest.mark.parametrize(
    "bad",
    [
        AccessDefinitions(0),
        AccessDefinitions(1, (), (RoleDefinition("viewer", "Viewer", "tenant"),)),
        AccessDefinitions(1, (), (RoleDefinition("Bad Key", "X", "tenant"),)),
        AccessDefinitions(1, (), (SALES, SALES)),
        AccessDefinitions(1, (READ,), (RoleDefinition("x1", "X", "tenant", ("platform:admin",)),)),
    ],
)
def test_invalid_definitions_are_refused(ax: Axentra, bad: AccessDefinitions) -> None:
    with pytest.raises(ValidationFailed):
        ax.access_definitions.apply(_product(ax), bad)
    assert ax.access_definitions.current(_product(ax)) is None


def test_an_unknown_product_is_not_found(ax: Axentra) -> None:
    with pytest.raises(NotFound):
        ax.access_definitions.apply("nope", V1)


def test_drift_reports_differences(ax: Axentra) -> None:
    pid = _product(ax)
    assert ax.access_definitions.drift(pid, V1) == [
        "no access definitions applied",
        "permission crm.deals:edit: missing or retired",
        "permission crm.deals:read: missing or retired",
        "role sales: missing",
    ]
    ax.access_definitions.apply(pid, V1)
    assert ax.access_definitions.drift(pid, V1) == []
    with ax.db.transaction(DbScope.platform()) as tx:
        tx.execute(
            "UPDATE axentra_roles SET permissions = '{tenant:read}' WHERE product_id = %s AND key = 'sales'",
            (pid,),
        )
    assert ax.access_definitions.drift(pid, V1) == ["role sales: permissions differ"]
