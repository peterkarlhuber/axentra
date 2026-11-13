"""Grep rule for session settings (TABRION QA-25, MIG-T-AXE-2 part 1; invariant AX-I-2 of the Tabrion plan).

The scope (``axentra.scope``, ``axentra.product_id``, ``axentra.tenant_id``) is set only transaction-locally
(``set_config(..., true)``), so a pooled connection never carries a tenant to its next user. Session-wide settings are
allowed only for time limits, ``application_name`` and ``search_path`` when a connection is set up. This rule reads
the source of Axentra and, once it is installed (TABRION MIG-AXE-1 and later), of Tabrion, so a helper that moves to
Tabrion is held to the same rule:

- ``set_config('<name>', ..., false)`` only for the allowed names; a dynamic name with ``false`` only at the listed
  places (each checked by hand: they set a timeout);
- ``set_config('axentra.*', ..., <anything but true>)`` never, including a flag passed as a parameter (``%s``,
  ``%(local)s``): it is not proven transaction-local;
- ``set_config(<other name>, ..., <parameter>)``: not proven local either, so it counts as a dynamic site;
- no ``SET`` / ``SET SESSION`` statement of a setting (``SET LOCAL`` and ``SET TRANSACTION`` are transaction-local),
  and no ``SET``/``RESET`` of a scope name at all.

The part 2 of MIG-T-AXE-2 records the statements Axentra's helpers really run
(``tests/integration/test_adoption_security.py``).
"""

from __future__ import annotations

from collections import Counter
from importlib.util import find_spec
from pathlib import Path
import re

import pytest

ROOT = Path(__file__).resolve().parents[2]
#: Session-wide settings a connection may get when it is set up (document 07, AX-I-2).
SESSION_ALLOWED = {"statement_timeout", "lock_timeout", "idle_in_transaction_session_timeout", "application_name",
                   "search_path"}  # fmt: skip
#: ``set_config(%s, %s, false)`` with a dynamic name: file -> number of such calls, each reviewed.
DYNAMIC_SESSION_SITES = {
    # MigrationRunner: the runner's own lock_timeout / statement_timeout around a no-transaction migration.
    "axentra/data/migrations.py": 1,
    # Tabrion v0.1.0 tabrion.postgres.configure (_apply, and its docstring): set_config(%s, %s, false) of
    # SessionSettings, whose names are a fixed list (the four timeouts, application_name, search_path, TimeZone);
    # reviewed for TABRION VER-1 (CI installs Tabrion).
    "tabrion/postgres/__init__.py": 2,
}
#: Findings in Tabrion's source, each checked by hand (TABRION VER-1, Tabrion v0.1.0): finding -> count. A Tabrion
#: update that changes them fails the test, so the new sites are reviewed before the pin moves.
REVIEWED_FINDINGS = {
    # Docstrings and comments that explain SET ROLE (contract I-20 of role_info and grant_runtime_role); no statement.
    "tabrion/postgres/roles.py: `SET ROLE": 3,
    # tabrion.sqlalchemy's read-only profile turns default_transaction_read_only on for its own connections: it only
    # makes a session stricter and carries no scope. Axentra does not use tabrion.sqlalchemy.
    "tabrion/_sa/events.py: session-wide setting default_transaction_read_only is not allowed:"
    " set_config('default_transaction_read_only', 'on', false)": 1,
}
SET_CONFIG = re.compile(r"set_config\(\s*(?P<name>'[^']*'|%s|%\(\w+\)s|\{\w*\})\s*,(?P<value>(?:%\(\w+\)s|'[^']*'|\[[^\]]*\]|\((?:[^()]|\((?:[^()]|\([^()]*\))*\))*\)|[^,()'\[\]])*),\s*(?P<local>%s|%\(\w+\)s|\{\w*\}|\w+)\s*\)",
                        re.IGNORECASE)  # fmt: skip
#: A ``SET`` statement at the start of a string or SQL line (``UPDATE ... SET col =`` is not one).
SET_STATEMENT = re.compile(r"""(?:^|["'`;])\s*SET\s+(?!LOCAL\b|TRANSACTION\b|CONSTRAINTS\b)(?:SESSION\s+)?(?P<name>[A-Za-z_][\w.]*)""",
                           re.MULTILINE)  # fmt: skip
SCOPE_NAME = re.compile(r"\b(?:SET|RESET)\s+(?:LOCAL\s+|SESSION\s+)?axentra\.")


def sources() -> list[tuple[str, str]]:
    """``(relative path, text)`` of every Python and SQL file of Axentra and, if installed, Tabrion."""
    roots = [ROOT / "src" / "axentra"]
    spec = find_spec("tabrion")
    if spec is not None and spec.submodule_search_locations:
        roots += [Path(p) for p in spec.submodule_search_locations]
    found = []
    for root in roots:
        for path in sorted(root.rglob("*")):
            if path.suffix in (".py", ".sql"):
                found.append((f"{root.name}/{path.relative_to(root).as_posix()}", path.read_text("utf-8")))
    return found


def violations(path: str, text: str) -> tuple[list[str], int]:
    """The rule's findings in one file, and how many dynamic session ``set_config`` calls it has."""
    found: list[str] = []
    dynamic = 0
    for m in SET_CONFIG.finditer(text):
        name, local = m["name"].strip("'"), m["local"].lower()
        if name.startswith("axentra.") and local != "true":
            found.append(f"{path}: scope setting {name} not transaction-local: {m[0]}")
        elif local not in ("true", "false"):
            dynamic += (
                1  # the flag is a parameter: not proven transaction-local, reviewed like a dynamic name
            )
        elif local == "false":
            if m["name"].startswith("'"):
                if name not in SESSION_ALLOWED:
                    found.append(f"{path}: session-wide setting {name} is not allowed: {m[0]}")
            else:
                dynamic += 1
    for m in SET_STATEMENT.finditer(text):
        name = m["name"].lower()
        if name in (
            "role",
            "session",
        ):  # SET ROLE / SET SESSION AUTHORIZATION: no setting, but never in Axentra
            found.append(f"{path}: {m[0].strip()}")
        elif name not in SESSION_ALLOWED or name.startswith("axentra."):
            found.append(f"{path}: session-wide SET of {name}: {m[0].strip()}")
    found += [f"{path}: SET/RESET of a scope setting: {m[0]}" for m in SCOPE_NAME.finditer(text)]
    return found, dynamic


def test_no_session_wide_scope_or_unlisted_session_setting() -> None:
    found: list[str] = []
    dynamic: dict[str, int] = {}
    scanned = set()
    for path, text in sources():
        scanned.add(path)
        problems, count = violations(path, text)
        found += problems
        if count:
            dynamic[path] = count
    # The reviewed entries of files this run scanned (Tabrion's only when it is installed).
    reviewed = {k: v for k, v in REVIEWED_FINDINGS.items() if k.split(": ", 1)[0] in scanned}
    assert dict(Counter(found)) == reviewed
    assert dynamic == {k: v for k, v in DYNAMIC_SESSION_SITES.items() if k in scanned}


@pytest.mark.parametrize(
    "snippet",
    [
        "SELECT set_config('axentra.tenant_id', %s, false)",
        "SELECT set_config('axentra.scope', %s, is_local)",
        "SELECT set_config('axentra.scope', %s, %s)",
        "SELECT set_config('axentra.tenant_id', %s, %(local)s)",
        # Values with calls, commas inside parentheses, string literals and arrays (review M-1 of #76).
        "SELECT set_config('axentra.tenant_id', coalesce(%s, ''), false)",
        "SELECT set_config('axentra.scope', CASE WHEN x = ANY (ARRAY['a', 'b']) THEN 'p, q' ELSE f(g(%s), 1) END, false)",
        "SELECT set_config('work_mem', concat(%s, 'MB'), false)",
        "SELECT set_config('axentra.product_id', %s, {local})",
        "SELECT set_config('work_mem', %s, false)",
        '"SET axentra.tenant_id = 1"',
        '"SET SESSION statement_timeout_x = 1"',
        "f\"SET LOCAL axentra.product_id = '{x}'\"",
        '"RESET axentra.scope"',
        '"SET ROLE admin"',
    ],
)
def test_the_rule_finds_what_it_forbids(snippet: str) -> None:
    """Mutation probe: each forbidden form is found."""
    problems, _ = violations("probe.py", snippet)
    assert problems, snippet


@pytest.mark.parametrize(
    "snippet",
    [
        "SELECT set_config(%s, %s, false)",
        "SELECT set_config('statement_timeout', %s, %s)",
        "SELECT set_config(%(name)s, %(value)s, %(local)s)",
    ],
)
def test_a_dynamic_or_parameterised_session_setting_counts_as_a_reviewed_site(snippet: str) -> None:
    problems, dynamic = violations("probe.py", snippet)
    assert problems == [] and dynamic == 1, snippet


@pytest.mark.parametrize(
    "snippet",
    [
        "SELECT set_config('axentra.scope', %s, true), set_config('axentra.product_id', %s, true)",
        "SELECT set_config('statement_timeout', %s, false)",
        '"SET LOCAL statement_timeout = 0"',
        '"SET TRANSACTION READ ONLY"',
        '"UPDATE axentra_users SET email = NULL WHERE id = %s"',
        '" ON CONFLICT (user_id) DO UPDATE SET role = EXCLUDED.role"',
    ],
)
def test_the_rule_allows_transaction_local_settings(snippet: str) -> None:
    problems, dynamic = violations("probe.py", snippet)
    assert problems == [] and dynamic == 0, snippet
