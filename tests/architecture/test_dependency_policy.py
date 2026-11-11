"""TABRION AC-2 (QA-17): the manifest follows this repository's copy of the dependency policy K-33.

``scripts/check_dependency_policy.py`` and ``dependency-policy.json`` are unchanged copies from
nodestro-studio; ``scripts/DEPENDENCY_POLICY_SOURCE.md`` records their origin and SHA-256. The tests
check the copies, run the checker on ``pyproject.toml`` and add one forbidden requirement per probe,
which must turn red.
"""

from __future__ import annotations

import hashlib
import importlib.util
from pathlib import Path
import re
import subprocess
import sys
import tomllib
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "check_dependency_policy.py"
POLICY = ROOT / "dependency-policy.json"
SOURCE = ROOT / "scripts" / "DEPENDENCY_POLICY_SOURCE.md"
COMPONENT = "axentra"


def _checker() -> Any:
    spec = importlib.util.spec_from_file_location("check_dependency_policy", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module  # dataclasses look the module up by name
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize("path", [SCRIPT, POLICY], ids=["script", "policy"])
def test_the_copies_are_unchanged(path: Path) -> None:
    recorded = re.search(rf"`{re.escape(path.name)}`: `([0-9a-f]{{64}})`", SOURCE.read_text(encoding="utf-8"))
    assert recorded is not None, f"{path.name} is not recorded in {SOURCE.name}"
    assert hashlib.sha256(path.read_bytes()).hexdigest() == recorded[1]


def test_the_manifest_follows_the_policy() -> None:
    result = subprocess.run(
        [sys.executable, str(SCRIPT)], cwd=ROOT, capture_output=True, text=True, check=False
    )
    assert result.returncode == 0, result.stderr
    assert f"; {COMPONENT})" in result.stdout


def test_the_copy_holds_only_this_component() -> None:
    policy = _checker().load_policy(POLICY)
    assert policy.errors == []
    assert policy.component == COMPONENT
    assert {edge.source for edge in policy.edges} <= {COMPONENT}


@pytest.mark.parametrize(
    ("requirements", "extra", "message"),
    [
        pytest.param('["orkexa>=0.2"]', None, "no edge axentra -> orkexa", id="library-to-library"),
        pytest.param(
            '["nodestro-runtime>=0.2"]', "server", "no edge axentra -> nodestro-runtime", id="platform"
        ),
        pytest.param('["axentra-studio"]', "ui", "no edge axentra -> axentra-studio", id="studio"),
        pytest.param(
            '["tabrion[postgres] @ https://example.invalid/tabrion.whl"]', None, "RC-1", id="direct-url"
        ),
        pytest.param('["tabrion[postgres]>=0.1,<0.2"]', "oidc", "not allowed here", id="wrong-extra"),
    ],
)
def test_a_forbidden_requirement_turns_red(requirements: str, extra: str | None, message: str) -> None:
    checker = _checker()
    pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    probe = tomllib.loads(f"items = {requirements}")["items"]
    project = pyproject["project"]
    if extra is None:
        project["dependencies"] = [*project.get("dependencies", []), *probe]
    else:
        extras = project.setdefault("optional-dependencies", {})
        extras[extra] = [*extras.get(extra, []), *probe]
    errors = checker.load_policy(POLICY).check_manifest(COMPONENT, pyproject)
    assert len(errors) == 1, errors
    assert message in errors[0]
