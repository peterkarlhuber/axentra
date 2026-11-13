"""QA-16 (AC-1): the import-linter contracts follow the edge list K-33, and a forbidden import turns them red.

Edge list K-33 of the Tabrion plan: Axentra never imports Orkexa, Nodestro or Axentra Studio, and it may import
``tabrion`` (axentra -> tabrion[postgres] is a required edge). The contract in ``pyproject.toml`` stays as it is
(plan 07 section 7); this module proves it:

* ``lint-imports`` on an unmodified copy of the package passes (positive control; CI runs it on the repository).
* Mutation probe: a copy with one forbidden import fails ``lint-imports`` and names the broken contract. Every
  contract has at least one probe.
* The edge to ``tabrion`` stays green, from the data layer and from the core.
* The K-33 contract names the platform packages, and an AST scan catches any ``orkexa*``, ``nodestro*``,
  ``levuvo*`` or ``*_studio`` package by prefix, which import-linter cannot express
  (``tests/unit/test_architecture.py`` keeps its own scan).
"""

from __future__ import annotations

import ast
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tomllib

import pytest

pytest.importorskip("importlinter")

ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "src"
PYPROJECT = ROOT / "pyproject.toml"
FORBIDDEN_PREFIXES = ("orkexa", "nodestro", "levuvo")

DOMAIN = "Domain modules do not depend on the HTTP layer or web frameworks"
NO_PLATFORM = "Axentra never depends on Nodestro, orkexa or Axentra Studio"
USAGE = "Usage never depends on billing"
CORE = "Core is the bottom layer"


def _lint_imports(cwd: Path, src: Path) -> subprocess.CompletedProcess[str]:
    env = {k: v for k, v in os.environ.items() if not k.startswith("PYTHON")}
    env["PYTHONPATH"] = str(src)
    # The console script's entry point, called through the running interpreter: ``python -m importlinter.cli``
    # does nothing (the module has no ``__main__`` block), and the script's location differs between POSIX and
    # Windows.
    entry = "import sys; from importlinter.cli import lint_imports_command; sys.exit(lint_imports_command())"
    return subprocess.run(
        [sys.executable, "-c", entry, "--config", str(cwd / "pyproject.toml"), "--no-cache"],
        cwd=cwd,
        env=env,
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )


def _copy(tmp_path: Path) -> Path:
    shutil.copytree(
        SRC / "axentra", tmp_path / "src" / "axentra", ignore=shutil.ignore_patterns("__pycache__")
    )
    shutil.copy(PYPROJECT, tmp_path / "pyproject.toml")
    return tmp_path


def _inject(path: Path, line: str) -> None:
    text = path.read_text(encoding="utf-8")
    anchor = "from __future__ import annotations\n"
    assert anchor in text, path
    path.write_text(text.replace(anchor, anchor + "\n" + line + "\n", 1), encoding="utf-8")


def _report(result: subprocess.CompletedProcess[str]) -> str:
    # lint-imports wraps a long contract name over two lines, so compare the report with its whitespace
    # folded.
    return " ".join(result.stdout.split())


def _kept(result: subprocess.CompletedProcess[str]) -> bool:
    count = len(_contracts())
    return result.returncode == 0 and f"{count} kept, 0 broken" in _report(result)


def test_unmodified_copy_is_kept(tmp_path: Path) -> None:
    root = _copy(tmp_path)
    result = _lint_imports(root, root / "src")
    assert _kept(result), result.stdout + result.stderr


@pytest.mark.parametrize(
    ("module", "line", "contract"),
    [
        ("cli.py", "import orkexa", NO_PLATFORM),
        ("data/database.py", "import orkexa.backends.postgres", NO_PLATFORM),
        ("platform.py", "import nodestro_runtime", NO_PLATFORM),
        ("api/app.py", "import nodestro_api", NO_PLATFORM),
        ("identity/service.py", "import nodestro", NO_PLATFORM),
        ("remote.py", "import axentra_studio", NO_PLATFORM),
        ("data/database.py", "import tabrion_studio", NO_PLATFORM),
        ("core/db_errors.py", "import fastapi", DOMAIN),
        ("identity/tokens.py", "import starlette.requests", DOMAIN),
        ("platform.py", "import axentra.api.app", DOMAIN),
        ("search/__init__.py", "import axentra.cli", DOMAIN),
        ("usage/service.py", "import axentra.billing", USAGE),
        ("core/clock.py", "import axentra.data", CORE),
        ("core/ids.py", "import axentra.identity.service", CORE),
    ],
)
def test_mutation_probe_turns_red(tmp_path: Path, module: str, line: str, contract: str) -> None:
    root = _copy(tmp_path)
    _inject(root / "src" / "axentra" / module, line)
    result = _lint_imports(root, root / "src")
    assert result.returncode != 0, f"{line!r} in {module} went unnoticed:\n{result.stdout}"
    assert f"{contract} BROKEN" in _report(result), result.stdout


@pytest.mark.parametrize(
    ("module", "line"),
    [
        ("data/database.py", "import tabrion.postgres"),
        ("core/db_errors.py", "import tabrion.errors"),
        ("data/roles.py", "import tabrion"),
    ],
)
def test_the_edge_to_tabrion_is_allowed(tmp_path: Path, module: str, line: str) -> None:
    """K-33: axentra -> tabrion[postgres] is a required edge (TABRION MIG-AXE), so no contract may forbid it."""
    root = _copy(tmp_path)
    _inject(root / "src" / "axentra" / module, line)
    result = _lint_imports(root, root / "src")
    assert _kept(result), result.stdout + result.stderr


def _contracts() -> list[dict[str, object]]:
    data = tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))
    contracts: list[dict[str, object]] = data["tool"]["importlinter"]["contracts"]
    return contracts


def test_platform_contract_follows_k33() -> None:
    """The existing contract (plan 07 section 7: unchanged) forbids every K-33 target and never ``tabrion``."""
    (contract,) = [c for c in _contracts() if c["name"] == NO_PLATFORM]
    forbidden = set(contract["forbidden_modules"])  # type: ignore[call-overload]
    assert contract["source_modules"] == ["axentra"]
    assert {
        "orkexa",
        "nodestro",
        "nodestro_runtime",
        "nodestro_api",
        "nodestro_studio",
        "axentra_studio",
        "tabrion_studio",
    } <= (forbidden)
    # tabrion_studio is forbidden (plan 06 section 7.4); tabrion itself, a K-33 edge, never is.
    assert not {name for name in forbidden if name.startswith("tabrion") and name != "tabrion_studio"}
    for other in _contracts():
        assert not {
            name
            for name in other["forbidden_modules"]
            if str(name) == "tabrion" or str(name).startswith("tabrion.")
        }  # type: ignore[attr-defined]


def test_no_contract_ignores_imports() -> None:
    """An ``ignore_imports`` entry would hide a real edge from every contract."""
    assert not [c["name"] for c in _contracts() if c.get("ignore_imports")]


def _imported_top_levels(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(alias.name.partition(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            names.add(node.module.partition(".")[0])
    return names


def _is_forbidden(name: str) -> bool:
    return name.startswith(FORBIDDEN_PREFIXES) or name.endswith("_studio")


def test_no_platform_import_by_prefix() -> None:
    """Covers ``nodestro_sdk`` and any future Orkexa, Nodestro, Levuvo or Studio package, also in
    ``TYPE_CHECKING`` blocks."""
    offenders = []
    for path in sorted((SRC / "axentra").rglob("*.py")):
        for name in _imported_top_levels(path):
            if _is_forbidden(name):
                offenders.append(f"{path.relative_to(SRC)}: {name}")
    assert not offenders


def test_prefix_scan_detects_a_probe(tmp_path: Path) -> None:
    probe = tmp_path / "probe.py"
    source = "from nodestro_sdk import x\nimport tabrion_studio.y\nimport tabrion\n"
    probe.write_text(source, encoding="utf-8")
    names = _imported_top_levels(probe)
    assert names == {"nodestro_sdk", "tabrion_studio", "tabrion"}
    assert {name for name in names if _is_forbidden(name)} == {"nodestro_sdk", "tabrion_studio"}
