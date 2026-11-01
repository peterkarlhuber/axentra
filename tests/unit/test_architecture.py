"""Architecture rules that must hold in every build (also enforced by import-linter in CI)."""

from __future__ import annotations

import ast
from pathlib import Path
import subprocess
import sys

SRC = Path(__file__).resolve().parents[2] / "src" / "axentra"
FORBIDDEN = ("nodestro", "orkexa", "axentra_studio")
WEB = ("fastapi", "starlette", "uvicorn")
DOMAIN = (
    "core",
    "config",
    "data",
    "identity",
    "tenancy",
    "access",
    "audit",
    "storage",
    "events",
    "usage",
    "billing",
    "notify",
    "search",
    "platform.py",
)


def _imports(path: Path) -> set[str]:
    mods = set()
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.Import):
            mods |= {a.name.split(".")[0] for a in node.names}
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            mods.add(node.module.split(".")[0] if not node.module.startswith("axentra.") else node.module)
    return mods


def test_no_dependency_on_nodestro_orkexa_or_studio():
    for path in SRC.rglob("*.py"):
        for mod in _imports(path):
            assert not mod.startswith(FORBIDDEN), f"{path} imports {mod}"


def test_domain_modules_do_not_import_web_frameworks():
    for part in DOMAIN:
        target = SRC / part
        files = [target] if target.suffix == ".py" else list(target.rglob("*.py"))
        for path in files:
            for mod in _imports(path):
                assert mod.split(".")[0] not in WEB, f"{path} imports {mod}"
                assert not mod.startswith(("axentra.api", "axentra.cli")), f"{path} imports {mod}"


def test_core_library_imports_without_server_extras():
    code = (
        "import sys; sys.modules['fastapi'] = None; sys.modules['starlette'] = None; sys.modules['uvicorn'] = None\n"
        "import axentra.platform, axentra.identity, axentra.tenancy, axentra.access, axentra.data, axentra.audit\n"
        "print('ok')"
    )
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, check=False)
    assert out.returncode == 0, out.stderr
    assert out.stdout.strip() == "ok"


def test_package_metadata_has_no_forbidden_dependencies():
    import tomllib

    data = tomllib.loads((SRC.parents[1] / "pyproject.toml").read_text(encoding="utf-8"))
    deps = " ".join(data["project"]["dependencies"]).lower()
    for extra in data["project"]["optional-dependencies"].values():
        deps += " " + " ".join(extra).lower()
    for name in FORBIDDEN + ("axentra-studio", "react"):
        assert name.replace("_", "-") not in deps.replace("axentra[", "")
