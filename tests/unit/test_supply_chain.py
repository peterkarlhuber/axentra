"""The SBOM generator (deploy/sbom.py) and the lock check (scripts/check_locks.py)."""

from __future__ import annotations

import json
from pathlib import Path
import runpy
import subprocess
import sys
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[2]
check_locks = runpy.run_path(str(ROOT / "scripts/check_locks.py"))


def _sbom(*args: str, env: dict[str, str] | None = None) -> dict[str, Any]:
    out = subprocess.run(
        [sys.executable, "-I", str(ROOT / "deploy/sbom.py"), *args],
        check=True,
        capture_output=True,
        text=True,
        env=env,
    ).stdout
    return dict(json.loads(out))


def test_sbom_lists_this_environment_deterministically() -> None:
    bom = _sbom("--component", "axentra")
    assert bom["bomFormat"] == "CycloneDX" and bom["specVersion"] == "1.5"
    assert bom["metadata"]["component"]["purl"].startswith("pkg:pypi/axentra@")
    names = [c["name"] for c in bom["components"]]
    assert names == sorted(names) and "psycopg" in names and "pydantic-core" in names
    assert "axentra" not in names and "pip" not in names
    by_name = {c["name"]: c for c in bom["components"]}
    assert by_name["psycopg"]["purl"] == f"pkg:pypi/psycopg@{by_name['psycopg']['version']}"
    assert bom["dependencies"][0]["dependsOn"] == [c["bom-ref"] for c in bom["components"]]
    assert "timestamp" not in bom["metadata"]
    assert _sbom("--component", "axentra") == bom  # same environment, same document


def test_sbom_timestamp_follows_source_date_epoch() -> None:
    import os

    bom = _sbom(env={**os.environ, "SOURCE_DATE_EPOCH": "1700000000"})
    assert bom["metadata"]["timestamp"] == "2023-11-14T22:13:20Z" and "component" not in bom["metadata"]


def test_repository_locks_are_consistent() -> None:
    assert check_locks["check"]() == []


def _tree(tmp_path: Path, constraints: str, locks: dict[str, str]) -> Path:
    (tmp_path / "deploy/locks").mkdir(parents=True)
    (tmp_path / "deploy/constraints.txt").write_text(constraints, encoding="utf-8")
    for name, text in locks.items():
        (tmp_path / "deploy/locks" / name).write_text(text, encoding="utf-8")
    return tmp_path


@pytest.mark.parametrize(
    ("server", "problem"),
    [
        ("a==1.0 \\\n    --hash=sha256:aa\nb==3.0 \\\n    --hash=sha256:bb\n", "constraints.txt pins 2.0"),
        ("a==1.0 \\\n    --hash=sha256:aa\nb==2.0\n", "no --hash"),
        ("a>=1.0\n", "not pinned with =="),
        ("a==1.0 --hash=sha256:aa\nc==1 --hash=sha256:cc\n", "missing in deploy/constraints.txt"),
    ],
)
def test_lock_check_finds_drift(tmp_path: Path, server: str, problem: str) -> None:
    root = _tree(
        tmp_path, "a==1.0\nb==2.0\n", {"server.txt": server, "full.txt": "a==1.0 --hash=sha256:aa\n"}
    )
    problems = check_locks["check"](root)
    assert any(problem in p for p in problems), problems


def test_lock_check_requires_both_image_locks(tmp_path: Path) -> None:
    root = _tree(tmp_path, "a==1.0\n", {"server.txt": "a==1.0 --hash=sha256:aa\n"})
    assert check_locks["check"](root) == ["deploy/locks/full.txt is missing"]
