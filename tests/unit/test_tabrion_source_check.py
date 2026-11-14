"""The negative dependency-confusion check (``scripts/check_tabrion_source.py``, TABRION DC-AX-1).

The script is an unchanged copy of nodestro-studio's canonical ``scripts/check_tabrion_source.py`` (DC-NS-2): its
SHA-256 is pinned here, so a change to one copy fails until every consumer has the new one. CI runs it in the job
"Install with a poisoned index (Tabrion pin)". Here, offline: a plain ``pip install tabrion`` against the poisoned
index is RED (it asks the index for the name and gets the poisoned release, 0.2.99: inside Axentra's range
``>=0.2,<0.3`` and above the pinned 0.2.1).
"""

from __future__ import annotations

import hashlib
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "check_tabrion_source.py"
#: SHA-256 of the canonical copy (nodestro-studio c036a29, head of #198; the merge commit once #198 is
#: merged).
SCRIPT_SHA256 = "f1edfc71b5da4986547abe0824833fb73bba532cb5e6a00e202c9ff317747456"


def test_the_script_is_the_shared_copy() -> None:
    assert hashlib.sha256(SCRIPT.read_bytes()).hexdigest() == SCRIPT_SHA256


def test_an_install_by_name_is_red(tmp_path: Path) -> None:
    target = tmp_path / "target"
    command = [sys.executable, "-m", "pip", "install", "--no-cache-dir", "--no-deps", "--target", str(target)]
    out = subprocess.run(
        [sys.executable, "-I", str(SCRIPT), "--lock", str(ROOT / "requirements" / "tabrion.txt")]
        + ["--path", str(target), "--", *command, "tabrion"],
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )
    assert out.returncode == 1, out.stdout + out.stderr
    assert "RED" in out.stdout.splitlines()[-1], out.stdout
    assert "ok   control: pip install --dry-run tabrion chooses the poisoned 0.2.99" in out.stdout, out.stdout
    assert "the index was asked for a poisoned name: GET /simple/tabrion/" in out.stdout, out.stdout
