#!/usr/bin/env python3
"""Check the hash-pinned image locks (deploy/locks/*.txt) against deploy/constraints.txt.

    python scripts/check_locks.py            # exit 1 with the differences

Every requirement of a lock must be pinned (``==``) with at least one ``--hash``, and the image
locks (server, full) must pin the same versions as deploy/constraints.txt. A dependency update that
changes only one of them fails here; regenerate the locks with scripts/update_locks.sh.

The one exception is Tabrion, which is not on a package index (TABRION VER-1, V-B0): deploy/locks/tabrion.txt
pins the source archive of the commit that requirements/tabrion.txt names, with a hash (TABRION MIG-AXE-3).
"""

from __future__ import annotations

from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parent.parent
CONSTRAINTS = ROOT / "deploy/constraints.txt"
LOCKS = ROOT / "deploy/locks"
IMAGE_LOCKS = ("server.txt", "full.txt")
_PIN = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)==([^\s;\\]+)")
#: The direct reference that deploy/locks/tabrion.txt may hold: Tabrion's source archive of one commit.
TABRION_LOCK = "tabrion.txt"
_TABRION_ARCHIVE = re.compile(
    r"^tabrion @ https://github\.com/peterkarlhuber/tabrion/archive/([0-9a-f]{40})\.tar\.gz(?=\s|$)"
)
_TABRION_PIN = re.compile(
    r"^tabrion @ git\+https://github\.com/peterkarlhuber/tabrion\.git@([0-9a-f]{40})$", re.M
)


def _norm(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def pins(text: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in text.splitlines():
        m = _PIN.match(line.strip())
        if m:
            out[_norm(m.group(1))] = m.group(2)
    return out


def lock_entries(text: str) -> list[tuple[str, str, int]]:
    """``(name, version, number of hashes)`` per requirement of a ``--generate-hashes`` lock."""
    joined = re.sub(r"\\\n\s*", " ", text)
    entries = []
    for line in joined.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        m = _PIN.match(line)
        if not m:
            entries.append((line.split()[0], "", 0))
            continue
        entries.append((_norm(m.group(1)), m.group(2), line.count("--hash=sha256:")))
    return entries


def _check_tabrion(root: Path, path: Path) -> list[str]:
    """deploy/locks/tabrion.txt: exactly Tabrion's archive of the commit requirements/tabrion.txt pins, hashed."""
    where = str(path.relative_to(root))
    joined = re.sub(r"\\\n\s*", " ", path.read_text(encoding="utf-8"))
    lines = [ln.strip() for ln in joined.splitlines() if ln.strip() and not ln.strip().startswith("#")]
    if len(lines) != 1:
        return [f"{where}: expected exactly one requirement, found {len(lines)}"]
    archive = _TABRION_ARCHIVE.match(lines[0])
    if archive is None:
        return [f"{where}: not the source archive of a Tabrion commit: {lines[0].split()[0:3]}"]
    problems = []
    if "--hash=sha256:" not in lines[0]:
        problems.append(f"{where}: no --hash")
    requirements = root / "requirements/tabrion.txt"
    pinned = _TABRION_PIN.findall(requirements.read_text(encoding="utf-8")) if requirements.is_file() else []
    if pinned != [archive.group(1)]:
        problems.append(f"{where}: commit {archive.group(1)} is not the one requirements/tabrion.txt pins {pinned}")
    return problems


def check(root: Path = ROOT) -> list[str]:
    problems: list[str] = []
    constraints = pins((root / "deploy/constraints.txt").read_text(encoding="utf-8"))
    for path in sorted((root / "deploy/locks").glob("*.txt")):
        if path.name == TABRION_LOCK:
            problems.extend(_check_tabrion(root, path))
            continue
        for name, version, hashes in lock_entries(path.read_text(encoding="utf-8")):
            where = f"{path.relative_to(root)}: {name}"
            if not version:
                problems.append(f"{where}: not pinned with ==")
            elif hashes == 0:
                problems.append(f"{where}=={version}: no --hash")
            elif path.name in IMAGE_LOCKS:
                expected = constraints.get(name)
                if expected is None:
                    problems.append(f"{where}=={version}: missing in deploy/constraints.txt")
                elif expected != version:
                    problems.append(f"{where}=={version}: deploy/constraints.txt pins {expected}")
    for name in (*IMAGE_LOCKS, TABRION_LOCK):
        if not (root / "deploy/locks" / name).is_file():
            problems.append(f"deploy/locks/{name} is missing")
    return problems


def main() -> int:
    problems = check()
    for p in problems:
        print(p, file=sys.stderr)
    if problems:
        print("regenerate the locks with scripts/update_locks.sh", file=sys.stderr)
        return 1
    print("deploy/locks match deploy/constraints.txt")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
