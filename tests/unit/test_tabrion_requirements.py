"""The Tabrion pin and ranges (TABRION VER-1; migration plan 06 section 6.4, rules RC-1 and RC-8).

- ``requirements/tabrion.txt`` holds exactly one requirement: ``tabrion`` (extras optional) by the canonical direct
  URL ``git+https://github.com/peterkarlhuber/tabrion.git@<sha>``, the full 40-hex SHA of a final Tabrion release.
- ``pyproject.toml`` names Tabrion only by a final range ``>=0.N,<0.(N+1)``: no direct URL (RC-1), no pre-release
  specifier (RC-8), and the pinned version lies inside every range.
- The installed Tabrion is the pinned commit (``-r requirements/tabrion.txt``) or the hashed archive of
  ``deploy/locks/tabrion.txt``, never a release from a package index (dependency confusion, DC-AX-1).

A new pin adds its SHA to ``FINAL_RELEASES`` after checking it in Tabrion: ``git show <sha>:src/tabrion/_version.py``
is a final version and the SHA is the release commit on Tabrion's ``master``.
"""

from __future__ import annotations

from importlib import metadata
import json
import os
from pathlib import Path
import re
import tomllib

from packaging.requirements import InvalidRequirement, Requirement
from packaging.version import InvalidVersion, Version
import pytest

ROOT = Path(__file__).resolve().parents[2]
REQUIREMENTS = ROOT / "requirements" / "tabrion.txt"

FINAL_RELEASES = {"d5821faa8742dea012abda3b663549c038d76543": "0.1.0"}
"""Final Tabrion releases a pin may name: commit SHA -> version (``src/tabrion/_version.py`` at that commit)."""

PIN = re.compile(
    r"tabrion(?:\[[a-z0-9_-]+(?:,[a-z0-9_-]+)*\])? @ git\+https://github\.com/peterkarlhuber/tabrion\.git"
    r"@(?P<sha>[0-9a-f]{40})"
)
RANGE = re.compile(r"0\.(?P<minor>\d+)")


def requirement_lines(text: str) -> list[str]:
    """The requirement lines of a requirements file: without blank lines and ``#`` comments."""
    lines = []
    for raw in text.splitlines():
        line = raw.split(" #", 1)[0].strip() if not raw.lstrip().startswith("#") else ""
        if line:
            lines.append(line)
    return lines


def pin_problems(text: str) -> tuple[str | None, list[str]]:
    """``(sha, problems)`` of a ``requirements/tabrion.txt`` text; ``sha`` is None when there is no valid pin."""
    lines = requirement_lines(text)
    if len(lines) != 1:
        return None, [f"exactly one requirement line expected, found {len(lines)}: {lines}"]
    match = PIN.fullmatch(lines[0])
    if match is None:
        return None, [
            f"not the canonical pin 'tabrion[...] @ git+https://github.com/peterkarlhuber/tabrion.git@<40-hex SHA>':"
            f" {lines[0]!r}"
        ]
    sha = match["sha"]
    version = FINAL_RELEASES.get(sha)
    if version is None:
        return sha, [f"{sha} is not a known final Tabrion release (FINAL_RELEASES)"]
    if Version(version).is_prerelease or Version(version).is_devrelease:
        return sha, [f"{sha} is Tabrion {version}, a pre-release (RC-8)"]
    return sha, []


def tabrion_requirements(pyproject: dict) -> list[tuple[str, Requirement | None]]:
    """``(where, requirement)`` for every Tabrion requirement in ``[project]`` dependencies and extras; ``None``
    for an entry that mentions Tabrion but does not parse."""
    project = pyproject.get("project", {})
    groups = {"dependencies": project.get("dependencies", [])}
    groups |= {f"optional-dependencies.{k}": v for k, v in project.get("optional-dependencies", {}).items()}
    found = []
    for where, items in groups.items():
        for item in items:
            try:
                req = Requirement(item)
            except InvalidRequirement:
                if "tabrion" in item.lower():
                    found.append((where, None))
                continue
            if req.name.lower() == "tabrion":
                found.append((where, req))
    return found


def _version(text: str) -> Version | None:
    try:
        return Version(text)
    except InvalidVersion:
        return None


def range_problems(pyproject: dict, pinned_version: str | None) -> list[str]:
    """RC-1 and RC-8 for the Tabrion requirements of a parsed ``pyproject.toml``."""
    problems = []
    for where, req in tabrion_requirements(pyproject):
        if req is None:
            problems.append(f"{where}: a Tabrion requirement that does not parse")
            continue
        if req.url:
            problems.append(f"{where}: {req} names Tabrion by a direct URL (RC-1: libraries use a range)")
            continue
        specs = {(s.operator, s.version) for s in req.specifier}
        lower = [v for op, v in specs if op == ">="]
        upper = [v for op, v in specs if op == "<"]
        versions = [_version(v) for _, v in specs]
        if any(v is None for v in versions) or {op for op, _ in specs} - {">=", "<"}:
            problems.append(
                f"{where}: {req} has a specifier that is not a plain version bound (only '>=0.N,<0.(N+1)')"
            )
        elif any(v is not None and (v.is_prerelease or v.is_devrelease) for v in versions):
            problems.append(f"{where}: {req} has a pre-release specifier (RC-8)")
        elif len(specs) != 2 or len(lower) != 1 or len(upper) != 1:
            problems.append(f"{where}: {req} is not a range '>=0.N,<0.(N+1)'")
        else:
            low, high = RANGE.fullmatch(lower[0]), RANGE.fullmatch(upper[0])
            if low is None or high is None or int(high["minor"]) != int(low["minor"]) + 1:
                problems.append(f"{where}: {req} is not a range '>=0.N,<0.(N+1)'")
            elif pinned_version is not None and Version(pinned_version) not in req.specifier:
                problems.append(f"{where}: the pinned Tabrion {pinned_version} is outside {req.specifier}")
    return problems


def _pyproject() -> dict:
    return tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))


def test_requirements_file_has_one_final_pin() -> None:
    sha, problems = pin_problems(REQUIREMENTS.read_text(encoding="utf-8"))
    assert problems == []
    assert sha is not None and len(sha) == 40


def test_pyproject_names_tabrion_by_final_range_only() -> None:
    sha, _ = pin_problems(REQUIREMENTS.read_text(encoding="utf-8"))
    assert range_problems(_pyproject(), FINAL_RELEASES.get(sha or "")) == []


#: Escape hatch for development against a sibling Tabrion checkout (``pip install -e ../tabrion``): with this variable
#: set to 1, an installed Tabrion from a local directory (``dir_info``) is accepted. Never set in CI.
LOCAL_CHECKOUT_ENV = "AXENTRA_TABRION_LOCAL_CHECKOUT"
LOCK = ROOT / "deploy" / "locks" / "tabrion.txt"
ARCHIVE = re.compile(r"https://github\.com/peterkarlhuber/tabrion/archive/(?P<sha>[0-9a-f]{40})\.tar\.gz")


def installed_problems(
    direct_url: str | None, sha: str | None, lock_text: str, *, local_ok: bool
) -> list[str]:
    """Where an installed Tabrion came from (its ``direct_url.json`` text): the pinned commit from Git
    (``vcs_info.commit_id`` equal to the pin), or the hashed source archive of ``deploy/locks/tabrion.txt``
    (``archive_info``, the URL of that commit). Anything else, in particular no ``direct_url.json`` at all (an
    install from a package index: dependency confusion, DC-AX-1), is refused; a local directory only with
    ``local_ok``. This detects an accidental index install; a poisoned wheel can forge the file, which is why CI also
    runs the install against a poisoned index (``scripts/check_tabrion_source.py``)."""
    if direct_url is None:
        return ["tabrion has no direct_url.json: it was installed from a package index, not from the pin"]
    try:
        data = json.loads(direct_url)
    except ValueError:
        return ["tabrion's direct_url.json does not parse"]
    url = data.get("url") if isinstance(data, dict) else None
    if not isinstance(url, str):
        return ["tabrion's direct_url.json names no URL"]
    if "vcs_info" in data:
        vcs = data["vcs_info"]
        if url != "https://github.com/peterkarlhuber/tabrion.git":
            return [f"tabrion comes from {url}, not github.com/peterkarlhuber/tabrion.git"]
        if not isinstance(vcs, dict) or vcs.get("commit_id") != sha:
            return [
                f"tabrion is commit {vcs.get('commit_id') if isinstance(vcs, dict) else None}, the pin is {sha}"
            ]
        return []
    if "archive_info" in data:
        match = ARCHIVE.fullmatch(url)
        locked = [m["sha"] for line in lock_text.splitlines() if (m := ARCHIVE.search(line))]
        if match is None or locked != [match["sha"]] or match["sha"] != sha:
            return [
                f"tabrion comes from the archive {url}, not the one of deploy/locks/tabrion.txt at the pin"
            ]
        return []
    if "dir_info" in data:
        if local_ok:
            return []
        return [
            f"tabrion comes from the local directory {url}; set {LOCAL_CHECKOUT_ENV}=1 for a sibling checkout"
        ]
    return [f"tabrion's direct_url.json names no known source: {sorted(data)}"]


def test_installed_tabrion_is_the_pin() -> None:
    """The installed Tabrion is the pinned commit and version, never one from a package index (DC-AX-1)."""
    dist = metadata.distribution("tabrion")  # the dev extra requires it: not installed is a failure
    sha, _ = pin_problems(REQUIREMENTS.read_text(encoding="utf-8"))
    local_ok = os.environ.get(LOCAL_CHECKOUT_ENV) == "1"
    lock_text = LOCK.read_text(encoding="utf-8") if LOCK.is_file() else ""
    assert installed_problems(dist.read_text("direct_url.json"), sha, lock_text, local_ok=local_ok) == []
    if not local_ok:
        assert dist.version == FINAL_RELEASES.get(sha or "")


SHA0 = "d5821faa8742dea012abda3b663549c038d76543"
GIT_URL = "https://github.com/peterkarlhuber/tabrion.git"
ARCHIVE_URL = f"https://github.com/peterkarlhuber/tabrion/archive/{SHA0}.tar.gz"
LOCK_TEXT = f"# lock\ntabrion @ {ARCHIVE_URL} \\\n    --hash=sha256:aa\n"


@pytest.mark.parametrize(
    ("direct_url", "local_ok"),
    [
        (json.dumps({"url": GIT_URL, "vcs_info": {"vcs": "git", "commit_id": SHA0}}), False),
        (json.dumps({"url": ARCHIVE_URL, "archive_info": {"hashes": {"sha256": "aa"}}}), False),
        (json.dumps({"url": "file:///home/dev/tabrion", "dir_info": {"editable": True}}), True),
    ],
)
def test_installed_sources_that_pass(direct_url: str, local_ok: bool) -> None:
    assert installed_problems(direct_url, SHA0, LOCK_TEXT, local_ok=local_ok) == []


@pytest.mark.parametrize(
    "direct_url",
    [
        None,  # from a package index
        "{not json",
        json.dumps({"vcs_info": {"commit_id": SHA0}}),  # no URL
        json.dumps({"url": GIT_URL, "vcs_info": {"vcs": "git", "commit_id": "0" * 40}}),  # another commit
        json.dumps({"url": "https://github.com/someone/tabrion.git", "vcs_info": {"commit_id": SHA0}}),
        json.dumps({"url": ARCHIVE_URL.replace(SHA0, "0" * 40), "archive_info": {}}),  # another archive
        json.dumps({"url": "https://files.example/tabrion-0.1.0-py3-none-any.whl", "archive_info": {}}),
        json.dumps({"url": "file:///home/dev/tabrion", "dir_info": {}}),  # local, without the escape hatch
        json.dumps({"url": GIT_URL}),  # no known source
    ],
)
def test_installed_sources_that_fail(direct_url: str | None) -> None:
    assert installed_problems(direct_url, SHA0, LOCK_TEXT, local_ok=False) != []


GOOD = "tabrion @ git+https://github.com/peterkarlhuber/tabrion.git@d5821faa8742dea012abda3b663549c038d76543"


@pytest.mark.parametrize(
    "text",
    [
        "# comments only\n",
        GOOD + "\n" + GOOD + "\n",  # two pins
        GOOD + "\ntabrion-extra==1\n",  # a second requirement
        GOOD.replace("d5821faa8742dea012abda3b663549c038d76543", "d5821faa"),  # short SHA
        GOOD.replace(".git@", "@"),  # without .git
        GOOD.replace("https://", "http://"),
        GOOD.replace("https://", "ssh://git@"),
        GOOD.replace("peterkarlhuber/tabrion", "someone/tabrion"),
        GOOD.replace("@d5821faa8742dea012abda3b663549c038d76543", "@v0.1.0"),  # a tag, not a SHA
        GOOD.replace("d5821faa8742dea012abda3b663549c038d76543", "85145cb" + "0" * 33),  # not a final release
        "tabrion==0.1.0",
        "tabrion>=0.1.0a1,<0.2",
        "-c constraints.txt\n" + GOOD,
        "--index-url https://example.invalid/simple\n" + GOOD,
    ],
)
def test_bad_pins_are_refused(text: str) -> None:
    assert pin_problems(text)[1] != []


def test_good_pin_variants_pass() -> None:
    assert pin_problems("# c\n\n" + GOOD + "  # trailing comment\n") == (
        "d5821faa8742dea012abda3b663549c038d76543",
        [],
    )
    assert pin_problems(GOOD.replace("tabrion @", "tabrion[testing,postgres] @"))[1] == []


@pytest.mark.parametrize(
    ("deps", "dev"),
    [
        (["tabrion[postgres] @ " + GOOD.split(" @ ")[1]], []),  # direct URL in dependencies (RC-1)
        ([], ["tabrion[testing] @ " + GOOD.split(" @ ")[1]]),  # direct URL in an extra (RC-1)
        (["tabrion[postgres]>=0.1.0a1,<0.2"], []),  # pre-release specifier (RC-8)
        (["tabrion>=0.1rc1,<0.2"], []),
        (["tabrion>=0.2.0.dev0,<0.3"], []),
        (["tabrion==0.1.0"], []),  # a pin, not a range
        (["tabrion>=0.1"], []),  # no upper bound
        (["tabrion>=0.1,<0.3"], []),  # wider than one minor
        (["tabrion>=0.2,<0.3"], []),  # the pinned 0.1.0 is outside
        (["tabrion"], []),  # unversioned
        (["tabrion[postgres]>=0.1,<0.2 @@"], []),  # does not parse
        (["tabrion==0.1.*"], []),  # a wildcard, not a version
        (["tabrion===0.1.0"], []),  # arbitrary equality
        (["tabrion>=0.1,<0.2,!=0.1.3"], []),  # an extra exclusion: not exactly one minor line
        (["tabrion>=0.1.0,<0.2"], []),  # three-part lower bound: not the canonical shape
        (["tabrion~=0.1"], []),  # compatible release: wider than 0.1 (allows 0.9)
        (["tabrion>0.1,<0.2"], []),  # exclusive lower bound
        (["tabrion>=0.1,<=0.2"], []),  # inclusive upper bound
        (["tabrion>=1.0,<1.1"], []),  # not a 0.x range
    ],
)
def test_bad_ranges_are_refused(deps: list[str], dev: list[str]) -> None:
    pyproject = {"project": {"dependencies": deps, "optional-dependencies": {"dev": dev}}}
    assert range_problems(pyproject, "0.1.0") != []


def test_good_ranges_pass() -> None:
    pyproject = {
        "project": {
            "dependencies": ["tabrion[postgres]>=0.1,<0.2"],
            "optional-dependencies": {"dev": ["tabrion[testing,postgres]>=0.1,<0.2", "pytest>=8"]},
        }
    }
    assert range_problems(pyproject, "0.1.0") == []
    assert [where for where, _ in tabrion_requirements(pyproject)] == [
        "dependencies",
        "optional-dependencies.dev",
    ]
