#!/usr/bin/env python3
"""Compare the skipped tests of a pytest run with a checked-in expectation file.

    python scripts/check_skips.py <junit.xml> tests/ci/skipped-<job>.txt

The JUnit XML comes from ``pytest --junitxml=...``. Every skipped test case is normalised to the node id
``<classname>::<name>`` (parametrisation is kept: Axentra's parameter ids are stable). Expected failures
(``type="pytest.xfail"``) are not skips: pytest writes them as ``<skipped>`` too, so they are left out.
The expectation file lists one skipped test per line as ``<nodeid>  # <reason>``; blank lines and lines starting with ``#`` are ignored.

Exit codes: 0 when the set of skipped tests equals the expectation, 1 when they differ (both lists are printed),
2 for a usage error, an unreadable file, or an expectation entry without a reason.

Standard library only, so the step runs before or without the project's dependencies.
"""

from __future__ import annotations

from pathlib import Path
import sys
import xml.etree.ElementTree as ET


class ExpectationError(Exception):
    """The expectation file is malformed."""


def skipped_from_junit(path: Path) -> set[str]:
    """Return the node ids of all skipped test cases in a JUnit XML report."""
    root = ET.parse(path).getroot()  # noqa: S314 - trusted input, see the module docstring
    skipped: set[str] = set()
    for case in root.iter("testcase"):
        marker = case.find("skipped")
        if marker is None or marker.get("type") == "pytest.xfail":
            continue
        classname = case.get("classname", "")
        name = case.get("name", "")
        skipped.add(f"{classname}::{name}" if classname else name)
    return skipped


def read_expectation(path: Path) -> set[str]:
    """Return the node ids listed in an expectation file; every entry must carry a reason."""
    expected: set[str] = set()
    for lineno, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        nodeid, sep, reason = line.partition("#")
        nodeid = nodeid.strip()
        if not sep or not reason.strip() or not nodeid:
            raise ExpectationError(f"{path}:{lineno}: entry needs '<nodeid>  # <reason>': {raw!r}")
        expected.add(nodeid)
    return expected


def compare(actual: set[str], expected: set[str]) -> tuple[list[str], list[str]]:
    """Return (unexpected skips, expected but not skipped), both sorted."""
    return sorted(actual - expected), sorted(expected - actual)


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: check_skips.py <junit.xml> <expectation file>", file=sys.stderr)
        return 2
    junit, expectation = Path(argv[0]), Path(argv[1])
    try:
        actual = skipped_from_junit(junit)
        expected = read_expectation(expectation)
    except ExpectationError as exc:
        print(f"check_skips: {exc}", file=sys.stderr)
        return 2
    except (OSError, ET.ParseError) as exc:
        print(f"check_skips: cannot read input: {exc}", file=sys.stderr)
        return 2
    unexpected, missing = compare(actual, expected)
    if not unexpected and not missing:
        print(f"check_skips: {len(actual)} skipped test(s), as expected in {expectation}")
        return 0
    print(f"check_skips: skipped tests differ from {expectation}")
    print(f"Unexpected skips ({len(unexpected)}):")
    for nodeid in unexpected:
        print(f"  {nodeid}")
    print(f"Expected but not skipped ({len(missing)}):")
    for nodeid in missing:
        print(f"  {nodeid}")
    print("Fix the cause, or update the expectation file with a reason (and justify it in the pull request).")
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
