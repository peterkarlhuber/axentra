"""The skip-expectation check of the CI jobs (scripts/check_skips.py)."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import subprocess
import sys
from types import ModuleType

import pytest

SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "check_skips.py"

JUNIT = """<?xml version="1.0" encoding="utf-8"?>
<testsuites><testsuite name="pytest" tests="4" skipped="3">
  <testcase classname="tests.unit.test_a" name="test_ok" time="0.1"/>
  <testcase classname="tests.unit.test_a" name="test_skip[x-1]" time="0">
    <skipped type="pytest.skip" message="no db">no db</skipped>
  </testcase>
  <testcase classname="tests.unit.test_b" name="test_xfail" time="0">
    <skipped type="pytest.xfail" message="known bug"/>
  </testcase>
  <testcase classname="tests.unit.test_b" name="test_skip2" time="0">
    <skipped type="pytest.skip" message="no s3">no s3</skipped>
  </testcase>
</testsuite></testsuites>
"""


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location("check_skips", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _run(tmp_path: Path, expectation: str) -> subprocess.CompletedProcess[str]:
    junit = tmp_path / "junit.xml"
    junit.write_text(JUNIT, encoding="utf-8")
    exp = tmp_path / "skipped.txt"
    exp.write_text(expectation, encoding="utf-8")
    return subprocess.run(
        [sys.executable, "-I", str(SCRIPT), str(junit), str(exp)], capture_output=True, text=True, check=False
    )


# MUP-ONA T-SKIP-1
def test_skips_are_read_as_node_ids_without_xfails(tmp_path: Path) -> None:
    junit = tmp_path / "junit.xml"
    junit.write_text(JUNIT, encoding="utf-8")
    assert _load().skipped_from_junit(junit) == {
        "tests.unit.test_a::test_skip[x-1]",
        "tests.unit.test_b::test_skip2",
    }


# MUP-ONA T-SKIP-1
def test_matching_expectation_passes(tmp_path: Path) -> None:
    result = _run(
        tmp_path,
        "# header comment\n\ntests.unit.test_a::test_skip[x-1]  # no database\n"
        "tests.unit.test_b::test_skip2  # no S3\n",
    )
    assert result.returncode == 0, result.stdout + result.stderr


# MUP-ONA T-SKIP-1
def test_unexpected_and_missing_skips_fail_and_are_listed(tmp_path: Path) -> None:
    result = _run(
        tmp_path, "tests.unit.test_a::test_skip[x-1]  # no database\ntests.unit.test_c::gone  # old\n"
    )
    assert result.returncode == 1
    assert "tests.unit.test_b::test_skip2" in result.stdout
    assert "tests.unit.test_c::gone" in result.stdout


# MUP-ONA T-SKIP-1
def test_empty_expectation_fails_on_any_skip(tmp_path: Path) -> None:
    assert _run(tmp_path, "# no skips expected\n").returncode == 1


# MUP-ONA T-SKIP-1
@pytest.mark.parametrize(
    "line", ["tests.unit.test_a::test_skip[x-1]", "tests.unit.test_a::test_skip[x-1]  #  "]
)
def test_entry_without_reason_is_a_usage_error(tmp_path: Path, line: str) -> None:
    result = _run(tmp_path, line + "\ntests.unit.test_b::test_skip2  # no S3\n")
    assert result.returncode == 2
    assert "reason" in result.stderr
