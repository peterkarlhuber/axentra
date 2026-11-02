"""The framework-independent error mapping (``axentra.core.errors.problem_details``)."""

from __future__ import annotations

import importlib
import pkgutil
import re

import pytest

import axentra
from axentra.core.errors import (
    PROBLEM_BASE,
    AxentraError,
    ConfigurationError,
    Forbidden,
    NotFound,
    QuotaExceeded,
    RateLimited,
    problem_details,
)

_CODE = re.compile(r"^[a-z][a-z0-9_]*$")


def _all_subclasses(cls: type) -> set[type]:
    out: set[type] = set()
    for sub in cls.__subclasses__():
        out |= {sub, *_all_subclasses(sub)}
    return out


def _import_all_axentra_modules() -> None:
    for info in pkgutil.walk_packages(axentra.__path__, prefix="axentra."):
        try:
            importlib.import_module(info.name)
        except ImportError as exc:  # optional extras that are not installed
            pytest.skip(f"cannot import {info.name}: {exc}")


def test_every_axentra_error_maps_to_a_status_and_code():
    _import_all_axentra_modules()
    classes = {c for c in _all_subclasses(AxentraError) if c.__module__.startswith("axentra.")}
    assert len(classes) >= 20, sorted(c.__name__ for c in classes)
    for cls in [AxentraError, *classes]:
        assert _CODE.match(cls.code), cls
        assert 400 <= cls.status <= 599, cls
        assert cls.title, cls
        info = problem_details(cls("some detail"))
        assert 400 <= info.status <= 599, cls
        assert _CODE.match(info.code), cls
        if cls.status < 500:
            assert (info.status, info.code, info.title, info.detail) == (
                cls.status,
                cls.code,
                cls.title,
                "some detail",
            )
            assert not info.internal
        else:
            assert (info.status, info.code, info.internal) == (500, "internal", True)
            assert info.detail == "An internal error occurred."


def test_problem_details_extra_headers_and_redaction():
    info = problem_details(Forbidden("token Bearer abcdefghijklmnopqrst", extra={"reason": "x"}))
    assert info.status == 403 and info.code == "forbidden"
    assert "abcdefghijklmnopqrst" not in info.detail
    assert info.extra == {"reason": "x"} and info.headers == {}
    body = info.body(request_id="req_1")
    assert body["type"] == PROBLEM_BASE + "forbidden" and body["reason"] == "x"
    assert body["request_id"] == "req_1" and body["status"] == 403

    assert problem_details(RateLimited()).headers == {"Retry-After": "60"}
    assert problem_details(QuotaExceeded(retry_after=5)).headers == {"Retry-After": "5"}
    assert problem_details(NotFound()).detail == "Not found"


def test_problem_details_hides_internal_errors():
    for exc in (ValueError("SELECT secret"), ConfigurationError("db password=x"), KeyError("k")):
        info = problem_details(exc)
        assert info.status == 500 and info.code == "internal" and info.internal
        assert info.detail == "An internal error occurred." and info.extra == {}
