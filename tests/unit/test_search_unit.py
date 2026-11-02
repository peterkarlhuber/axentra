"""Search module units: validation, highlight rendering, cursors, settings and role defaults."""

from __future__ import annotations

import pytest

from axentra.access.permissions import BUILTIN_ROLES, CATALOG, PLATFORM_ROLE_PERMISSIONS
from axentra.config.settings import load_settings
from axentra.core.errors import ConfigurationError, PayloadTooLarge, ValidationFailed
from axentra.core.pagination import encode_cursor
from axentra.search import PostgresSearchAdapter, SearchAdapter
from axentra.search.adapters import render_highlight
from axentra.search.models import MARK_START, MARK_STOP, IndexDocument
from axentra.search.service import _offset


def _doc(**kw):  # type: ignore[no-untyped-def]
    base = {"product_id": "prd_1", "tenant_id": "ten_1", "kind": "invoice", "ref_id": "inv_1", "title": "t"}
    return IndexDocument(**{**base, **kw})


def test_highlight_is_escaped_and_only_marks_matches():
    raw = f'<script>x</script> & "{MARK_START}needle{MARK_STOP}"'
    assert render_highlight(raw) == "&lt;script&gt;x&lt;/script&gt; &amp; &quot;<mark>needle</mark>&quot;"


def test_index_document_validation_strips_delimiters_and_nul():
    clean = _doc(title=f"a{MARK_START}b\x00c{MARK_STOP}", body="x").validate(max_body_chars=10)
    assert clean.title == "abc"
    with pytest.raises(PayloadTooLarge):
        _doc(body="x" * 11).validate(max_body_chars=10)
    for bad in (
        {"kind": "Invoice"},
        {"kind": "9x"},
        {"ref_id": "a/b"},
        {"ref_id": ""},
        {"ref_id": "x" * 201},
        {"title": "", "body": ""},
        {"metadata": [1]},
        {"metadata": {"x": object()}},
        {"metadata": {"x": "y" * 17_000}},
    ):
        with pytest.raises(ValidationFailed):
            _doc(**bad).validate(max_body_chars=1000)


def test_offset_cursor():
    assert _offset(None) == 0
    assert _offset(["o", 40]) == 40
    for bad in (["o", -1], ["o", "1"], ["o", True], ["x", 1], [1]):
        with pytest.raises(ValidationFailed):
            _offset(bad)
    assert encode_cursor(["o", 20])  # opaque, base64url


def test_search_settings():
    s = load_settings(None, environ={})
    assert s.search.language == "simple" and s.search.audit_index_writes
    assert load_settings(None, environ={}, search={"language": "pg_catalog.german"}).search.language
    for bad in ("simple; drop table x", "English", "a b", ""):
        with pytest.raises(ConfigurationError):
            load_settings(None, environ={}, search={"language": bad})
    env = load_settings(None, environ={"AXENTRA__SEARCH__LANGUAGE": "english"})
    assert env.search.language == "english"


def test_permissions_and_role_defaults():
    names = {p.name: p.scope for p in CATALOG}
    assert names["search:query"] == "tenant" and names["search:index"] == "tenant"
    query_roles = {k for k, r in BUILTIN_ROLES.items() if "search:query" in r.permissions}
    index_roles = {k for k, r in BUILTIN_ROLES.items() if "search:index" in r.permissions}
    assert query_roles == set(BUILTIN_ROLES)
    assert index_roles == {"product_owner", "product_admin", "tenant_owner", "tenant_admin"}
    assert "search:query" in PLATFORM_ROLE_PERMISSIONS["platform_viewer"]
    assert "search:index" not in PLATFORM_ROLE_PERMISSIONS["platform_viewer"]


def test_postgres_adapter_satisfies_the_protocol():
    adapter = PostgresSearchAdapter(db=None, language="simple")  # type: ignore[arg-type]
    assert isinstance(adapter, SearchAdapter) and adapter.name == "postgres"
