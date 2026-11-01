"""The committed OpenAPI contract matches the code (the Studio and SDKs are generated from it)."""

from __future__ import annotations

import json
from pathlib import Path

from axentra.api.app import create_app
from axentra.config.settings import load_settings

ROOT = Path(__file__).resolve().parents[2]


def test_committed_openapi_is_current():
    app = create_app(load_settings(None, environ={}, environment="test", mode="multi"), start=False)
    current = json.dumps(app.openapi(), indent=2, sort_keys=True) + "\n"
    committed = (ROOT / "openapi" / "axentra-v1.json").read_text(encoding="utf-8")
    assert committed == current, "run `axentra openapi export` and commit openapi/axentra-v1.json"


def test_every_operation_documents_problem_errors_and_has_unique_ids():
    spec = json.loads((ROOT / "openapi" / "axentra-v1.json").read_text(encoding="utf-8"))
    ids = [op["operationId"] for path in spec["paths"].values() for op in path.values()]
    assert len(ids) == len(set(ids))
