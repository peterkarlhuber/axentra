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
    problem = {"application/problem+json": {"schema": {"$ref": "#/components/schemas/Problem"}}}
    for path, item in spec["paths"].items():
        for method, op in item.items():
            responses = op["responses"]
            assert responses["default"]["content"] == problem, (method, path)
            for status, response in responses.items():
                if status[0] in "45" and status != "503":
                    assert response["content"] == problem, (method, path, status)
    # FastAPI's own validation schema does not match the real body, so it is not in the contract.
    assert "HTTPValidationError" not in json.dumps(spec)
    assert set(spec["components"]["schemas"]["Problem"]["required"]) == {
        "type",
        "title",
        "status",
        "code",
        "detail",
    }


def test_security_schemes_and_public_operations():
    from axentra.api.app import PUBLIC_ROUTES

    spec = json.loads((ROOT / "openapi" / "axentra-v1.json").read_text(encoding="utf-8"))
    schemes = spec["components"]["securitySchemes"]
    assert schemes["sessionCookie"] == {**schemes["sessionCookie"], "type": "apiKey", "in": "cookie"}
    assert schemes["bearerAuth"]["scheme"] == "bearer"
    assert schemes["apiKeyHeader"]["name"] == "X-API-Key"
    assert spec["security"] == [{"sessionCookie": []}, {"bearerAuth": []}, {"apiKeyHeader": []}]
    public = {(m.lower(), p) for m, p in PUBLIC_ROUTES}
    seen_public = 0
    for path, item in spec["paths"].items():
        for method, op in item.items():
            if (method, path) in public:
                seen_public += 1
                assert op["security"] == [], (method, path)
            else:
                assert "security" not in op, (method, path)
    assert seen_public >= 8


def test_openapi_follows_routes_added_after_create_app():
    """A host that adds its own routes after ``create_app`` sees them in ``app.openapi()``."""
    app = create_app(load_settings(None, environ={}, environment="test", mode="multi"), start=False)
    first = app.openapi()
    assert app.openapi() is first  # cached

    @app.get("/host/extra")
    def extra() -> dict[str, str]:
        return {}

    spec = app.openapi()
    assert "/host/extra" in spec["paths"]
    assert spec["paths"]["/host/extra"]["get"]["responses"]["default"]


def test_get_oidc_start_no_longer_declares_the_refused_invitation_parameter():
    spec = json.loads((ROOT / "openapi" / "axentra-v1.json").read_text(encoding="utf-8"))
    params = spec["paths"]["/v1/auth/oidc/{provider}/start"]["get"]["parameters"]
    assert [p["name"] for p in params] == ["provider", "return_to"]
