"""Unit tests (httpx.MockTransport) for the SSE parser, the streams and checkout parsing."""

from __future__ import annotations

import json

import httpx
import pytest

from axentra_client import AxentraApiError
from axentra_client._base import SseParser

from .test_client import NOW, aclient, client


def _feed(text: str) -> list[dict[str, object]]:
    parser = SseParser()
    out = []
    for line in text.split("\n"):
        message = parser.feed(line)
        if message is not None:
            out.append(message)
    return out


def test_sse_parser_follows_the_event_stream_format() -> None:
    text = (
        "retry: 3000\n\n"
        ": keep-alive\n\n"
        'id: 5\nevent: invoice.paid\ndata: {"n": 1}\n\n'
        "event: note\ndata: line one\ndata: line two\n\n"
        "data:no-space\n\n"
        "id: 7\r\nevent: job.done\r\ndata: [1, 2]\r\n\r\n"
        "event: lonely\n\n"
        "data: tail without a blank line"
    )
    assert _feed(text) == [
        {"id": "5", "event": "invoice.paid", "data": {"n": 1}},
        {"id": "5", "event": "note", "data": "line one\nline two"},  # the last id stays in effect
        {"id": "5", "event": "message", "data": "no-space"},
        {"id": "7", "event": "job.done", "data": [1, 2]},
    ]


def _sse_handler(body: str, status: int = 200):  # type: ignore[no-untyped-def]
    def handler(request: httpx.Request) -> httpx.Response:
        if status != 200:
            return httpx.Response(status, json={"code": "validation_failed", "title": "Validation failed"})
        return httpx.Response(200, text=body, headers={"Content-Type": "text/event-stream"})

    return handler


def test_event_stream_sends_resume_position_and_types() -> None:
    body = 'retry: 3000\n\nid: 9\nevent: invoice.paid\ndata: {"id": "evt_1", "data": {"n": 1}}\n\n'
    c, rec = client(_sse_handler(body), api_key="axk_test")
    messages = list(
        c.events.stream("prd_1", tenant_id="ten_1", types=["invoice.*", "order.*"], last_event_id="8")
    )
    assert [(m.id, m.event, m.data["id"]) for m in messages] == [("9", "invoice.paid", "evt_1")]
    req = rec.last
    assert req.url.path == "/v1/products/prd_1/events/stream"
    assert req.url.params["types"] == "invoice.*,order.*" and req.url.params["tenant_id"] == "ten_1"
    assert req.headers["Last-Event-ID"] == "8" and req.headers["Accept"] == "text/event-stream"
    assert req.headers["Authorization"] == "Bearer axk_test"


def test_stream_errors_are_mapped() -> None:
    c, _ = client(_sse_handler("", status=422))
    with pytest.raises(AxentraApiError) as ei:
        list(c.jobs.stream("prd_1", last_event_id="x"))
    assert ei.value.status == 422


@pytest.mark.anyio
async def test_async_job_stream() -> None:
    body = 'id: 3\nevent: job.done\ndata: {"id": "job_1", "status": "done"}\n\n'
    c, rec = aclient(_sse_handler(body))
    got = [m async for m in c.jobs.stream("prd_1")]
    assert [(m.event, m.data["status"]) for m in got] == [("job.done", "done")]
    assert "Last-Event-ID" not in rec.last.headers
    await c.aclose()


def test_checkout_and_search_batch_requests() -> None:
    sub = {
        "id": "sub_1",
        "product_id": "prd_1",
        "tenant_id": "ten_1",
        "plan_id": "pln_1",
        "plan_key": "pro",
        "status": "incomplete",
        "provider": "stripe",
        "cancel_at_period_end": False,
        "current_period_start": NOW,
        "current_period_end": NOW,
        "version": 1,
        "created_at": NOW,
        "updated_at": NOW,
    }

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/billing/checkout"):
            return httpx.Response(
                201,
                json={
                    "provider": "stripe",
                    "checkout_id": "cs_1",
                    "url": "https://pay.example/cs_1",
                    "completed": False,
                    "subscription": sub,
                },
            )
        if request.url.path.endswith("/documents/batch"):
            return httpx.Response(200, json={"created": 1, "updated": 0, "documents": []})
        if request.method == "DELETE":
            return httpx.Response(200, json={"deleted": 4})
        return httpx.Response(200, json={"items": [], "next_cursor": None})

    c, rec = client(handler)
    session = c.billing.checkout(
        "prd_1", "ten_1", "pro", success_url="https://a/ok", cancel_url="https://a/no"
    )
    assert session.url == "https://pay.example/cs_1" and session.subscription.plan_key == "pro"
    assert json.loads(rec.last.content) == {
        "plan": "pro",
        "success_url": "https://a/ok",
        "cancel_url": "https://a/no",
    }
    assert c.search.index_batch("prd_1", "ten_1", [{"kind": "k", "ref_id": "r", "title": "t"}]).created == 1
    assert json.loads(rec.last.content) == {"documents": [{"kind": "k", "ref_id": "r", "title": "t"}]}
    assert c.search.remove_kind("prd_1", "ten_1", "k") == 4
    assert (
        rec.last.method == "DELETE"
        and rec.last.url.path == "/v1/products/prd_1/tenants/ten_1/search/documents/k"
    )
    c.search.query("prd_1", "ten_1", "q", metadata={"status": "open"})
    assert rec.last.url.params["metadata"] == '{"status":"open"}'
