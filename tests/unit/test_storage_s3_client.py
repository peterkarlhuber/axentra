"""S3Backend client configuration and error mapping, without network access (botocore stubs)."""

from __future__ import annotations

from urllib.parse import parse_qs, urlsplit

import pytest

from axentra.core.errors import PayloadTooLarge, problem_details

boto3 = pytest.importorskip("boto3")
from botocore import exceptions as bce  # noqa: E402
from botocore.stub import Stubber  # noqa: E402

from axentra.storage.backends import (  # noqa: E402
    S3_CONNECT_TIMEOUT_SECONDS,
    S3_MAX_ATTEMPTS,
    S3_READ_TIMEOUT_SECONDS,
    ObjectNotFound,
    S3Backend,
    StorageUnavailable,
)


def _backend() -> S3Backend:
    # An endpoint nothing listens on: presigning is local, and the stubbed tests never connect.
    return S3Backend(
        "bucket",
        region="us-east-1",
        endpoint_url="http://127.0.0.1:9",
        access_key="AKIAEXAMPLETEST",
        secret_key="example-secret-key-for-tests",
        prefix="ax",
    )


def test_client_signs_with_sigv4_and_bounds_waits():
    b = _backend()
    cfg = b.client.meta.config
    assert cfg.signature_version == "s3v4"
    assert cfg.connect_timeout == S3_CONNECT_TIMEOUT_SECONDS
    assert cfg.read_timeout == S3_READ_TIMEOUT_SECONDS
    assert cfg.retries == {"total_max_attempts": S3_MAX_ATTEMPTS, "mode": "standard"}
    assert 0 < S3_CONNECT_TIMEOUT_SECONDS <= 10 and 0 < S3_READ_TIMEOUT_SECONDS <= 60 and S3_MAX_ATTEMPTS <= 3


def test_presigned_url_uses_sigv4_with_response_overrides():
    url = _backend().presigned_url(
        "p/t/f", ttl_seconds=60, filename_header='attachment; filename="x.txt"', content_type="text/plain"
    )
    q = parse_qs(urlsplit(url).query)
    assert q["X-Amz-Algorithm"] == ["AWS4-HMAC-SHA256"]
    assert q["X-Amz-Expires"] == ["60"] and "X-Amz-Signature" in q
    assert "AWSAccessKeyId" not in q and "Signature" not in q  # no SigV2
    assert q["response-content-disposition"] == ['attachment; filename="x.txt"']
    assert urlsplit(url).path == "/bucket/ax/p/t/f"
    assert "example-secret-key-for-tests" not in url


class _Failing:
    """A stand-in client whose every call raises ``exc`` (connection-level failures cannot be stubbed)."""

    def __init__(self, exc: Exception) -> None:
        self.exc = exc

    def __getattr__(self, name: str):  # type: ignore[no-untyped-def]
        def call(*a: object, **kw: object) -> None:
            raise self.exc

        return call


def _client_error(code: str, status: int) -> bce.ClientError:
    return bce.ClientError(
        {"Error": {"Code": code, "Message": "m"}, "ResponseMetadata": {"HTTPStatusCode": status}}, "GetObject"
    )


UNAVAILABLE = [
    bce.EndpointConnectionError(endpoint_url="http://10.9.9.9:9000/bucket/ax/p/t/f"),
    bce.ConnectTimeoutError(endpoint_url="http://10.9.9.9:9000/"),
    bce.ReadTimeoutError(endpoint_url="http://10.9.9.9:9000/"),
    bce.ConnectionClosedError(endpoint_url="http://10.9.9.9:9000/"),
    _client_error("SlowDown", 503),
    _client_error("InternalError", 500),
    _client_error("ServiceUnavailable", 503),
    _client_error("Weird", 502),
]


@pytest.mark.parametrize("exc", UNAVAILABLE, ids=lambda e: type(e).__name__ + ":" + str(e)[:20])
def test_unavailable_store_maps_to_503(exc: Exception):
    b = S3Backend("bucket", client=_Failing(exc), prefix="ax")
    calls = {
        "put": lambda: b.put("p/t/f", iter([b"data"]), content_type="text/plain"),
        "get": lambda: b.get("p/t/f"),
        "exists": lambda: b.exists("p/t/f"),
        "delete": lambda: b.delete("p/t/f"),
        "list_keys": lambda: list(b.list_keys("p/")),
    }
    for name, call in calls.items():
        with pytest.raises(StorageUnavailable) as info:
            call()
        p = problem_details(info.value)
        assert (p.status, p.code, p.headers.get("Retry-After")) == (503, "service_unavailable", "10"), name
        assert "10.9.9.9" not in p.detail and "bucket" not in p.detail, name
        assert info.value.__cause__ is exc  # kept for the server log


def test_other_errors_are_not_503():
    b = S3Backend("bucket", client=_Failing(_client_error("AccessDenied", 403)), prefix="ax")
    with pytest.raises(bce.ClientError):
        b.get("p/t/f")
    with pytest.raises(ObjectNotFound):
        S3Backend("bucket", client=_Failing(_client_error("NoSuchKey", 404)), prefix="ax").get("p/t/f")
    assert (
        S3Backend("bucket", client=_Failing(_client_error("404", 404)), prefix="ax").exists("p/t/f") is False
    )


def test_errors_of_the_source_stream_pass_through():
    """The size limit and quota are raised by the upload stream inside put(): never mapped to 503."""
    client = boto3.client("s3", region_name="us-east-1", aws_access_key_id="a", aws_secret_access_key="b")
    b = S3Backend("bucket", client=client, prefix="ax")

    def chunks():  # type: ignore[no-untyped-def]
        yield b"x"
        raise PayloadTooLarge("too large")

    with Stubber(client), pytest.raises(PayloadTooLarge):
        b.put("p/t/f", chunks(), content_type="text/plain")
