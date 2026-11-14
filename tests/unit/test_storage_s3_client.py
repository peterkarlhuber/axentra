"""S3Backend client configuration, without network access."""

from __future__ import annotations

from urllib.parse import parse_qs, urlsplit

import pytest

boto3 = pytest.importorskip("boto3")

from axentra.storage.backends import (  # noqa: E402
    S3_CONNECT_TIMEOUT_SECONDS,
    S3_MAX_ATTEMPTS,
    S3_READ_TIMEOUT_SECONDS,
    S3Backend,
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
