"""axentra-client: a pure HTTP client for the Axentra API (sync and async).

    from axentra_client import AxentraClient

    with AxentraClient("https://api.example.com", api_key="axk_...") as ax:
        ax.check_compatibility()
        for tenant in ax.tenants.iter("prd_..."):
            print(tenant.slug)

This package never imports the ``axentra`` server package.
"""

from axentra_client._async.client import AsyncAxentraClient
from axentra_client._base import (
    CLIENT_HEADER,
    IDEMPOTENCY_KEY_MAX_LENGTH,
    assert_compatible,
    new_idempotency_key,
)
from axentra_client._sync.client import AxentraClient
from axentra_client._version import API_VERSION, __version__
from axentra_client.errors import AxentraApiError, AxentraError, IncompatibleApiError
from axentra_client.models import Page

__all__ = [
    "API_VERSION",
    "CLIENT_HEADER",
    "IDEMPOTENCY_KEY_MAX_LENGTH",
    "AsyncAxentraClient",
    "AxentraApiError",
    "AxentraClient",
    "AxentraError",
    "IncompatibleApiError",
    "Page",
    "__version__",
    "assert_compatible",
    "new_idempotency_key",
]
