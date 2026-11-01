"""The versioned HTTP API (``/v1``): a thin FastAPI layer over the Axentra services."""

from axentra.api.app import create_app

__all__ = ["create_app"]
