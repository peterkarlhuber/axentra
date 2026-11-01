"""Axentra: a modular, reusable backend foundation for SaaS products.

Two supported ways to use it:

- As a library inside a product backend: build an :class:`~axentra.platform.Axentra` from
  :class:`~axentra.config.Settings` and call its services with an explicit security context.
- As an HTTP service: ``axentra serve`` runs the versioned ``/v1`` API (``axentra[server]``).

Axentra never depends on Axentra Studio, Nodestro or orkexa.
"""

from typing import TYPE_CHECKING, Any

from axentra._version import __version__

API_VERSION = (1, 0)
"""The ``/v1`` contract version (major, minor) this release serves."""

__all__ = ["API_VERSION", "Settings", "__version__", "load_settings"]

if TYPE_CHECKING:
    from axentra.config.settings import Settings, load_settings


def __getattr__(name: str) -> Any:
    # Lazy, so `import axentra` (e.g. for __version__) stays cheap.
    if name in ("Settings", "load_settings"):
        from axentra.config import settings

        return getattr(settings, name)
    raise AttributeError(f"module 'axentra' has no attribute {name!r}")
