"""Axentra: a modular, reusable backend foundation for SaaS products.

Two supported ways to use it:

- As a library inside a product backend: build an :class:`~axentra.platform.Axentra` from
  :class:`~axentra.config.Settings` and call its services with an explicit security context.
- As an HTTP service: ``axentra serve`` runs the versioned ``/v1`` API (``axentra[server]``).

Axentra never depends on Axentra Studio, Nodestro or orkexa.
"""

from axentra._version import __version__

API_VERSION = (1, 0)
"""The ``/v1`` contract version (major, minor) this release serves."""

__all__ = ["API_VERSION", "__version__"]
