"""Carriex message server package."""

from .app import app, create_app
from ._version import __version__

__all__ = ["app", "create_app", "__version__"]
