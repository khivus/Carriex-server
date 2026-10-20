"""Carriex message server package."""

from ._version import __version__

__all__ = ["app", "create_app", "__version__"]


def __getattr__(name):
    # CLI tools must not open a default relay database just by importing src.
    if name in {"app", "create_app"}:
        from importlib import import_module
        module = import_module(".app", __name__)
        globals().update(app=module.app, create_app=module.create_app)
        return globals()[name]
    raise AttributeError(name)
