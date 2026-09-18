"""Read-only monitoring API for the PRL HAProxy relay."""

from .app import create_app

__all__ = ["create_app"]
