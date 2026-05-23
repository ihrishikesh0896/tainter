"""
Taint source definitions — backward-compatible re-export.

Content lives in models/lang/python/sources.py.
Registry classes live in models/registry.py.
"""

from tainter.models.registry import SourceRegistry
from tainter.models.lang.python.sources import (
    FLASK_SOURCES,
    DJANGO_SOURCES,
    FASTAPI_SOURCES,
    AIOHTTP_SOURCES,
    TORNADO_SOURCES,
    CLI_SOURCES,
    BUILTIN_SOURCES,
    get_all_sources,
    create_default_registry,
)

__all__ = [
    "SourceRegistry",
    "FLASK_SOURCES",
    "DJANGO_SOURCES",
    "FASTAPI_SOURCES",
    "AIOHTTP_SOURCES",
    "TORNADO_SOURCES",
    "CLI_SOURCES",
    "BUILTIN_SOURCES",
    "get_all_sources",
    "create_default_registry",
]
