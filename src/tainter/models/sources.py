"""Python taint sources — re-exports from lang/python/sources."""

from tainter.models.lang.python.sources import (
    FLASK_SOURCES,
    DJANGO_SOURCES,
    FASTAPI_SOURCES,
    TORNADO_SOURCES,
    AIOHTTP_SOURCES,
    CLI_SOURCES,
    BUILTIN_SOURCES,
    get_all_sources,
    create_default_registry,
)
from tainter.models.registry import SourceRegistry

__all__ = [
    "FLASK_SOURCES",
    "DJANGO_SOURCES",
    "FASTAPI_SOURCES",
    "TORNADO_SOURCES",
    "AIOHTTP_SOURCES",
    "CLI_SOURCES",
    "BUILTIN_SOURCES",
    "get_all_sources",
    "create_default_registry",
    "SourceRegistry",
]
