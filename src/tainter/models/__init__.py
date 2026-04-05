"""
Taint models: sources, sinks, and sanitizers.

Language-specific definitions live under lang/python/ and lang/java/.
Shared registry classes live in registry.py.
"""

from tainter.models.registry import SourceRegistry, SinkRegistry, SanitizerRegistry

from tainter.models.lang.python.sources import (
    FLASK_SOURCES,
    DJANGO_SOURCES,
    FASTAPI_SOURCES,
    CLI_SOURCES,
    BUILTIN_SOURCES,
    get_all_sources,
)

from tainter.models.lang.python.sinks import (
    SQL_SINKS,
    RCE_SINKS,
    SSTI_SINKS,
    SSRF_SINKS,
    DESERIALIZE_SINKS,
    PATH_TRAVERSAL_SINKS,
    get_all_sinks,
)

from tainter.models.lang.python.sanitizers import (
    SQL_SANITIZERS,
    GENERAL_SANITIZERS,
    get_all_sanitizers,
)

__all__ = [
    # Source collections
    "FLASK_SOURCES",
    "DJANGO_SOURCES",
    "FASTAPI_SOURCES",
    "CLI_SOURCES",
    "BUILTIN_SOURCES",
    "get_all_sources",
    "SourceRegistry",
    # Sink collections
    "SQL_SINKS",
    "RCE_SINKS",
    "SSTI_SINKS",
    "SSRF_SINKS",
    "DESERIALIZE_SINKS",
    "PATH_TRAVERSAL_SINKS",
    "get_all_sinks",
    "SinkRegistry",
    # Sanitizer collections
    "SQL_SANITIZERS",
    "GENERAL_SANITIZERS",
    "get_all_sanitizers",
    "SanitizerRegistry",
]
