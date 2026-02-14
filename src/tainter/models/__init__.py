"""
Taint models: sources, sinks, and sanitizers.

This module provides built-in definitions for common frameworks
and allows extensibility for custom models.
"""

from tainter.models.sources import (
    FLASK_SOURCES,
    DJANGO_SOURCES,
    FASTAPI_SOURCES,
    CLI_SOURCES,
    BUILTIN_SOURCES,
    get_all_sources,
    SourceRegistry,
)

from tainter.models.sinks import (
    SQL_SINKS,
    RCE_SINKS,
    SSTI_SINKS,
    SSRF_SINKS,
    DESERIALIZE_SINKS,
    PATH_TRAVERSAL_SINKS,
    get_all_sinks,
    SinkRegistry,
)

from tainter.models.sanitizers import (
    SQL_SANITIZERS,
    GENERAL_SANITIZERS,
    get_all_sanitizers,
    SanitizerRegistry,
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
