"""Python taint models."""

from tainter.models.lang.python.sources import (
    AIOHTTP_SOURCES,
    BUILTIN_SOURCES,
    CLI_SOURCES,
    DJANGO_SOURCES,
    FASTAPI_SOURCES,
    FLASK_SOURCES,
    SourceRegistry,
    TORNADO_SOURCES,
    create_default_registry as create_source_registry,
    get_all_sources,
)
from tainter.models.lang.python.sinks import (
    DESERIALIZE_SINKS,
    PATH_TRAVERSAL_SINKS,
    RCE_SINKS,
    SQL_SINKS,
    SSRF_SINKS,
    SSTI_SINKS,
    SinkRegistry,
    XSS_SINKS,
    create_default_registry as create_sink_registry,
    get_all_sinks,
)
from tainter.models.lang.python.sanitizers import (
    GENERAL_SANITIZERS,
    SQL_SANITIZERS,
    SanitizerRegistry,
    create_default_registry as create_sanitizer_registry,
    get_all_sanitizers,
)

__all__ = [
    "AIOHTTP_SOURCES",
    "BUILTIN_SOURCES",
    "CLI_SOURCES",
    "DJANGO_SOURCES",
    "FASTAPI_SOURCES",
    "FLASK_SOURCES",
    "SourceRegistry",
    "TORNADO_SOURCES",
    "create_source_registry",
    "get_all_sources",
    "DESERIALIZE_SINKS",
    "PATH_TRAVERSAL_SINKS",
    "RCE_SINKS",
    "SQL_SINKS",
    "SSRF_SINKS",
    "SSTI_SINKS",
    "SinkRegistry",
    "XSS_SINKS",
    "create_sink_registry",
    "get_all_sinks",
    "GENERAL_SANITIZERS",
    "SQL_SANITIZERS",
    "SanitizerRegistry",
    "create_sanitizer_registry",
    "get_all_sanitizers",
]

