"""
Taint sink definitions — backward-compatible re-export.

Content lives in models/lang/python/sinks.py.
Registry classes live in models/registry.py.
"""

from tainter.models.registry import SinkRegistry
from tainter.models.lang.python.sinks import (
    SQL_SINKS,
    RCE_SINKS,
    SSTI_SINKS,
    XSS_SINKS,
    SSRF_SINKS,
    DESERIALIZE_SINKS,
    PATH_TRAVERSAL_SINKS,
    LDAP_INJECTION_SINKS,
    HEADER_INJECTION_SINKS,
    XXE_SINKS,
    get_all_sinks,
    create_default_registry,
)

# Keep old name alias for any code that used XXEIS_SINKS
XXEIS_SINKS = XXE_SINKS

__all__ = [
    "SinkRegistry",
    "SQL_SINKS",
    "RCE_SINKS",
    "SSTI_SINKS",
    "XSS_SINKS",
    "SSRF_SINKS",
    "DESERIALIZE_SINKS",
    "PATH_TRAVERSAL_SINKS",
    "LDAP_INJECTION_SINKS",
    "HEADER_INJECTION_SINKS",
    "XXE_SINKS",
    "XXEIS_SINKS",
    "get_all_sinks",
    "create_default_registry",
]
