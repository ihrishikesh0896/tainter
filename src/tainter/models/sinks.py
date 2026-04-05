"""Python taint sinks — re-exports from lang/python/sinks."""

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
    XXEIS_SINKS,
    XPATH_INJECTION_SINKS,
    LOG_INJECTION_SINKS,
    get_all_sinks,
    create_default_registry,
)
from tainter.models.registry import SinkRegistry

__all__ = [
    "SQL_SINKS",
    "RCE_SINKS",
    "SSTI_SINKS",
    "XSS_SINKS",
    "SSRF_SINKS",
    "DESERIALIZE_SINKS",
    "PATH_TRAVERSAL_SINKS",
    "LDAP_INJECTION_SINKS",
    "HEADER_INJECTION_SINKS",
    "XXEIS_SINKS",
    "XPATH_INJECTION_SINKS",
    "LOG_INJECTION_SINKS",
    "get_all_sinks",
    "create_default_registry",
    "SinkRegistry",
]
