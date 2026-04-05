"""Java taint models."""

from tainter.models.lang.java.sources import (
    JAVA_IO_SOURCES,
    JAXRS_SOURCES,
    SERVLET_SOURCES,
    SPRING_SOURCES,
    create_java_source_registry,
    get_all_java_sources,
)
from tainter.models.lang.java.sinks import (
    JAVA_DESERIALIZE_SINKS,
    JAVA_LDAP_SINKS,
    JAVA_PATH_TRAVERSAL_SINKS,
    JAVA_RCE_SINKS,
    JAVA_SQL_SINKS,
    JAVA_SSRF_SINKS,
    JAVA_SSTI_SINKS,
    JAVA_XXE_SINKS,
    JAVA_XSS_SINKS,
    create_java_sink_registry,
    get_all_java_sinks,
)
from tainter.models.lang.java.sanitizers import (
    JAVA_GENERAL_SANITIZERS,
    JAVA_PATH_SANITIZERS,
    JAVA_SQL_SANITIZERS,
    JAVA_XSS_SANITIZERS,
    create_java_sanitizer_registry,
    get_all_java_sanitizers,
)

__all__ = [
    "JAVA_IO_SOURCES",
    "JAXRS_SOURCES",
    "SERVLET_SOURCES",
    "SPRING_SOURCES",
    "create_java_source_registry",
    "get_all_java_sources",
    "JAVA_DESERIALIZE_SINKS",
    "JAVA_LDAP_SINKS",
    "JAVA_PATH_TRAVERSAL_SINKS",
    "JAVA_RCE_SINKS",
    "JAVA_SQL_SINKS",
    "JAVA_SSRF_SINKS",
    "JAVA_SSTI_SINKS",
    "JAVA_XXE_SINKS",
    "JAVA_XSS_SINKS",
    "create_java_sink_registry",
    "get_all_java_sinks",
    "JAVA_GENERAL_SANITIZERS",
    "JAVA_PATH_SANITIZERS",
    "JAVA_SQL_SANITIZERS",
    "JAVA_XSS_SANITIZERS",
    "create_java_sanitizer_registry",
    "get_all_java_sanitizers",
]

