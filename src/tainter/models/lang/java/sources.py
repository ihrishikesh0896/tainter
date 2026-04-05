"""
Java taint source definitions.

Sources are where untrusted data enters a Java application.
Covers Servlet API, Spring MVC, JAX-RS, and Java I/O.
"""

from tainter.core.types import TaintSource
from tainter.models.registry import SourceRegistry


# --- Servlet API ---

SERVLET_SOURCES: tuple[TaintSource, ...] = (
    TaintSource(
        module="javax.servlet.http", function="HttpServletRequest",
        attribute="getParameter", framework="servlet",
        description="HTTP request parameter",
    ),
    TaintSource(
        module="javax.servlet.http", function="HttpServletRequest",
        attribute="getParameterValues", framework="servlet",
        description="HTTP request parameter values",
    ),
    TaintSource(
        module="javax.servlet.http", function="HttpServletRequest",
        attribute="getParameterMap", framework="servlet",
        description="HTTP request parameter map",
    ),
    TaintSource(
        module="javax.servlet.http", function="HttpServletRequest",
        attribute="getHeader", framework="servlet",
        description="HTTP request header",
    ),
    TaintSource(
        module="javax.servlet.http", function="HttpServletRequest",
        attribute="getCookies", framework="servlet",
        description="HTTP cookies",
    ),
    TaintSource(
        module="javax.servlet.http", function="HttpServletRequest",
        attribute="getQueryString", framework="servlet",
        description="HTTP query string",
    ),
    TaintSource(
        module="javax.servlet.http", function="HttpServletRequest",
        attribute="getRequestURI", framework="servlet",
        description="HTTP request URI",
    ),
    TaintSource(
        module="javax.servlet.http", function="HttpServletRequest",
        attribute="getInputStream", framework="servlet",
        description="HTTP request input stream",
    ),
    TaintSource(
        module="javax.servlet.http", function="HttpServletRequest",
        attribute="getReader", framework="servlet",
        description="HTTP request reader",
    ),
    TaintSource(
        module="javax.servlet.http", function="HttpServletRequest",
        attribute="getPathInfo", framework="servlet",
        description="HTTP path info",
    ),
)

# --- Spring MVC ---

SPRING_SOURCES: tuple[TaintSource, ...] = (
    TaintSource(
        module="org.springframework.web.bind.annotation", function="RequestParam",
        framework="spring",
        description="Spring @RequestParam annotated parameter",
    ),
    TaintSource(
        module="org.springframework.web.bind.annotation", function="PathVariable",
        framework="spring",
        description="Spring @PathVariable annotated parameter",
    ),
    TaintSource(
        module="org.springframework.web.bind.annotation", function="RequestBody",
        framework="spring",
        description="Spring @RequestBody annotated parameter",
    ),
    TaintSource(
        module="org.springframework.web.bind.annotation", function="RequestHeader",
        framework="spring",
        description="Spring @RequestHeader annotated parameter",
    ),
    TaintSource(
        module="org.springframework.web.bind.annotation", function="CookieValue",
        framework="spring",
        description="Spring @CookieValue annotated parameter",
    ),
)

# --- JAX-RS ---

JAXRS_SOURCES: tuple[TaintSource, ...] = (
    TaintSource(
        module="javax.ws.rs", function="QueryParam",
        framework="jaxrs",
        description="JAX-RS @QueryParam annotated parameter",
    ),
    TaintSource(
        module="javax.ws.rs", function="PathParam",
        framework="jaxrs",
        description="JAX-RS @PathParam annotated parameter",
    ),
    TaintSource(
        module="javax.ws.rs", function="FormParam",
        framework="jaxrs",
        description="JAX-RS @FormParam annotated parameter",
    ),
    TaintSource(
        module="javax.ws.rs", function="HeaderParam",
        framework="jaxrs",
        description="JAX-RS @HeaderParam annotated parameter",
    ),
)

# --- Java I/O ---

JAVA_IO_SOURCES: tuple[TaintSource, ...] = (
    TaintSource(
        module="java.io", function="BufferedReader",
        attribute="readLine",
        description="Reading input from stream",
    ),
    TaintSource(
        module="java.util", function="Scanner",
        attribute="nextLine",
        description="Reading input from Scanner",
    ),
    TaintSource(
        module="java.util", function="Scanner",
        attribute="next",
        description="Reading input from Scanner",
    ),
    TaintSource(
        module="java.lang", function="System",
        attribute="getenv",
        description="Environment variable",
    ),
    TaintSource(
        module="java.lang", function="System",
        attribute="getProperty",
        description="System property",
    ),
)


def get_all_java_sources() -> tuple[TaintSource, ...]:
    """Return all Java taint sources."""
    return SERVLET_SOURCES + SPRING_SOURCES + JAXRS_SOURCES + JAVA_IO_SOURCES


def create_java_source_registry() -> SourceRegistry:
    """Create a registry with all Java sources."""
    registry = SourceRegistry()
    registry.register_all(get_all_java_sources())
    return registry
