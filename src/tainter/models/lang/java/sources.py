"""
Java taint source definitions.

Sources are where untrusted data enters a Java application.
Covers Servlet API, Spring MVC / Spring Boot, JAX-RS, and Java I/O.
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
    # Jakarta EE equivalents
    TaintSource(
        module="jakarta.servlet.http", function="HttpServletRequest",
        attribute="getParameter", framework="servlet",
        description="Jakarta HTTP request parameter",
    ),
    TaintSource(
        module="jakarta.servlet.http", function="HttpServletRequest",
        attribute="getHeader", framework="servlet",
        description="Jakarta HTTP request header",
    ),
)

# --- Spring MVC / Spring Boot ---

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
    TaintSource(
        module="org.springframework.web.bind.annotation", function="MatrixVariable",
        framework="spring",
        description="Spring @MatrixVariable annotated parameter",
    ),
    TaintSource(
        module="org.springframework.http", function="HttpEntity",
        attribute="getBody", framework="spring",
        description="Spring HttpEntity request body",
    ),
    TaintSource(
        module="org.springframework.web.multipart", function="MultipartFile",
        attribute="getOriginalFilename", framework="spring",
        description="Multipart file upload original filename",
    ),
    TaintSource(
        module="org.springframework.web.multipart", function="MultipartFile",
        attribute="getBytes", framework="spring",
        description="Multipart file upload bytes",
    ),
    TaintSource(
        module="org.springframework.core.env", function="Environment",
        attribute="getProperty", framework="spring",
        description="Spring Environment property (can be externally configured)",
    ),
    TaintSource(
        module="org.springframework.web.context.request", function="WebRequest",
        attribute="getParameter", framework="spring",
        description="Spring WebRequest parameter",
    ),
    TaintSource(
        module="org.springframework.web.context.request", function="NativeWebRequest",
        attribute="getParameter", framework="spring",
        description="Spring NativeWebRequest parameter",
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
    TaintSource(
        module="javax.ws.rs", function="CookieParam",
        framework="jaxrs",
        description="JAX-RS @CookieParam annotated parameter",
    ),
    TaintSource(
        module="javax.ws.rs.core", function="UriInfo",
        attribute="getQueryParameters", framework="jaxrs",
        description="JAX-RS UriInfo query parameters",
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
        description="Reading token from Scanner",
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
    TaintSource(
        module="java.util", function="Properties",
        attribute="getProperty",
        description="Properties file value",
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
