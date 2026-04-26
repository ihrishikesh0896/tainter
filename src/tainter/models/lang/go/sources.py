# src/tainter/models/lang/go/sources.py
"""Go taint source definitions — net/http, Gin, Echo."""

from tainter.core.types import TaintSource
from tainter.models.registry import SourceRegistry

# --- net/http ---

NET_HTTP_SOURCES: tuple[TaintSource, ...] = (
    TaintSource(
        module="net/http", function="Query.Get", attribute="Query",
        framework="go", description="HTTP request query parameter via Query().Get()",
    ),
    TaintSource(
        module="net/http", function="FormValue",
        framework="go", description="HTTP request form value",
    ),
    TaintSource(
        module="net/http", function="Header.Get", attribute="Header",
        framework="go", description="HTTP request header via Header().Get()",
    ),
    TaintSource(
        module="net/http", function="PathValue",
        framework="go", description="HTTP request path value",
    ),
)

# --- Gin ---

GIN_SOURCES: tuple[TaintSource, ...] = (
    TaintSource(
        module="github.com/gin-gonic/gin", function="Param",
        framework="go", description="Gin context parameter",
    ),
    TaintSource(
        module="github.com/gin-gonic/gin", function="Query",
        framework="go", description="Gin context query parameter",
    ),
    TaintSource(
        module="github.com/gin-gonic/gin", function="PostForm",
        framework="go", description="Gin context post form value",
    ),
    TaintSource(
        module="github.com/gin-gonic/gin", function="GetHeader",
        framework="go", description="Gin context header value",
    ),
    TaintSource(
        module="github.com/gin-gonic/gin", function="ShouldBind",
        framework="go", description="Gin context ShouldBind (binds request data)",
    ),
)

# --- Echo ---

ECHO_SOURCES: tuple[TaintSource, ...] = (
    TaintSource(
        module="github.com/labstack/echo", function="Param",
        framework="go", description="Echo context parameter",
    ),
    TaintSource(
        module="github.com/labstack/echo", function="QueryParam",
        framework="go", description="Echo context query parameter",
    ),
    TaintSource(
        module="github.com/labstack/echo", function="FormValue",
        framework="go", description="Echo context form value",
    ),
)


def get_all_go_sources() -> tuple[TaintSource, ...]:
    return NET_HTTP_SOURCES + GIN_SOURCES + ECHO_SOURCES


def create_go_source_registry() -> SourceRegistry:
    registry = SourceRegistry()
    registry.register_all(get_all_go_sources())
    return registry
