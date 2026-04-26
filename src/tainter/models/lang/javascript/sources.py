# src/tainter/models/lang/javascript/sources.py
"""JavaScript taint source definitions — Express, Next.js, NestJS."""

from tainter.core.types import TaintSource
from tainter.models.registry import SourceRegistry

# --- Express ---

EXPRESS_SOURCES: tuple[TaintSource, ...] = (
    TaintSource(
        module="express", function="Request", attribute="body",
        framework="express", description="Express request body",
    ),
    TaintSource(
        module="express", function="Request", attribute="params",
        framework="express", description="Express route parameters",
    ),
    TaintSource(
        module="express", function="Request", attribute="query",
        framework="express", description="Express query string parameters",
    ),
    TaintSource(
        module="express", function="Request", attribute="headers",
        framework="express", description="Express request headers",
    ),
    TaintSource(
        module="express", function="Request", attribute="cookies",
        framework="express", description="Express cookies",
    ),
)

# --- Next.js ---

NEXTJS_SOURCES: tuple[TaintSource, ...] = (
    TaintSource(
        module="next", function="NextApiRequest", attribute="query",
        framework="nextjs", description="Next.js API route query parameters",
    ),
    TaintSource(
        module="next", function="context", attribute="params",
        framework="nextjs", description="Next.js page context params",
    ),
    TaintSource(
        module="next/navigation", function="searchParams",
        framework="nextjs", description="Next.js searchParams (App Router)",
    ),
)

# --- NestJS ---

NESTJS_SOURCES: tuple[TaintSource, ...] = (
    TaintSource(
        module="@nestjs/common", function="Body",
        framework="nestjs", description="NestJS @Body() decorator parameter",
    ),
    TaintSource(
        module="@nestjs/common", function="Param",
        framework="nestjs", description="NestJS @Param() decorator parameter",
    ),
    TaintSource(
        module="@nestjs/common", function="Query",
        framework="nestjs", description="NestJS @Query() decorator parameter",
    ),
    TaintSource(
        module="@nestjs/common", function="Headers",
        framework="nestjs", description="NestJS @Headers() decorator parameter",
    ),
)


def get_all_javascript_sources() -> tuple[TaintSource, ...]:
    return EXPRESS_SOURCES + NEXTJS_SOURCES + NESTJS_SOURCES


def create_javascript_source_registry() -> SourceRegistry:
    registry = SourceRegistry()
    registry.register_all(get_all_javascript_sources())
    return registry
