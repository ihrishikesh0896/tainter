"""
Python taint source definitions.

Sources are where untrusted data enters the application.
"""

from tainter.core.types import TaintSource
from tainter.models.registry import SourceRegistry


FLASK_SOURCES: tuple[TaintSource, ...] = (
    TaintSource(module="flask", function="request", attribute="args", framework="flask"),
    TaintSource(module="flask", function="request", attribute="form", framework="flask"),
    TaintSource(module="flask", function="request", attribute="values", framework="flask"),
    TaintSource(module="flask", function="request", attribute="json", framework="flask"),
    TaintSource(module="flask", function="request", attribute="data", framework="flask"),
    TaintSource(module="flask", function="request", attribute="cookies", framework="flask"),
    TaintSource(module="flask", function="request", attribute="headers", framework="flask"),
    TaintSource(module="flask", function="request.get_json", framework="flask"),
)

DJANGO_SOURCES: tuple[TaintSource, ...] = (
    TaintSource(module="django.http", function="HttpRequest", attribute="GET", framework="django"),
    TaintSource(module="django.http", function="HttpRequest", attribute="POST", framework="django"),
    TaintSource(module="django.http", function="HttpRequest", attribute="COOKIES", framework="django"),
    TaintSource(module="django.http", function="HttpRequest", attribute="META", framework="django"),
    TaintSource(module="django.http", function="request.GET.get", framework="django"),
    TaintSource(module="django.http", function="request.POST.get", framework="django"),
)

FASTAPI_SOURCES: tuple[TaintSource, ...] = (
    TaintSource(module="starlette.requests", function="Request", attribute="query_params", framework="fastapi"),
    TaintSource(module="starlette.requests", function="Request", attribute="path_params", framework="fastapi"),
    TaintSource(module="starlette.requests", function="Request.json", framework="fastapi"),
    TaintSource(module="fastapi", function="Query", framework="fastapi"),
    TaintSource(module="fastapi", function="Path", framework="fastapi"),
    TaintSource(module="fastapi", function="Body", framework="fastapi"),
)

AIOHTTP_SOURCES: tuple[TaintSource, ...] = (
    TaintSource(module="aiohttp.web", function="Request", attribute="query", framework="aiohttp"),
    TaintSource(module="aiohttp.web", function="Request", attribute="match_info", framework="aiohttp"),
    TaintSource(module="aiohttp.web", function="Request.json", framework="aiohttp"),
    TaintSource(module="aiohttp.web", function="Request.text", framework="aiohttp"),
)

TORNADO_SOURCES: tuple[TaintSource, ...] = (
    TaintSource(module="tornado.web", function="RequestHandler.get_argument", framework="tornado"),
    TaintSource(module="tornado.web", function="RequestHandler.get_body_argument", framework="tornado"),
    TaintSource(module="tornado.web", function="RequestHandler.get_query_argument", framework="tornado"),
)

CLI_SOURCES: tuple[TaintSource, ...] = (
    TaintSource(module="builtins", function="input", description="User console input"),
    TaintSource(module="sys", function="argv", description="Command-line arguments"),
    TaintSource(module="argparse", function="ArgumentParser.parse_args", description="Parsed CLI args"),
)

BUILTIN_SOURCES: tuple[TaintSource, ...] = (
    TaintSource(module="os", function="environ", description="Environment variables"),
    TaintSource(module="os", function="getenv", description="Get environment variable"),
    TaintSource(module="json", function="loads", description="Deserialized JSON"),
    TaintSource(module="yaml", function="load", description="Deserialized YAML"),
    TaintSource(module="pickle", function="load", description="Deserialized pickle"),
    TaintSource(module="pickle", function="loads", description="Deserialized pickle string"),
)


def get_all_sources() -> tuple[TaintSource, ...]:
    return (
        *FLASK_SOURCES, *DJANGO_SOURCES, *FASTAPI_SOURCES,
        *AIOHTTP_SOURCES, *TORNADO_SOURCES, *CLI_SOURCES, *BUILTIN_SOURCES,
    )


def create_default_registry() -> SourceRegistry:
    registry = SourceRegistry()
    registry.register_all(get_all_sources())
    return registry
