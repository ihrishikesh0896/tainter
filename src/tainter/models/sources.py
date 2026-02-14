"""
Taint source definitions.

Sources are where untrusted data enters the application.
"""

from typing import Optional
from tainter.core.types import TaintSource


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


class SourceRegistry:
    """Registry for taint sources with lookup capabilities."""
    
    def __init__(self) -> None:
        self._sources: dict[str, TaintSource] = {}
        self._by_framework: dict[str, list[TaintSource]] = {}
    
    def register(self, source: TaintSource) -> None:
        self._sources[source.qualified_name] = source
        if source.framework:
            self._by_framework.setdefault(source.framework, []).append(source)
    
    def register_all(self, sources: tuple[TaintSource, ...]) -> None:
        for source in sources:
            self.register(source)
    
    def get(self, qualified_name: str) -> Optional[TaintSource]:
        return self._sources.get(qualified_name)
    
    def get_by_framework(self, framework: str) -> list[TaintSource]:
        return self._by_framework.get(framework, [])
    
    def match(self, module: str, function: str, attribute: Optional[str] = None) -> Optional[TaintSource]:
        if attribute:
            key = f"{module}.{function}.{attribute}"
            if key in self._sources:
                return self._sources[key]
        key = f"{module}.{function}"
        return self._sources.get(key)
    
    def all_sources(self) -> list[TaintSource]:
        return list(self._sources.values())


def get_all_sources() -> tuple[TaintSource, ...]:
    return (*FLASK_SOURCES, *DJANGO_SOURCES, *FASTAPI_SOURCES, *CLI_SOURCES, *BUILTIN_SOURCES)


def create_default_registry() -> SourceRegistry:
    registry = SourceRegistry()
    registry.register_all(get_all_sources())
    return registry
