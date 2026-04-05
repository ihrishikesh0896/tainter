"""
Taint source definitions.

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
    TaintSource(module="flask", function="request", attribute="files", framework="flask",
                description="Uploaded files — filename and content are attacker-controlled"),
    TaintSource(module="flask", function="request", attribute="stream", framework="flask",
                description="Raw request stream"),
    TaintSource(module="flask", function="request", attribute="environ", framework="flask",
                description="WSGI environ — contains raw HTTP headers and server vars"),
    TaintSource(module="flask", function="request.get_json", framework="flask"),
    TaintSource(module="flask", function="request.get_data", framework="flask",
                description="Raw request body bytes"),
    TaintSource(module="flask", function="request.args.get", framework="flask"),
    TaintSource(module="flask", function="request.form.get", framework="flask"),
    TaintSource(module="flask", function="request.headers.get", framework="flask"),
    TaintSource(module="flask", function="request.cookies.get", framework="flask"),
)

DJANGO_SOURCES: tuple[TaintSource, ...] = (
    TaintSource(module="django.http", function="HttpRequest", attribute="GET", framework="django"),
    TaintSource(module="django.http", function="HttpRequest", attribute="POST", framework="django"),
    TaintSource(module="django.http", function="HttpRequest", attribute="COOKIES", framework="django"),
    TaintSource(module="django.http", function="HttpRequest", attribute="META", framework="django"),
    TaintSource(module="django.http", function="HttpRequest", attribute="FILES", framework="django",
                description="Uploaded files — filename and content are attacker-controlled"),
    TaintSource(module="django.http", function="HttpRequest", attribute="body", framework="django",
                description="Raw request body bytes"),
    TaintSource(module="django.http", function="HttpRequest", attribute="data", framework="django",
                description="DRF request.data — parsed request body"),
    TaintSource(module="django.http", function="HttpRequest", attribute="headers", framework="django",
                description="HTTP request headers"),
    TaintSource(module="django.http", function="request.GET.get", framework="django"),
    TaintSource(module="django.http", function="request.POST.get", framework="django"),
    TaintSource(module="django.http", function="request.FILES.get", framework="django"),
    TaintSource(module="django.http", function="request.headers.get", framework="django"),
    # URL resolver kwargs (captured path parameters)
    TaintSource(module="django.urls", function="resolve", framework="django",
                description="URL resolver kwargs from path parameters"),
)

FASTAPI_SOURCES: tuple[TaintSource, ...] = (
    TaintSource(module="starlette.requests", function="Request", attribute="query_params", framework="fastapi"),
    TaintSource(module="starlette.requests", function="Request", attribute="path_params", framework="fastapi"),
    TaintSource(module="starlette.requests", function="Request", attribute="headers", framework="fastapi"),
    TaintSource(module="starlette.requests", function="Request", attribute="cookies", framework="fastapi"),
    TaintSource(module="starlette.requests", function="Request.json", framework="fastapi"),
    TaintSource(module="starlette.requests", function="Request.body", framework="fastapi",
                description="Raw request body bytes"),
    TaintSource(module="starlette.requests", function="Request.form", framework="fastapi"),
    TaintSource(module="fastapi", function="Query", framework="fastapi"),
    TaintSource(module="fastapi", function="Path", framework="fastapi"),
    TaintSource(module="fastapi", function="Body", framework="fastapi"),
    TaintSource(module="fastapi", function="Header", framework="fastapi",
                description="HTTP header value injected as FastAPI dependency"),
    TaintSource(module="fastapi", function="Cookie", framework="fastapi",
                description="Cookie value injected as FastAPI dependency"),
    TaintSource(module="fastapi", function="Form", framework="fastapi",
                description="Form field value injected as FastAPI dependency"),
    TaintSource(module="fastapi", function="File", framework="fastapi",
                description="Uploaded file injected as FastAPI dependency"),
)

TORNADO_SOURCES: tuple[TaintSource, ...] = (
    TaintSource(module="tornado.web", function="RequestHandler.get_argument", framework="tornado",
                description="Tornado query/form parameter"),
    TaintSource(module="tornado.web", function="RequestHandler.get_body_argument", framework="tornado",
                description="Tornado body parameter"),
    TaintSource(module="tornado.web", function="RequestHandler.get_query_argument", framework="tornado",
                description="Tornado query string parameter"),
    TaintSource(module="tornado.web", function="RequestHandler", attribute="request", framework="tornado",
                description="Tornado request object"),
    TaintSource(module="tornado.web", function="RequestHandler.get_cookie", framework="tornado",
                description="Tornado cookie value"),
)

AIOHTTP_SOURCES: tuple[TaintSource, ...] = (
    TaintSource(module="aiohttp.web", function="Request", attribute="rel_url", framework="aiohttp",
                description="aiohttp request URL (query string)"),
    TaintSource(module="aiohttp.web", function="Request", attribute="match_info", framework="aiohttp",
                description="aiohttp URL path parameters"),
    TaintSource(module="aiohttp.web", function="Request", attribute="headers", framework="aiohttp",
                description="aiohttp HTTP request headers"),
    TaintSource(module="aiohttp.web", function="Request", attribute="cookies", framework="aiohttp",
                description="aiohttp request cookies"),
    TaintSource(module="aiohttp.web", function="Request.json", framework="aiohttp",
                description="aiohttp JSON body (awaitable)"),
    TaintSource(module="aiohttp.web", function="Request.post", framework="aiohttp",
                description="aiohttp parsed form/multipart body (awaitable)"),
    TaintSource(module="aiohttp.web", function="Request.text", framework="aiohttp",
                description="aiohttp raw text body (awaitable)"),
    TaintSource(module="aiohttp.web", function="Request.read", framework="aiohttp",
                description="aiohttp raw bytes body (awaitable)"),
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
        *FLASK_SOURCES,
        *DJANGO_SOURCES,
        *FASTAPI_SOURCES,
        *TORNADO_SOURCES,
        *AIOHTTP_SOURCES,
        *CLI_SOURCES,
        *BUILTIN_SOURCES,
    )


def create_default_registry() -> SourceRegistry:
    registry = SourceRegistry()
    registry.register_all(get_all_sources())
    return registry
