"""
Taint sink definitions.

Sinks are dangerous operations where tainted data can cause harm.
"""

from typing import Optional
from tainter.core.types import TaintSink, VulnerabilityClass

SQL_SINKS: tuple[TaintSink, ...] = (
    TaintSink(module="sqlite3", function="Cursor.execute", vulnerable_parameters=(0,),
              vulnerability_class=VulnerabilityClass.SQLI),
    TaintSink(module="sqlite3", function="Cursor.executemany", vulnerable_parameters=(0,),
              vulnerability_class=VulnerabilityClass.SQLI),
    TaintSink(module="sqlite3", function="Cursor.executescript", vulnerable_parameters=(0,),
              vulnerability_class=VulnerabilityClass.SQLI),
    TaintSink(module="psycopg2", function="cursor.execute", vulnerable_parameters=(0,),
              vulnerability_class=VulnerabilityClass.SQLI),
    TaintSink(module="psycopg2", function="cursor.executemany", vulnerable_parameters=(0,),
              vulnerability_class=VulnerabilityClass.SQLI),
    TaintSink(module="MySQLdb", function="cursor.execute", vulnerable_parameters=(0,),
              vulnerability_class=VulnerabilityClass.SQLI),
    TaintSink(module="MySQLdb", function="cursor.executemany", vulnerable_parameters=(0,),
              vulnerability_class=VulnerabilityClass.SQLI),
    TaintSink(module="pymysql", function="cursor.execute", vulnerable_parameters=(0,),
              vulnerability_class=VulnerabilityClass.SQLI),
    TaintSink(module="mysql.connector", function="cursor.execute", vulnerable_parameters=(0,),
              vulnerability_class=VulnerabilityClass.SQLI),
    TaintSink(module="sqlalchemy", function="text", vulnerable_parameters=(0,),
              vulnerability_class=VulnerabilityClass.SQLI),
    TaintSink(module="sqlalchemy", function="Engine.execute", vulnerable_parameters=(0,),
              vulnerability_class=VulnerabilityClass.SQLI),
    TaintSink(module="sqlalchemy", function="Connection.execute", vulnerable_parameters=(0,),
              vulnerability_class=VulnerabilityClass.SQLI),
    TaintSink(module="sqlalchemy", function="Session.execute", vulnerable_parameters=(0,),
              vulnerability_class=VulnerabilityClass.SQLI),
    TaintSink(module="django.db", function="connection.cursor().execute", vulnerable_parameters=(0,),
              vulnerability_class=VulnerabilityClass.SQLI),
    TaintSink(module="django.db", function="RawSQL", vulnerable_parameters=(0,),
              vulnerability_class=VulnerabilityClass.SQLI),
    TaintSink(module="django.db.models", function="raw", vulnerable_parameters=(0,),
              vulnerability_class=VulnerabilityClass.SQLI),
    TaintSink(module="peewee", function="Database.execute_sql", vulnerable_parameters=(0,),
              vulnerability_class=VulnerabilityClass.SQLI),
)

RCE_SINKS: tuple[TaintSink, ...] = (
    TaintSink(module="builtins", function="eval", vulnerable_parameters=(0,),
              vulnerability_class=VulnerabilityClass.RCE),
    TaintSink(module="builtins", function="exec", vulnerable_parameters=(0,),
              vulnerability_class=VulnerabilityClass.RCE),
    TaintSink(module="builtins", function="compile", vulnerable_parameters=(0,),
              vulnerability_class=VulnerabilityClass.RCE),
    TaintSink(module="builtins", function="__import__", vulnerable_parameters=(0,),
              vulnerability_class=VulnerabilityClass.RCE),
    TaintSink(module="os", function="system", vulnerable_parameters=(0,),
              vulnerability_class=VulnerabilityClass.RCE),
    TaintSink(module="os", function="popen", vulnerable_parameters=(0,),
              vulnerability_class=VulnerabilityClass.RCE),
    TaintSink(module="os", function="popen2", vulnerable_parameters=(0,),
              vulnerability_class=VulnerabilityClass.RCE),
    TaintSink(module="os", function="popen3", vulnerable_parameters=(0,),
              vulnerability_class=VulnerabilityClass.RCE),
    TaintSink(module="os", function="popen4", vulnerable_parameters=(0,),
              vulnerability_class=VulnerabilityClass.RCE),
    TaintSink(module="subprocess", function="run", vulnerable_parameters=(0,),
              vulnerability_class=VulnerabilityClass.RCE),
    TaintSink(module="subprocess", function="call", vulnerable_parameters=(0,),
              vulnerability_class=VulnerabilityClass.RCE),
    TaintSink(module="subprocess", function="Popen", vulnerable_parameters=(0,),
              vulnerability_class=VulnerabilityClass.RCE),
    TaintSink(module="subprocess", function="check_output", vulnerable_parameters=(0,),
              vulnerability_class=VulnerabilityClass.RCE),
    TaintSink(module="subprocess", function="check_call", vulnerable_parameters=(0,),
              vulnerability_class=VulnerabilityClass.RCE),
    TaintSink(module="subprocess", function="getoutput", vulnerable_parameters=(0,),
              vulnerability_class=VulnerabilityClass.RCE),
    TaintSink(module="subprocess", function="getstatusoutput", vulnerable_parameters=(0,),
              vulnerability_class=VulnerabilityClass.RCE),
    TaintSink(module="commands", function="getoutput", vulnerable_parameters=(0,),
              vulnerability_class=VulnerabilityClass.RCE),
    TaintSink(module="commands", function="getstatusoutput", vulnerable_parameters=(0,),
              vulnerability_class=VulnerabilityClass.RCE),
    TaintSink(module="importlib", function="import_module", vulnerable_parameters=(0,),
              vulnerability_class=VulnerabilityClass.RCE),
    TaintSink(module="importlib", function="__import__", vulnerable_parameters=(0,),
              vulnerability_class=VulnerabilityClass.RCE),
)

SSTI_SINKS: tuple[TaintSink, ...] = (
    TaintSink(module="jinja2", function="Template", vulnerable_parameters=(0,),
              vulnerability_class=VulnerabilityClass.SSTI),
    TaintSink(module="jinja2", function="Environment.from_string", vulnerable_parameters=(0,),
              vulnerability_class=VulnerabilityClass.SSTI),
    TaintSink(module="flask", function="render_template_string", vulnerable_parameters=(0,),
              vulnerability_class=VulnerabilityClass.SSTI),
    TaintSink(module="django.template", function="Template", vulnerable_parameters=(0,),
              vulnerability_class=VulnerabilityClass.SSTI),
    TaintSink(module="mako.template", function="Template", vulnerable_parameters=(0,),
              vulnerability_class=VulnerabilityClass.SSTI),
    TaintSink(module="tornado.template", function="Template", vulnerable_parameters=(0,),
              vulnerability_class=VulnerabilityClass.SSTI),
    TaintSink(module="bottle", function="template", vulnerable_parameters=(0,),
              vulnerability_class=VulnerabilityClass.SSTI),
)

XSS_SINKS: tuple[TaintSink, ...] = (
    TaintSink(module="flask", function="render_template", vulnerable_parameters=(),
              vulnerability_class=VulnerabilityClass.XSS,
              description="Rendering templates with unescaped context data"),
    TaintSink(module="flask", function="Markup", vulnerable_parameters=(0,),
              vulnerability_class=VulnerabilityClass.XSS,
              description="Marking string as safe HTML without sanitization"),
    TaintSink(module="django.utils.safestring", function="mark_safe", vulnerable_parameters=(0,),
              vulnerability_class=VulnerabilityClass.XSS),
    TaintSink(module="jinja2", function="Markup", vulnerable_parameters=(0,),
              vulnerability_class=VulnerabilityClass.XSS),
)

SSRF_SINKS: tuple[TaintSink, ...] = (
    TaintSink(module="requests", function="get", vulnerable_parameters=(0,),
              vulnerability_class=VulnerabilityClass.SSRF),
    TaintSink(module="requests", function="post", vulnerable_parameters=(0,),
              vulnerability_class=VulnerabilityClass.SSRF),
    TaintSink(module="requests", function="put", vulnerable_parameters=(0,),
              vulnerability_class=VulnerabilityClass.SSRF),
    TaintSink(module="requests", function="delete", vulnerable_parameters=(0,),
              vulnerability_class=VulnerabilityClass.SSRF),
    TaintSink(module="requests", function="head", vulnerable_parameters=(0,),
              vulnerability_class=VulnerabilityClass.SSRF),
    TaintSink(module="requests", function="patch", vulnerable_parameters=(0,),
              vulnerability_class=VulnerabilityClass.SSRF),
    TaintSink(module="requests", function="request", vulnerable_parameters=(1,),
              vulnerability_class=VulnerabilityClass.SSRF),
    TaintSink(module="urllib.request", function="urlopen", vulnerable_parameters=(0,),
              vulnerability_class=VulnerabilityClass.SSRF),
    TaintSink(module="urllib.request", function="urlretrieve", vulnerable_parameters=(0,),
              vulnerability_class=VulnerabilityClass.SSRF),
    TaintSink(module="urllib2", function="urlopen", vulnerable_parameters=(0,),
              vulnerability_class=VulnerabilityClass.SSRF),
    TaintSink(module="httpx", function="get", vulnerable_parameters=(0,),
              vulnerability_class=VulnerabilityClass.SSRF),
    TaintSink(module="httpx", function="post", vulnerable_parameters=(0,),
              vulnerability_class=VulnerabilityClass.SSRF),
    TaintSink(module="httpx", function="put", vulnerable_parameters=(0,),
              vulnerability_class=VulnerabilityClass.SSRF),
    TaintSink(module="httpx", function="delete", vulnerable_parameters=(0,),
              vulnerability_class=VulnerabilityClass.SSRF),
    TaintSink(module="httpx", function="request", vulnerable_parameters=(1,),
              vulnerability_class=VulnerabilityClass.SSRF),
    TaintSink(module="aiohttp", function="ClientSession.get", vulnerable_parameters=(0,),
              vulnerability_class=VulnerabilityClass.SSRF),
    TaintSink(module="aiohttp", function="ClientSession.post", vulnerable_parameters=(0,),
              vulnerability_class=VulnerabilityClass.SSRF),
    TaintSink(module="aiohttp", function="ClientSession.request", vulnerable_parameters=(1,),
              vulnerability_class=VulnerabilityClass.SSRF),
)

DESERIALIZE_SINKS: tuple[TaintSink, ...] = (
    TaintSink(module="pickle", function="loads", vulnerable_parameters=(0,),
              vulnerability_class=VulnerabilityClass.DESERIALIZE),
    TaintSink(module="pickle", function="load", vulnerable_parameters=(0,),
              vulnerability_class=VulnerabilityClass.DESERIALIZE),
    TaintSink(module="cPickle", function="loads", vulnerable_parameters=(0,),
              vulnerability_class=VulnerabilityClass.DESERIALIZE),
    TaintSink(module="cPickle", function="load", vulnerable_parameters=(0,),
              vulnerability_class=VulnerabilityClass.DESERIALIZE),
    TaintSink(module="yaml", function="load", vulnerable_parameters=(0,),
              vulnerability_class=VulnerabilityClass.DESERIALIZE),
    TaintSink(module="yaml", function="unsafe_load", vulnerable_parameters=(0,),
              vulnerability_class=VulnerabilityClass.DESERIALIZE),
    TaintSink(module="yaml", function="full_load", vulnerable_parameters=(0,),
              vulnerability_class=VulnerabilityClass.DESERIALIZE),
    TaintSink(module="marshal", function="loads", vulnerable_parameters=(0,),
              vulnerability_class=VulnerabilityClass.DESERIALIZE),
    TaintSink(module="marshal", function="load", vulnerable_parameters=(0,),
              vulnerability_class=VulnerabilityClass.DESERIALIZE),
    TaintSink(module="shelve", function="open", vulnerable_parameters=(0,),
              vulnerability_class=VulnerabilityClass.DESERIALIZE),
    TaintSink(module="jsonpickle", function="decode", vulnerable_parameters=(0,),
              vulnerability_class=VulnerabilityClass.DESERIALIZE),
)

PATH_TRAVERSAL_SINKS: tuple[TaintSink, ...] = (
    TaintSink(module="builtins", function="open", vulnerable_parameters=(0,),
              vulnerability_class=VulnerabilityClass.PATH_TRAVERSAL),
    TaintSink(module="os", function="remove", vulnerable_parameters=(0,),
              vulnerability_class=VulnerabilityClass.PATH_TRAVERSAL),
    TaintSink(module="os", function="unlink", vulnerable_parameters=(0,),
              vulnerability_class=VulnerabilityClass.PATH_TRAVERSAL),
    TaintSink(module="os", function="rename", vulnerable_parameters=(0, 1),
              vulnerability_class=VulnerabilityClass.PATH_TRAVERSAL),
    TaintSink(module="os", function="rmdir", vulnerable_parameters=(0,),
              vulnerability_class=VulnerabilityClass.PATH_TRAVERSAL),
    TaintSink(module="os", function="mkdir", vulnerable_parameters=(0,),
              vulnerability_class=VulnerabilityClass.PATH_TRAVERSAL),
    TaintSink(module="os", function="makedirs", vulnerable_parameters=(0,),
              vulnerability_class=VulnerabilityClass.PATH_TRAVERSAL),
    TaintSink(module="os", function="listdir", vulnerable_parameters=(0,),
              vulnerability_class=VulnerabilityClass.PATH_TRAVERSAL),
    TaintSink(module="os", function="chmod", vulnerable_parameters=(0,),
              vulnerability_class=VulnerabilityClass.PATH_TRAVERSAL),
    TaintSink(module="os", function="chown", vulnerable_parameters=(0,),
              vulnerability_class=VulnerabilityClass.PATH_TRAVERSAL),
    TaintSink(module="os.path", function="exists", vulnerable_parameters=(0,),
              vulnerability_class=VulnerabilityClass.PATH_TRAVERSAL),
    TaintSink(module="shutil", function="copy", vulnerable_parameters=(0, 1),
              vulnerability_class=VulnerabilityClass.PATH_TRAVERSAL),
    TaintSink(module="shutil", function="copy2", vulnerable_parameters=(0, 1),
              vulnerability_class=VulnerabilityClass.PATH_TRAVERSAL),
    TaintSink(module="shutil", function="copyfile", vulnerable_parameters=(0, 1),
              vulnerability_class=VulnerabilityClass.PATH_TRAVERSAL),
    TaintSink(module="shutil", function="move", vulnerable_parameters=(0, 1),
              vulnerability_class=VulnerabilityClass.PATH_TRAVERSAL),
    TaintSink(module="shutil", function="rmtree", vulnerable_parameters=(0,),
              vulnerability_class=VulnerabilityClass.PATH_TRAVERSAL),
    TaintSink(module="pathlib", function="Path.read_text", vulnerable_parameters=(0,),
              vulnerability_class=VulnerabilityClass.PATH_TRAVERSAL),
    TaintSink(module="pathlib", function="Path.read_bytes", vulnerable_parameters=(0,),
              vulnerability_class=VulnerabilityClass.PATH_TRAVERSAL),
    TaintSink(module="pathlib", function="Path.write_text", vulnerable_parameters=(0,),
              vulnerability_class=VulnerabilityClass.PATH_TRAVERSAL),
    TaintSink(module="pathlib", function="Path.write_bytes", vulnerable_parameters=(0,),
              vulnerability_class=VulnerabilityClass.PATH_TRAVERSAL),
    TaintSink(module="pathlib", function="Path.unlink", vulnerable_parameters=(0,),
              vulnerability_class=VulnerabilityClass.PATH_TRAVERSAL),
    TaintSink(module="pathlib", function="Path.rmdir", vulnerable_parameters=(0,),
              vulnerability_class=VulnerabilityClass.PATH_TRAVERSAL),
)

LDAP_INJECTION_SINKS: tuple[TaintSink, ...] = (
    TaintSink(module="ldap", function="search_s", vulnerable_parameters=(2,),
              vulnerability_class=VulnerabilityClass.LDAP_INJECTION,
              description="LDAP search filter"),
    TaintSink(module="ldap", function="search_st", vulnerable_parameters=(2,),
              vulnerability_class=VulnerabilityClass.LDAP_INJECTION),
    TaintSink(module="ldap3", function="Connection.search", vulnerable_parameters=(1,),
              vulnerability_class=VulnerabilityClass.LDAP_INJECTION),
)

HEADER_INJECTION_SINKS: tuple[TaintSink, ...] = (
    TaintSink(module="http.client", function="HTTPConnection.putheader", vulnerable_parameters=(0, 1),
              vulnerability_class=VulnerabilityClass.HEADER_INJECTION),
    TaintSink(module="flask", function="Response", vulnerable_parameters=(),
              vulnerability_class=VulnerabilityClass.HEADER_INJECTION,
              description="HTTP Response headers"),
    TaintSink(module="django.http", function="HttpResponse", vulnerable_parameters=(),
              vulnerability_class=VulnerabilityClass.HEADER_INJECTION),
)

XXEIS_SINKS: tuple[TaintSink, ...] = (
    TaintSink(module="xml.etree.ElementTree", function="parse", vulnerable_parameters=(0,),
              vulnerability_class=VulnerabilityClass.XXE,
              description="XML External Entity injection"),
    TaintSink(module="xml.etree.ElementTree", function="fromstring", vulnerable_parameters=(0,),
              vulnerability_class=VulnerabilityClass.XXE),
    TaintSink(module="xml.dom.minidom", function="parse", vulnerable_parameters=(0,),
              vulnerability_class=VulnerabilityClass.XXE),
    TaintSink(module="xml.dom.minidom", function="parseString", vulnerable_parameters=(0,),
              vulnerability_class=VulnerabilityClass.XXE),
    TaintSink(module="lxml.etree", function="parse", vulnerable_parameters=(0,),
              vulnerability_class=VulnerabilityClass.XXE),
    TaintSink(module="lxml.etree", function="fromstring", vulnerable_parameters=(0,),
              vulnerability_class=VulnerabilityClass.XXE),
)


class SinkRegistry:
    """Registry for taint sinks with lookup capabilities."""

    def __init__(self) -> None:
        self._sinks: dict[str, TaintSink] = {}
        self._by_vuln_class: dict[VulnerabilityClass, list[TaintSink]] = {}
        self._by_module: dict[str, list[TaintSink]] = {}

    def register(self, sink: TaintSink) -> None:
        """Register a single taint sink."""
        self._sinks[sink.qualified_name] = sink
        self._by_vuln_class.setdefault(sink.vulnerability_class, []).append(sink)
        self._by_module.setdefault(sink.module, []).append(sink)

    def register_all(self, sinks: tuple[TaintSink, ...]) -> None:
        """Register multiple taint sinks."""
        for sink in sinks:
            self.register(sink)

    def get(self, qualified_name: str) -> Optional[TaintSink]:
        """Get a sink by its qualified name (module.function)."""
        return self._sinks.get(qualified_name)

    def get_by_vuln_class(self, vuln_class: VulnerabilityClass) -> list[TaintSink]:
        """Get all sinks for a specific vulnerability class."""
        return self._by_vuln_class.get(vuln_class, [])

    def get_by_module(self, module: str) -> list[TaintSink]:
        """Get all sinks for a specific module."""
        return self._by_module.get(module, [])

    def match(self, module: str, function: str) -> Optional[TaintSink]:
        """Match a sink by module and function name."""
        return self._sinks.get(f"{module}.{function}")

    def all_sinks(self) -> list[TaintSink]:
        """Get all registered sinks."""
        return list(self._sinks.values())

    def count(self) -> int:
        """Get the total number of registered sinks."""
        return len(self._sinks)

    def count_by_vuln_class(self) -> dict[VulnerabilityClass, int]:
        """Get counts of sinks grouped by vulnerability class."""
        return {vc: len(sinks) for vc, sinks in self._by_vuln_class.items()}


def get_all_sinks() -> tuple[TaintSink, ...]:
    """Get all defined taint sinks."""
    return (
        *SQL_SINKS,
        *RCE_SINKS,
        *SSTI_SINKS,
        *XSS_SINKS,
        *SSRF_SINKS,
        *DESERIALIZE_SINKS,
        *PATH_TRAVERSAL_SINKS,
        *LDAP_INJECTION_SINKS,
        *HEADER_INJECTION_SINKS,
        *XXEIS_SINKS,
    )


def create_default_registry() -> SinkRegistry:
    """Create a registry with all default sinks registered."""
    registry = SinkRegistry()
    registry.register_all(get_all_sinks())
    return registry