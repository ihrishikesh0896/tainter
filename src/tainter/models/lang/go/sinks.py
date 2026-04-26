# src/tainter/models/lang/go/sinks.py
"""Go taint sink definitions."""

from tainter.core.types import TaintSink, VulnerabilityClass
from tainter.models.registry import SinkRegistry

# --- SQL Injection ---

GO_SQL_SINKS: tuple[TaintSink, ...] = (
    TaintSink(
        module="database/sql", function="Query",
        vulnerable_parameters=(0,),
        vulnerability_class=VulnerabilityClass.SQLI,
        description="database/sql Query() with tainted SQL string",
    ),
    TaintSink(
        module="database/sql", function="Exec",
        vulnerable_parameters=(0,),
        vulnerability_class=VulnerabilityClass.SQLI,
        description="database/sql Exec() with tainted SQL string",
    ),
    TaintSink(
        module="database/sql", function="QueryRow",
        vulnerable_parameters=(0,),
        vulnerability_class=VulnerabilityClass.SQLI,
        description="database/sql QueryRow() with tainted SQL string",
    ),
)

# --- Remote Code Execution ---

GO_RCE_SINKS: tuple[TaintSink, ...] = (
    TaintSink(
        module="os/exec", function="Command",
        vulnerable_parameters=(0,),
        vulnerability_class=VulnerabilityClass.RCE,
        description="exec.Command() with tainted command string",
    ),
)

# --- SSRF ---

GO_SSRF_SINKS: tuple[TaintSink, ...] = (
    TaintSink(
        module="net/http", function="Get",
        vulnerable_parameters=(0,),
        vulnerability_class=VulnerabilityClass.SSRF,
        description="http.Get() with tainted URL",
    ),
    TaintSink(
        module="net/http", function="Post",
        vulnerable_parameters=(0,),
        vulnerability_class=VulnerabilityClass.SSRF,
        description="http.Post() with tainted URL",
    ),
    TaintSink(
        module="net/http", function="NewRequest",
        vulnerable_parameters=(0,),
        vulnerability_class=VulnerabilityClass.SSRF,
        description="http.NewRequest() with tainted URL",
    ),
)

# --- Path Traversal ---

GO_PATH_TRAVERSAL_SINKS: tuple[TaintSink, ...] = (
    TaintSink(
        module="os", function="Open",
        vulnerable_parameters=(0,),
        vulnerability_class=VulnerabilityClass.PATH_TRAVERSAL,
        description="os.Open() with tainted path",
    ),
    TaintSink(
        module="os", function="ReadFile",
        vulnerable_parameters=(0,),
        vulnerability_class=VulnerabilityClass.PATH_TRAVERSAL,
        description="os.ReadFile() with tainted path",
    ),
    TaintSink(
        module="io/ioutil", function="ReadFile",
        vulnerable_parameters=(0,),
        vulnerability_class=VulnerabilityClass.PATH_TRAVERSAL,
        description="ioutil.ReadFile() with tainted path",
    ),
)


def get_all_go_sinks() -> tuple[TaintSink, ...]:
    return (
        GO_SQL_SINKS + GO_RCE_SINKS + GO_SSRF_SINKS
        + GO_PATH_TRAVERSAL_SINKS
    )


def create_go_sink_registry() -> SinkRegistry:
    registry = SinkRegistry()
    registry.register_all(get_all_go_sinks())
    return registry
