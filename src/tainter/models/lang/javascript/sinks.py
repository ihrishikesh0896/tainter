# src/tainter/models/lang/javascript/sinks.py
"""JavaScript taint sink definitions."""

from tainter.core.types import TaintSink, VulnerabilityClass
from tainter.models.registry import SinkRegistry

# --- SQL Injection ---

JS_SQL_SINKS: tuple[TaintSink, ...] = (
    TaintSink(
        module="mysql", function="query",
        vulnerable_parameters=(0,),
        vulnerability_class=VulnerabilityClass.SQLI,
        description="MySQL query() with tainted SQL string",
    ),
    TaintSink(
        module="mysql2", function="query",
        vulnerable_parameters=(0,),
        vulnerability_class=VulnerabilityClass.SQLI,
        description="mysql2 query() with tainted SQL string",
    ),
    TaintSink(
        module="pg", function="query",
        vulnerable_parameters=(0,),
        vulnerability_class=VulnerabilityClass.SQLI,
        description="pg (PostgreSQL) query() with tainted SQL string",
    ),
    TaintSink(
        module="sequelize", function="query",
        vulnerable_parameters=(0,),
        vulnerability_class=VulnerabilityClass.SQLI,
        description="Sequelize raw query() with tainted SQL string",
    ),
    TaintSink(
        module="knex", function="raw",
        vulnerable_parameters=(0,),
        vulnerability_class=VulnerabilityClass.SQLI,
        description="Knex raw() with tainted SQL string",
    ),
)

# --- Remote Code Execution ---

JS_RCE_SINKS: tuple[TaintSink, ...] = (
    TaintSink(
        module="child_process", function="exec",
        vulnerable_parameters=(0,),
        vulnerability_class=VulnerabilityClass.RCE,
        description="child_process.exec() with tainted command",
    ),
    TaintSink(
        module="child_process", function="execSync",
        vulnerable_parameters=(0,),
        vulnerability_class=VulnerabilityClass.RCE,
        description="child_process.execSync() with tainted command",
    ),
    TaintSink(
        module="child_process", function="spawn",
        vulnerable_parameters=(0,),
        vulnerability_class=VulnerabilityClass.RCE,
        description="child_process.spawn() with tainted command",
    ),
    TaintSink(
        module="child_process", function="spawnSync",
        vulnerable_parameters=(0,),
        vulnerability_class=VulnerabilityClass.RCE,
        description="child_process.spawnSync() with tainted command",
    ),
    TaintSink(
        module="builtins", function="eval",
        vulnerable_parameters=(0,),
        vulnerability_class=VulnerabilityClass.RCE,
        description="eval() with tainted code string",
    ),
    TaintSink(
        module="vm", function="runInNewContext",
        vulnerable_parameters=(0,),
        vulnerability_class=VulnerabilityClass.RCE,
        description="vm.runInNewContext() with tainted code",
    ),
)

# --- Cross-Site Scripting ---

JS_XSS_SINKS: tuple[TaintSink, ...] = (
    TaintSink(
        module="dom", function="innerHTML",
        vulnerable_parameters=(0,),
        vulnerability_class=VulnerabilityClass.XSS,
        description="innerHTML assignment with tainted HTML",
    ),
    TaintSink(
        module="dom", function="outerHTML",
        vulnerable_parameters=(0,),
        vulnerability_class=VulnerabilityClass.XSS,
        description="outerHTML assignment with tainted HTML",
    ),
    TaintSink(
        module="react", function="dangerouslySetInnerHTML",
        vulnerable_parameters=(0,),
        vulnerability_class=VulnerabilityClass.XSS,
        description="React dangerouslySetInnerHTML with tainted HTML",
    ),
    TaintSink(
        module="dom", function="document.write",
        vulnerable_parameters=(0,),
        vulnerability_class=VulnerabilityClass.XSS,
        description="document.write() with tainted content",
    ),
)

# --- SSRF ---

JS_SSRF_SINKS: tuple[TaintSink, ...] = (
    TaintSink(
        module="node-fetch", function="fetch",
        vulnerable_parameters=(0,),
        vulnerability_class=VulnerabilityClass.SSRF,
        description="fetch() with tainted URL",
    ),
    TaintSink(
        module="axios", function="get",
        vulnerable_parameters=(0,),
        vulnerability_class=VulnerabilityClass.SSRF,
        description="axios.get() with tainted URL",
    ),
    TaintSink(
        module="axios", function="post",
        vulnerable_parameters=(0,),
        vulnerability_class=VulnerabilityClass.SSRF,
        description="axios.post() with tainted URL",
    ),
    TaintSink(
        module="axios", function="request",
        vulnerable_parameters=(0,),
        vulnerability_class=VulnerabilityClass.SSRF,
        description="axios.request() with tainted URL",
    ),
    TaintSink(
        module="http", function="request",
        vulnerable_parameters=(0,),
        vulnerability_class=VulnerabilityClass.SSRF,
        description="http.request() with tainted options",
    ),
    TaintSink(
        module="https", function="request",
        vulnerable_parameters=(0,),
        vulnerability_class=VulnerabilityClass.SSRF,
        description="https.request() with tainted options",
    ),
)

# --- Path Traversal ---

JS_PATH_TRAVERSAL_SINKS: tuple[TaintSink, ...] = (
    TaintSink(
        module="fs", function="readFile",
        vulnerable_parameters=(0,),
        vulnerability_class=VulnerabilityClass.PATH_TRAVERSAL,
        description="fs.readFile() with tainted path",
    ),
    TaintSink(
        module="fs", function="readFileSync",
        vulnerable_parameters=(0,),
        vulnerability_class=VulnerabilityClass.PATH_TRAVERSAL,
        description="fs.readFileSync() with tainted path",
    ),
    TaintSink(
        module="fs", function="writeFile",
        vulnerable_parameters=(0,),
        vulnerability_class=VulnerabilityClass.PATH_TRAVERSAL,
        description="fs.writeFile() with tainted path",
    ),
    TaintSink(
        module="fs", function="writeFileSync",
        vulnerable_parameters=(0,),
        vulnerability_class=VulnerabilityClass.PATH_TRAVERSAL,
        description="fs.writeFileSync() with tainted path",
    ),
    TaintSink(
        module="fs", function="createReadStream",
        vulnerable_parameters=(0,),
        vulnerability_class=VulnerabilityClass.PATH_TRAVERSAL,
        description="fs.createReadStream() with tainted path",
    ),
    TaintSink(
        module="path", function="join",
        vulnerable_parameters=(0,),
        vulnerability_class=VulnerabilityClass.PATH_TRAVERSAL,
        description="path.join() with tainted path component",
    ),
)


def get_all_javascript_sinks() -> tuple[TaintSink, ...]:
    return (
        JS_SQL_SINKS + JS_RCE_SINKS + JS_XSS_SINKS
        + JS_SSRF_SINKS + JS_PATH_TRAVERSAL_SINKS
    )


def create_javascript_sink_registry() -> SinkRegistry:
    registry = SinkRegistry()
    registry.register_all(get_all_javascript_sinks())
    return registry
