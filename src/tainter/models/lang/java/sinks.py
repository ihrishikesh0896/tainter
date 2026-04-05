"""
Java taint sink definitions.

Sinks are dangerous operations where tainted data can cause harm.
Covers JDBC, command execution, file I/O, XML parsing, and more.
"""

from tainter.core.types import TaintSink, VulnerabilityClass
from tainter.models.registry import SinkRegistry


# --- SQL Injection ---

JAVA_SQL_SINKS: tuple[TaintSink, ...] = (
    TaintSink(
        module="java.sql", function="Statement.executeQuery",
        vulnerable_parameters=(0,),
        vulnerability_class=VulnerabilityClass.SQLI,
        description="JDBC Statement.executeQuery with string query",
    ),
    TaintSink(
        module="java.sql", function="Statement.executeUpdate",
        vulnerable_parameters=(0,),
        vulnerability_class=VulnerabilityClass.SQLI,
        description="JDBC Statement.executeUpdate with string query",
    ),
    TaintSink(
        module="java.sql", function="Statement.execute",
        vulnerable_parameters=(0,),
        vulnerability_class=VulnerabilityClass.SQLI,
        description="JDBC Statement.execute with string query",
    ),
    TaintSink(
        module="java.sql", function="Connection.prepareStatement",
        vulnerable_parameters=(0,),
        vulnerability_class=VulnerabilityClass.SQLI,
        description="PreparedStatement with tainted query string",
    ),
    TaintSink(
        module="java.sql", function="Connection.nativeSQL",
        vulnerable_parameters=(0,),
        vulnerability_class=VulnerabilityClass.SQLI,
        description="JDBC nativeSQL with tainted input",
    ),
)

# --- Remote Code Execution ---

JAVA_RCE_SINKS: tuple[TaintSink, ...] = (
    TaintSink(
        module="java.lang", function="Runtime.exec",
        vulnerable_parameters=(0,),
        vulnerability_class=VulnerabilityClass.RCE,
        description="Runtime.exec command execution",
    ),
    TaintSink(
        module="java.lang", function="ProcessBuilder",
        vulnerable_parameters=(0,),
        vulnerability_class=VulnerabilityClass.RCE,
        description="ProcessBuilder command execution",
    ),
    TaintSink(
        module="javax.script", function="ScriptEngine.eval",
        vulnerable_parameters=(0,),
        vulnerability_class=VulnerabilityClass.RCE,
        description="ScriptEngine.eval code execution",
    ),
)

# --- Server-Side Request Forgery ---

JAVA_SSRF_SINKS: tuple[TaintSink, ...] = (
    TaintSink(
        module="java.net", function="URL",
        vulnerable_parameters=(0,),
        vulnerability_class=VulnerabilityClass.SSRF,
        description="java.net.URL with tainted URL string",
    ),
    TaintSink(
        module="java.net", function="URI",
        vulnerable_parameters=(0,),
        vulnerability_class=VulnerabilityClass.SSRF,
        description="java.net.URI with tainted URI string",
    ),
    TaintSink(
        module="java.net.http", function="HttpClient.send",
        vulnerable_parameters=(0,),
        vulnerability_class=VulnerabilityClass.SSRF,
        description="HttpClient request with tainted URL",
    ),
    TaintSink(
        module="org.apache.http.client", function="HttpClient.execute",
        vulnerable_parameters=(0,),
        vulnerability_class=VulnerabilityClass.SSRF,
        description="Apache HttpClient with tainted URL",
    ),
)

# --- Path Traversal ---

JAVA_PATH_TRAVERSAL_SINKS: tuple[TaintSink, ...] = (
    TaintSink(
        module="java.io", function="File",
        vulnerable_parameters=(0,),
        vulnerability_class=VulnerabilityClass.PATH_TRAVERSAL,
        description="java.io.File with tainted path",
    ),
    TaintSink(
        module="java.io", function="FileInputStream",
        vulnerable_parameters=(0,),
        vulnerability_class=VulnerabilityClass.PATH_TRAVERSAL,
        description="FileInputStream with tainted path",
    ),
    TaintSink(
        module="java.io", function="FileOutputStream",
        vulnerable_parameters=(0,),
        vulnerability_class=VulnerabilityClass.PATH_TRAVERSAL,
        description="FileOutputStream with tainted path",
    ),
    TaintSink(
        module="java.io", function="FileReader",
        vulnerable_parameters=(0,),
        vulnerability_class=VulnerabilityClass.PATH_TRAVERSAL,
        description="FileReader with tainted path",
    ),
    TaintSink(
        module="java.io", function="FileWriter",
        vulnerable_parameters=(0,),
        vulnerability_class=VulnerabilityClass.PATH_TRAVERSAL,
        description="FileWriter with tainted path",
    ),
    TaintSink(
        module="java.nio.file", function="Paths.get",
        vulnerable_parameters=(0,),
        vulnerability_class=VulnerabilityClass.PATH_TRAVERSAL,
        description="Paths.get with tainted path string",
    ),
    TaintSink(
        module="java.nio.file", function="Files.readAllBytes",
        vulnerable_parameters=(0,),
        vulnerability_class=VulnerabilityClass.PATH_TRAVERSAL,
        description="Files.readAllBytes with tainted path",
    ),
)

# --- Cross-Site Scripting ---

JAVA_XSS_SINKS: tuple[TaintSink, ...] = (
    TaintSink(
        module="javax.servlet.http", function="HttpServletResponse.getWriter",
        vulnerable_parameters=(),
        vulnerability_class=VulnerabilityClass.XSS,
        description="Writing tainted data to HTTP response",
    ),
    TaintSink(
        module="java.io", function="PrintWriter.print",
        vulnerable_parameters=(0,),
        vulnerability_class=VulnerabilityClass.XSS,
        description="PrintWriter.print with tainted data",
    ),
    TaintSink(
        module="java.io", function="PrintWriter.println",
        vulnerable_parameters=(0,),
        vulnerability_class=VulnerabilityClass.XSS,
        description="PrintWriter.println with tainted data",
    ),
    TaintSink(
        module="java.io", function="PrintWriter.write",
        vulnerable_parameters=(0,),
        vulnerability_class=VulnerabilityClass.XSS,
        description="PrintWriter.write with tainted data",
    ),
)

# --- Unsafe Deserialization ---

JAVA_DESERIALIZE_SINKS: tuple[TaintSink, ...] = (
    TaintSink(
        module="java.io", function="ObjectInputStream.readObject",
        vulnerable_parameters=(),
        vulnerability_class=VulnerabilityClass.DESERIALIZE,
        description="ObjectInputStream.readObject from tainted stream",
    ),
    TaintSink(
        module="com.fasterxml.jackson.databind", function="ObjectMapper.readValue",
        vulnerable_parameters=(0,),
        vulnerability_class=VulnerabilityClass.DESERIALIZE,
        description="Jackson ObjectMapper.readValue with tainted input",
    ),
    TaintSink(
        module="com.google.gson", function="Gson.fromJson",
        vulnerable_parameters=(0,),
        vulnerability_class=VulnerabilityClass.DESERIALIZE,
        description="Gson.fromJson with tainted input",
    ),
)

# --- XML External Entity (XXE) ---

JAVA_XXE_SINKS: tuple[TaintSink, ...] = (
    TaintSink(
        module="javax.xml.parsers", function="DocumentBuilder.parse",
        vulnerable_parameters=(0,),
        vulnerability_class=VulnerabilityClass.XXE,
        description="DocumentBuilder.parse with tainted input",
    ),
    TaintSink(
        module="javax.xml.parsers", function="SAXParser.parse",
        vulnerable_parameters=(0,),
        vulnerability_class=VulnerabilityClass.XXE,
        description="SAXParser.parse with tainted input",
    ),
    TaintSink(
        module="javax.xml.transform", function="TransformerFactory.newTransformer",
        vulnerable_parameters=(0,),
        vulnerability_class=VulnerabilityClass.XXE,
        description="TransformerFactory with tainted XSLT",
    ),
)

# --- LDAP Injection ---

JAVA_LDAP_SINKS: tuple[TaintSink, ...] = (
    TaintSink(
        module="javax.naming.directory", function="DirContext.search",
        vulnerable_parameters=(1,),
        vulnerability_class=VulnerabilityClass.LDAP_INJECTION,
        description="LDAP search with tainted filter",
    ),
)

# --- SSTI ---

JAVA_SSTI_SINKS: tuple[TaintSink, ...] = (
    TaintSink(
        module="freemarker.template", function="Template",
        vulnerable_parameters=(0,),
        vulnerability_class=VulnerabilityClass.SSTI,
        description="FreeMarker template from tainted input",
    ),
    TaintSink(
        module="org.apache.velocity", function="Velocity.evaluate",
        vulnerable_parameters=(2,),
        vulnerability_class=VulnerabilityClass.SSTI,
        description="Velocity template evaluation with tainted input",
    ),
)


def get_all_java_sinks() -> tuple[TaintSink, ...]:
    """Return all Java taint sinks."""
    return (
        JAVA_SQL_SINKS + JAVA_RCE_SINKS + JAVA_SSRF_SINKS +
        JAVA_PATH_TRAVERSAL_SINKS + JAVA_XSS_SINKS + JAVA_DESERIALIZE_SINKS +
        JAVA_XXE_SINKS + JAVA_LDAP_SINKS + JAVA_SSTI_SINKS
    )


def create_java_sink_registry() -> SinkRegistry:
    """Create a registry with all Java sinks."""
    registry = SinkRegistry()
    registry.register_all(get_all_java_sinks())
    return registry
