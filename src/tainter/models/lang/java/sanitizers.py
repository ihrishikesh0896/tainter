"""
Java sanitizer definitions.

Sanitizers are functions or patterns that make tainted data safe.
Covers prepared statements, encoding libraries, and type coercion.
"""

from tainter.core.types import Sanitizer, VulnerabilityClass
from tainter.models.registry import SanitizerRegistry


# --- SQL Sanitizers (Parameterized Queries) ---

JAVA_SQL_SANITIZERS: tuple[Sanitizer, ...] = (
    Sanitizer(
        module="java.sql", function="PreparedStatement.setString",
        clears=(VulnerabilityClass.SQLI,),
        description="PreparedStatement parameterized query (string)",
    ),
    Sanitizer(
        module="java.sql", function="PreparedStatement.setInt",
        clears=(VulnerabilityClass.SQLI,),
        description="PreparedStatement parameterized query (int)",
    ),
    Sanitizer(
        module="java.sql", function="PreparedStatement.setLong",
        clears=(VulnerabilityClass.SQLI,),
        description="PreparedStatement parameterized query (long)",
    ),
    Sanitizer(
        module="java.sql", function="PreparedStatement.setObject",
        clears=(VulnerabilityClass.SQLI,),
        description="PreparedStatement parameterized query (object)",
    ),
)

# --- XSS Sanitizers ---

JAVA_XSS_SANITIZERS: tuple[Sanitizer, ...] = (
    Sanitizer(
        module="org.owasp.encoder", function="Encode.forHtml",
        clears=(VulnerabilityClass.XSS,),
        description="OWASP Encoder HTML encoding",
    ),
    Sanitizer(
        module="org.owasp.encoder", function="Encode.forJavaScript",
        clears=(VulnerabilityClass.XSS,),
        description="OWASP Encoder JavaScript encoding",
    ),
    Sanitizer(
        module="org.owasp.encoder", function="Encode.forCssString",
        clears=(VulnerabilityClass.XSS,),
        description="OWASP Encoder CSS encoding",
    ),
    Sanitizer(
        module="org.owasp.esapi", function="ESAPI.encoder",
        clears=(VulnerabilityClass.XSS,),
        description="ESAPI encoder",
    ),
    Sanitizer(
        module="org.apache.commons.text", function="StringEscapeUtils.escapeHtml4",
        clears=(VulnerabilityClass.XSS,),
        description="Apache Commons HTML escaping",
    ),
    Sanitizer(
        module="org.apache.commons.lang3", function="StringEscapeUtils.escapeHtml4",
        clears=(VulnerabilityClass.XSS,),
        description="Apache Commons Lang HTML escaping",
    ),
    Sanitizer(
        module="org.springframework.web.util", function="HtmlUtils.htmlEscape",
        clears=(VulnerabilityClass.XSS,),
        description="Spring HtmlUtils HTML escaping",
    ),
)

# --- Path Traversal Sanitizers ---

JAVA_PATH_SANITIZERS: tuple[Sanitizer, ...] = (
    Sanitizer(
        module="java.nio.file", function="Path.normalize",
        clears=(VulnerabilityClass.PATH_TRAVERSAL,),
        description="Path normalization",
    ),
    Sanitizer(
        module="java.io", function="File.getCanonicalPath",
        clears=(VulnerabilityClass.PATH_TRAVERSAL,),
        description="Canonical path resolution",
    ),
)

# --- General Sanitizers (Type Coercion) ---

JAVA_GENERAL_SANITIZERS: tuple[Sanitizer, ...] = (
    Sanitizer(
        module="java.lang", function="Integer.parseInt",
        clears_all=True,
        description="Integer parsing clears string-based attacks",
    ),
    Sanitizer(
        module="java.lang", function="Integer.valueOf",
        clears_all=True,
        description="Integer.valueOf clears string-based attacks",
    ),
    Sanitizer(
        module="java.lang", function="Long.parseLong",
        clears_all=True,
        description="Long parsing clears string-based attacks",
    ),
    Sanitizer(
        module="java.lang", function="Double.parseDouble",
        clears_all=True,
        description="Double parsing clears string-based attacks",
    ),
    Sanitizer(
        module="java.lang", function="Boolean.parseBoolean",
        clears_all=True,
        description="Boolean parsing clears string-based attacks",
    ),
    Sanitizer(
        module="java.util.regex", function="Pattern.matches",
        clears_all=True,
        description="Regex validation (conservative: clears all if matched)",
    ),
)


def get_all_java_sanitizers() -> tuple[Sanitizer, ...]:
    """Return all Java sanitizers."""
    return (
        JAVA_SQL_SANITIZERS + JAVA_XSS_SANITIZERS +
        JAVA_PATH_SANITIZERS + JAVA_GENERAL_SANITIZERS
    )


def create_java_sanitizer_registry() -> SanitizerRegistry:
    """Create a registry with all Java sanitizers."""
    registry = SanitizerRegistry()
    registry.register_all(get_all_java_sanitizers())
    return registry
