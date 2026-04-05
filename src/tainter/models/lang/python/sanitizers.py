"""
Sanitizer definitions.

Sanitizers are functions that clear or neutralize taint for specific vulnerability classes.
"""

from tainter.core.types import Sanitizer, VulnerabilityClass
from tainter.models.registry import SanitizerRegistry


SQL_SANITIZERS: tuple[Sanitizer, ...] = (
    Sanitizer(module="sqlite3", function="Cursor.execute",
              clears=(VulnerabilityClass.SQLI,),
              description="Parameterized query clears SQL injection"),
    Sanitizer(module="psycopg2.sql", function="SQL",
              clears=(VulnerabilityClass.SQLI,),
              description="psycopg2 SQL composition"),
    Sanitizer(module="psycopg2.sql", function="Identifier",
              clears=(VulnerabilityClass.SQLI,),
              description="psycopg2 identifier escaping"),
    Sanitizer(module="psycopg2.sql", function="Literal",
              clears=(VulnerabilityClass.SQLI,),
              description="psycopg2 literal escaping"),
    Sanitizer(module="sqlalchemy", function="bindparam",
              clears=(VulnerabilityClass.SQLI,),
              description="SQLAlchemy bound parameter"),
    # Django ORM safe query methods (parameterized internally)
    Sanitizer(module="django.db.models", function="filter",
              clears=(VulnerabilityClass.SQLI,),
              description="Django ORM filter() uses parameterized queries"),
    Sanitizer(module="django.db.models", function="exclude",
              clears=(VulnerabilityClass.SQLI,),
              description="Django ORM exclude() uses parameterized queries"),
    Sanitizer(module="django.db.models", function="get",
              clears=(VulnerabilityClass.SQLI,),
              description="Django ORM get() uses parameterized queries"),
)

GENERAL_SANITIZERS: tuple[Sanitizer, ...] = (
    # Type coercion sanitizers
    Sanitizer(module="builtins", function="int",
              clears_all=True,
              description="Integer conversion clears string-based attacks"),
    Sanitizer(module="builtins", function="float",
              clears_all=True,
              description="Float conversion clears string-based attacks"),
    Sanitizer(module="builtins", function="bool",
              clears_all=True,
              description="Boolean conversion clears string-based attacks"),
    # HTML escaping
    Sanitizer(module="html", function="escape",
              clears=(VulnerabilityClass.XSS, VulnerabilityClass.SSTI),
              description="HTML escaping"),
    Sanitizer(module="markupsafe", function="escape",
              clears=(VulnerabilityClass.XSS, VulnerabilityClass.SSTI),
              description="MarkupSafe HTML escaping"),
    # Django HTML escaping
    Sanitizer(module="django.utils.html", function="escape",
              clears=(VulnerabilityClass.XSS, VulnerabilityClass.SSTI),
              description="Django HTML escaping"),
    Sanitizer(module="django.utils.html", function="conditional_escape",
              clears=(VulnerabilityClass.XSS, VulnerabilityClass.SSTI),
              description="Django conditional HTML escaping"),
    Sanitizer(module="django.utils.html", function="strip_tags",
              clears=(VulnerabilityClass.XSS,),
              description="Django strip HTML tags"),
    # Bleach HTML sanitizer
    Sanitizer(module="bleach", function="clean",
              clears=(VulnerabilityClass.XSS,),
              description="Bleach HTML sanitizer"),
    Sanitizer(module="bleach", function="linkify",
              clears=(VulnerabilityClass.XSS,),
              description="Bleach linkify sanitizes URLs"),
    # XML escaping
    Sanitizer(module="xml.sax.saxutils", function="escape",
              clears=(VulnerabilityClass.XSS, VulnerabilityClass.XXE),
              description="XML/HTML escaping via SAX utils"),
    Sanitizer(module="xml.sax.saxutils", function="quoteattr",
              clears=(VulnerabilityClass.XSS, VulnerabilityClass.XXE),
              description="XML attribute value quoting"),
    # LDAP / XPath escaping
    Sanitizer(module="re", function="escape",
              clears=(VulnerabilityClass.LDAP_INJECTION, VulnerabilityClass.XPATH),
              description="Regex/special char escaping for LDAP and XPath filters"),
    Sanitizer(module="ldap", function="filter.escape_filter_chars",
              clears=(VulnerabilityClass.LDAP_INJECTION,),
              description="LDAP filter character escaping"),
    Sanitizer(module="ldap3.utils.conv", function="escape_filter_chars",
              clears=(VulnerabilityClass.LDAP_INJECTION,),
              description="ldap3 filter character escaping"),
    # Path sanitizers
    Sanitizer(module="os.path", function="basename",
              clears=(VulnerabilityClass.PATH_TRAVERSAL,),
              description="Extracts filename, removes directory traversal"),
    Sanitizer(module="werkzeug.utils", function="secure_filename",
              clears=(VulnerabilityClass.PATH_TRAVERSAL,),
              description="Werkzeug secure filename"),
    # URL encoding
    Sanitizer(module="urllib.parse", function="quote",
              clears=(VulnerabilityClass.SSRF,),
              description="URL percent-encoding"),
    Sanitizer(module="urllib.parse", function="quote_plus",
              clears=(VulnerabilityClass.SSRF,),
              description="URL encoding with plus for spaces"),
    Sanitizer(module="urllib.parse", function="urlencode",
              clears=(VulnerabilityClass.SSRF,),
              description="URL query-string encoding"),
    # Shell escaping
    Sanitizer(module="shlex", function="quote",
              clears=(VulnerabilityClass.RCE,),
              description="Shell argument escaping"),
    Sanitizer(module="pipes", function="quote",
              clears=(VulnerabilityClass.RCE,),
              description="Shell argument escaping (deprecated)"),
)



def get_all_sanitizers() -> tuple[Sanitizer, ...]:
    return (*SQL_SANITIZERS, *GENERAL_SANITIZERS)


def create_default_registry() -> SanitizerRegistry:
    registry = SanitizerRegistry()
    registry.register_all(get_all_sanitizers())
    return registry
