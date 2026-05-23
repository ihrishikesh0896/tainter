"""
Python sanitizer definitions.

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
)

GENERAL_SANITIZERS: tuple[Sanitizer, ...] = (
    Sanitizer(module="builtins", function="int",
              clears_all=True,
              description="Integer conversion clears string-based attacks"),
    Sanitizer(module="builtins", function="float",
              clears_all=True,
              description="Float conversion clears string-based attacks"),
    Sanitizer(module="builtins", function="bool",
              clears_all=True,
              description="Boolean conversion clears string-based attacks"),
    Sanitizer(module="html", function="escape",
              clears=(VulnerabilityClass.XSS, VulnerabilityClass.SSTI),
              description="HTML escaping"),
    Sanitizer(module="markupsafe", function="escape",
              clears=(VulnerabilityClass.XSS, VulnerabilityClass.SSTI),
              description="MarkupSafe HTML escaping"),
    Sanitizer(module="os.path", function="basename",
              clears=(VulnerabilityClass.PATH_TRAVERSAL,),
              description="Extracts filename, removes directory traversal"),
    Sanitizer(module="werkzeug.utils", function="secure_filename",
              clears=(VulnerabilityClass.PATH_TRAVERSAL,),
              description="Werkzeug secure filename"),
    Sanitizer(module="urllib.parse", function="quote",
              clears=(VulnerabilityClass.SSRF,),
              description="URL encoding"),
    Sanitizer(module="urllib.parse", function="quote_plus",
              clears=(VulnerabilityClass.SSRF,),
              description="URL encoding with plus for spaces"),
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
