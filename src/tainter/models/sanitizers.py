"""
Sanitizer definitions.

Sanitizers are functions that clear or neutralize taint for specific vulnerability classes.
"""

from typing import Optional
from tainter.core.types import Sanitizer, VulnerabilityClass


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
              description="URL encoding"),
    Sanitizer(module="urllib.parse", function="quote_plus",
              clears=(VulnerabilityClass.SSRF,),
              description="URL encoding with plus for spaces"),
    # Shell escaping
    Sanitizer(module="shlex", function="quote",
              clears=(VulnerabilityClass.RCE,),
              description="Shell argument escaping"),
    Sanitizer(module="pipes", function="quote",
              clears=(VulnerabilityClass.RCE,),
              description="Shell argument escaping (deprecated)"),
)


class SanitizerRegistry:
    """Registry for sanitizers with lookup capabilities."""
    
    def __init__(self) -> None:
        self._sanitizers: dict[str, Sanitizer] = {}
        self._by_vuln_class: dict[VulnerabilityClass, list[Sanitizer]] = {}
    
    def register(self, sanitizer: Sanitizer) -> None:
        self._sanitizers[sanitizer.qualified_name] = sanitizer
        if sanitizer.clears_all:
            for vc in VulnerabilityClass:
                self._by_vuln_class.setdefault(vc, []).append(sanitizer)
        else:
            for vc in sanitizer.clears:
                self._by_vuln_class.setdefault(vc, []).append(sanitizer)
    
    def register_all(self, sanitizers: tuple[Sanitizer, ...]) -> None:
        for sanitizer in sanitizers:
            self.register(sanitizer)
    
    def get(self, qualified_name: str) -> Optional[Sanitizer]:
        return self._sanitizers.get(qualified_name)
    
    def get_for_vuln_class(self, vuln_class: VulnerabilityClass) -> list[Sanitizer]:
        return self._by_vuln_class.get(vuln_class, [])
    
    def match(self, module: str, function: str) -> Optional[Sanitizer]:
        return self._sanitizers.get(f"{module}.{function}")
    
    def all_sanitizers(self) -> list[Sanitizer]:
        return list(self._sanitizers.values())


def get_all_sanitizers() -> tuple[Sanitizer, ...]:
    return (*SQL_SANITIZERS, *GENERAL_SANITIZERS)


def create_default_registry() -> SanitizerRegistry:
    registry = SanitizerRegistry()
    registry.register_all(get_all_sanitizers())
    return registry
