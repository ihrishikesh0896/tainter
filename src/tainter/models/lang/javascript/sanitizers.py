# src/tainter/models/lang/javascript/sanitizers.py
"""JavaScript sanitizer definitions."""

from tainter.core.types import Sanitizer, VulnerabilityClass
from tainter.models.registry import SanitizerRegistry

JS_SANITIZERS: tuple[Sanitizer, ...] = (
    Sanitizer(
        module="he", function="encode",
        clears=(VulnerabilityClass.XSS,),
        description="HTML entity encoding via 'he' library",
    ),
    Sanitizer(
        module="dompurify", function="sanitize",
        clears=(VulnerabilityClass.XSS,),
        description="DOMPurify HTML sanitization",
    ),
    Sanitizer(
        module="validator", function="escape",
        clears=(VulnerabilityClass.XSS,),
        description="validator.js HTML escape",
    ),
    Sanitizer(
        module="mysql", function="escape",
        clears=(VulnerabilityClass.SQLI,),
        description="MySQL string escaping",
    ),
    Sanitizer(
        module="mysql2", function="escape",
        clears=(VulnerabilityClass.SQLI,),
        description="mysql2 string escaping",
    ),
    Sanitizer(
        module="path", function="resolve",
        clears=(VulnerabilityClass.PATH_TRAVERSAL,),
        description="path.resolve() normalizes traversal sequences",
    ),
)


def get_all_javascript_sanitizers() -> tuple[Sanitizer, ...]:
    return JS_SANITIZERS


def create_javascript_sanitizer_registry() -> SanitizerRegistry:
    registry = SanitizerRegistry()
    registry.register_all(get_all_javascript_sanitizers())
    return registry
