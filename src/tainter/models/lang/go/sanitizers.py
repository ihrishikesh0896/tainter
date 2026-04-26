# src/tainter/models/lang/go/sanitizers.py
"""Go sanitizer definitions."""

from tainter.core.types import Sanitizer, VulnerabilityClass
from tainter.models.registry import SanitizerRegistry

GO_SANITIZERS: tuple[Sanitizer, ...] = (
    Sanitizer(
        module="html", function="EscapeString",
        clears=(VulnerabilityClass.XSS,),
        description="HTML entity escaping via html.EscapeString",
    ),
    Sanitizer(
        module="net/url", function="QueryEscape",
        clears=(VulnerabilityClass.SSRF,),
        description="URL query parameter escaping via url.QueryEscape",
    ),
    Sanitizer(
        module="path/filepath", function="Clean",
        clears=(VulnerabilityClass.PATH_TRAVERSAL,),
        description="filepath.Clean() normalizes and removes traversal sequences",
    ),
    Sanitizer(
        module="regexp", function="QuoteMeta",
        clears=(VulnerabilityClass.SQLI,),
        description="regexp.QuoteMeta() escapes special regex characters",
    ),
)


def get_all_go_sanitizers() -> tuple[Sanitizer, ...]:
    return GO_SANITIZERS


def create_go_sanitizer_registry() -> SanitizerRegistry:
    registry = SanitizerRegistry()
    registry.register_all(get_all_go_sanitizers())
    return registry
