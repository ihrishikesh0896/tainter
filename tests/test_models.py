"""Unit tests for language-specific taint models (sources, sinks, sanitizers)."""

from tainter.core.types import VulnerabilityClass
from tainter.models.lang.javascript.sources import create_javascript_source_registry
from tainter.models.lang.javascript.sinks import create_javascript_sink_registry
from tainter.models.lang.javascript.sanitizers import create_javascript_sanitizer_registry
from tainter.models.lang.go.sources import create_go_source_registry
from tainter.models.lang.go.sinks import create_go_sink_registry
from tainter.models.lang.go.sanitizers import create_go_sanitizer_registry


class TestJavaScriptModels:
    """Tests for JavaScript taint models."""

    def test_javascript_source_registry(self):
        registry = create_javascript_source_registry()
        sources = registry.all_sources()
        assert len(sources) >= 11
        functions = [s.function for s in sources]
        assert "Request" in functions
        assert "Body" in functions

    def test_javascript_sink_registry(self):
        registry = create_javascript_sink_registry()
        sinks = registry.all_sinks()
        assert len(sinks) >= 16
        sqli = [s for s in sinks if s.vulnerability_class == VulnerabilityClass.SQLI]
        rce = [s for s in sinks if s.vulnerability_class == VulnerabilityClass.RCE]
        assert len(sqli) >= 5
        assert len(rce) >= 6

    def test_javascript_sanitizer_registry(self):
        registry = create_javascript_sanitizer_registry()
        sanitizers = registry.all_sanitizers()
        assert len(sanitizers) >= 6


class TestGoModels:
    """Tests for Go taint models."""

    def test_go_source_registry(self):
        registry = create_go_source_registry()
        sources = registry.all_sources()
        assert len(sources) >= 12
        functions = [s.function for s in sources]
        assert "Query.Get" in functions
        assert "Param" in functions
        assert "QueryParam" in functions

    def test_go_sink_registry(self):
        registry = create_go_sink_registry()
        sinks = registry.all_sinks()
        assert len(sinks) >= 10
        sqli = [s for s in sinks if s.vulnerability_class == VulnerabilityClass.SQLI]
        rce = [s for s in sinks if s.vulnerability_class == VulnerabilityClass.RCE]
        assert len(sqli) >= 3
        assert len(rce) >= 1

    def test_go_sanitizer_registry(self):
        registry = create_go_sanitizer_registry()
        sanitizers = registry.all_sanitizers()
        assert len(sanitizers) >= 4
