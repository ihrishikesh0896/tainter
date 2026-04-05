"""
Shared registry classes for taint models.

These registries provide lookup and matching for sources, sinks,
and sanitizers regardless of language.
"""

from typing import Optional

from tainter.core.types import Sanitizer, TaintSink, TaintSource, VulnerabilityClass


class SourceRegistry:
    """Registry for taint sources with lookup capabilities."""

    def __init__(self) -> None:
        self._sources: dict[str, TaintSource] = {}
        self._by_framework: dict[str, list[TaintSource]] = {}

    def register(self, source: TaintSource) -> None:
        self._sources[source.qualified_name] = source
        if source.framework:
            self._by_framework.setdefault(source.framework, []).append(source)

    def register_all(self, sources: tuple[TaintSource, ...]) -> None:
        for source in sources:
            self.register(source)

    def get(self, qualified_name: str) -> Optional[TaintSource]:
        return self._sources.get(qualified_name)

    def get_by_framework(self, framework: str) -> list[TaintSource]:
        return self._by_framework.get(framework, [])

    def match(self, module: str, function: str, attribute: Optional[str] = None) -> Optional[TaintSource]:
        if attribute:
            key = f"{module}.{function}.{attribute}"
            if key in self._sources:
                return self._sources[key]
        key = f"{module}.{function}"
        return self._sources.get(key)

    def all_sources(self) -> list[TaintSource]:
        return list(self._sources.values())


class SinkRegistry:
    """Registry for taint sinks with lookup capabilities."""

    def __init__(self) -> None:
        self._sinks: dict[str, TaintSink] = {}
        self._by_vuln_class: dict[VulnerabilityClass, list[TaintSink]] = {}
        self._by_module: dict[str, list[TaintSink]] = {}

    def register(self, sink: TaintSink) -> None:
        self._sinks[sink.qualified_name] = sink
        self._by_vuln_class.setdefault(sink.vulnerability_class, []).append(sink)
        self._by_module.setdefault(sink.module, []).append(sink)

    def register_all(self, sinks: tuple[TaintSink, ...]) -> None:
        for sink in sinks:
            self.register(sink)

    def get(self, qualified_name: str) -> Optional[TaintSink]:
        return self._sinks.get(qualified_name)

    def get_by_vuln_class(self, vuln_class: VulnerabilityClass) -> list[TaintSink]:
        return self._by_vuln_class.get(vuln_class, [])

    def get_by_module(self, module: str) -> list[TaintSink]:
        return self._by_module.get(module, [])

    def match(self, module: str, function: str) -> Optional[TaintSink]:
        return self._sinks.get(f"{module}.{function}")

    def all_sinks(self) -> list[TaintSink]:
        return list(self._sinks.values())

    def count(self) -> int:
        return len(self._sinks)

    def count_by_vuln_class(self) -> dict[VulnerabilityClass, int]:
        return {vc: len(sinks) for vc, sinks in self._by_vuln_class.items()}


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
