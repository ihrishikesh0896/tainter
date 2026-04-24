# src/tainter/analysis/java_flow_finder.py
"""Java taint flow finder — subclass of BaseFlowFinder."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional

from tainter.analysis.base_flow_finder import BaseFlowFinder, CallSite
from tainter.core.types import Location, Sanitizer, TaintSink, TaintSource, TaintState
from tainter.models.lang.java.sanitizers import create_java_sanitizer_registry
from tainter.models.lang.java.sinks import create_java_sink_registry
from tainter.models.lang.java.sources import create_java_source_registry
from tainter.models.registry import SanitizerRegistry, SinkRegistry, SourceRegistry
from tainter.parser.ast_parser import CallInfo, FunctionInfo, ParsedModule

_JAVA_ASSIGNMENT_RE = re.compile(
    r"^(?:[\w<>\[\],.?]+\s+)?(?P<target>[A-Za-z_]\w*)\s*=\s*(?P<expr>.+);$"
)
_JAVA_RETURN_RE = re.compile(r"^return\s+(?P<expr>.+);$")


@dataclass
class JavaFlowFinder(BaseFlowFinder):
    """Find Java source-to-sink flows using lightweight taint propagation."""

    source_registry: SourceRegistry = field(default_factory=create_java_source_registry)
    sink_registry: SinkRegistry = field(default_factory=create_java_sink_registry)
    sanitizer_registry: SanitizerRegistry = field(
        default_factory=create_java_sanitizer_registry
    )

    def _parse_assignment(self, line: str) -> Optional[tuple[str, str]]:
        m = _JAVA_ASSIGNMENT_RE.match(line)
        return (m.group("target"), m.group("expr")) if m else None

    def _parse_return(self, line: str) -> Optional[str]:
        m = _JAVA_RETURN_RE.match(line)
        return m.group("expr") if m else None

    def _seed_parameter_taints(
        self, module: ParsedModule, method: FunctionInfo
    ) -> dict[str, TaintState]:
        taints: dict[str, TaintState] = {}
        for param in method.parameters:
            taints[param.name] = TaintState(
                is_tainted=True,
                source=TaintSource(
                    module=module.module_name,
                    function=method.name,
                    attribute=f"param:{param.name}",
                    description="Method parameter treated as untrusted input",
                ),
                source_location=Location(module.file_path, method.line_start),
            )
        return taints

    def _identify_source(
        self, module: ParsedModule, expr: str
    ) -> Optional[TaintSource]:
        for source in self.source_registry.all_sources():
            source_name = source.attribute or source.function.split(".")[-1]
            if re.search(rf"\b{re.escape(source_name)}\s*\(", expr):
                return source
        return None

    def _identify_sink(
        self, module: ParsedModule, call: CallInfo
    ) -> Optional[TaintSink]:
        for sink in self.sink_registry.all_sinks():
            sink_method = sink.function.split(".")[-1]
            if call.callee != sink_method:
                continue
            if self._sink_module_compatible(module, call, sink):
                return sink
        return None

    def _identify_sanitizer(
        self, module: ParsedModule, expr: str
    ) -> Optional[Sanitizer]:
        for sanitizer in self.sanitizer_registry.all_sanitizers():
            sanitizer_name = sanitizer.function.split(".")[-1]
            if re.search(rf"\b{re.escape(sanitizer_name)}\s*\(", expr):
                return sanitizer
        return None

    def _sink_module_compatible(
        self, module: ParsedModule, call: CallInfo, sink: TaintSink
    ) -> bool:
        if sink.module.startswith("java.lang"):
            return True
        imports = [imp.module for imp in module.imports]
        if any(
            imp == sink.module or imp.startswith(sink.module + ".") for imp in imports
        ):
            return True
        sink_parts = sink.function.split(".")
        if len(sink_parts) >= 2 and call.receiver:
            expected_owner = sink_parts[-2]
            receiver_leaf = call.receiver.split(".")[-1]
            if receiver_leaf == expected_owner:
                return True
        return False
