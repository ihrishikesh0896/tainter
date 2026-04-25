# src/tainter/analysis/javascript_flow_finder.py
"""JavaScript taint flow finder — subclass of BaseFlowFinder."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional

from tainter.analysis.base_flow_finder import BaseFlowFinder
from tainter.core.types import Location, Sanitizer, TaintSink, TaintSource, TaintState
from tainter.models.lang.javascript.sanitizers import create_javascript_sanitizer_registry
from tainter.models.lang.javascript.sinks import create_javascript_sink_registry
from tainter.models.lang.javascript.sources import create_javascript_source_registry
from tainter.models.registry import SanitizerRegistry, SinkRegistry, SourceRegistry
from tainter.parser.ast_parser import CallInfo, FunctionInfo, ParsedModule

_JS_ASSIGNMENT_RE = re.compile(
    r"^(?:(?:const|let|var)\s+)?(?P<target>[A-Za-z_$][\w$]*)\s*=(?!=)\s*(?P<expr>.+?);?\s*$"
)
_JS_RETURN_RE = re.compile(r"^return\s+(?P<expr>.+?);?\s*$")

_JS_HTTP_HANDLER_PARAMS = {
    "req", "request",
}


@dataclass
class JavaScriptFlowFinder(BaseFlowFinder):
    """Find JavaScript source-to-sink flows using lightweight taint propagation."""

    source_registry: SourceRegistry = field(
        default_factory=create_javascript_source_registry
    )
    sink_registry: SinkRegistry = field(
        default_factory=create_javascript_sink_registry
    )
    sanitizer_registry: SanitizerRegistry = field(
        default_factory=create_javascript_sanitizer_registry
    )

    def _parse_assignment(self, line: str) -> Optional[tuple[str, str]]:
        m = _JS_ASSIGNMENT_RE.match(line)
        if not m:
            return None
        target = m.group("target")
        expr = m.group("expr").strip().rstrip(";")
        return (target, expr)

    def _parse_return(self, line: str) -> Optional[str]:
        m = _JS_RETURN_RE.match(line)
        return m.group("expr").strip().rstrip(";") if m else None

    def _seed_parameter_taints(
        self, module: ParsedModule, method: FunctionInfo
    ) -> dict[str, TaintState]:
        taints: dict[str, TaintState] = {}
        for param in method.parameters:
            if param.name in _JS_HTTP_HANDLER_PARAMS:
                taints[param.name] = TaintState(
                    is_tainted=True,
                    source=TaintSource(
                        module=module.module_name,
                        function=method.name,
                        attribute=f"param:{param.name}",
                        description="HTTP handler request object",
                    ),
                    source_location=Location(module.file_path, method.line_start),
                )
        return taints

    def _identify_source(
        self, module: ParsedModule, expr: str
    ) -> Optional[TaintSource]:
        for source in self.source_registry.all_sources():
            pattern = source.attribute or source.function
            if re.search(rf"\b{re.escape(pattern)}\b", expr):
                return source
        return None

    def _identify_sink(
        self, module: ParsedModule, call: CallInfo
    ) -> Optional[TaintSink]:
        for sink in self.sink_registry.all_sinks():
            sink_func = sink.function.split(".")[-1]
            if call.callee == sink_func:
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
