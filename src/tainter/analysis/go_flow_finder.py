# src/tainter/analysis/go_flow_finder.py
"""Go taint flow finder — subclass of BaseFlowFinder."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional

from tainter.analysis.base_flow_finder import BaseFlowFinder
from tainter.core.types import Location, Sanitizer, TaintSink, TaintSource, TaintState
from tainter.models.lang.go.sanitizers import create_go_sanitizer_registry
from tainter.models.lang.go.sinks import create_go_sink_registry
from tainter.models.lang.go.sources import create_go_source_registry
from tainter.models.registry import SanitizerRegistry, SinkRegistry, SourceRegistry
from tainter.parser.ast_parser import CallInfo, FunctionInfo, ParsedModule

_GO_ASSIGN_RE = re.compile(
    r"^(?P<target>[A-Za-z_]\w*)\s*(?::=|=(?!=))\s*(?P<expr>.+?)\s*$"
)
_GO_RETURN_RE = re.compile(r"^return\s+(?P<expr>.+?)\s*$")

# HTTP handler param types that indicate the param carries user input
_GO_HTTP_HANDLER_TYPES = {
    "*http.Request",
    "http.Request",
    "gin.Context",
    "*gin.Context",
    "echo.Context",
    "*echo.Context",
}


@dataclass
class GoFlowFinder(BaseFlowFinder):
    """Find Go source-to-sink taint flows using lightweight taint propagation."""

    source_registry: SourceRegistry = field(
        default_factory=create_go_source_registry
    )
    sink_registry: SinkRegistry = field(
        default_factory=create_go_sink_registry
    )
    sanitizer_registry: SanitizerRegistry = field(
        default_factory=create_go_sanitizer_registry
    )

    def _parse_assignment(self, line: str) -> Optional[tuple[str, str]]:
        m = _GO_ASSIGN_RE.match(line)
        if not m:
            return None
        target = m.group("target")
        expr = m.group("expr").strip()
        return (target, expr)

    def _parse_return(self, line: str) -> Optional[str]:
        m = _GO_RETURN_RE.match(line)
        return m.group("expr").strip() if m else None

    def _seed_parameter_taints(
        self, module: ParsedModule, method: FunctionInfo
    ) -> dict[str, TaintState]:
        taints: dict[str, TaintState] = {}
        for param in method.parameters:
            # The Go parser stores the type in ParameterInfo.annotation.
            param_type = param.annotation or ""
            # Strip pointer prefix for comparison
            normalized = param_type.lstrip("*")
            if param_type in _GO_HTTP_HANDLER_TYPES or normalized in _GO_HTTP_HANDLER_TYPES:
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
            # Match `receiver.function` pattern (e.g. r.FormValue)
            if re.search(rf"\b{re.escape(source.function)}\b", expr):
                return source
            # Also match attribute pattern if present
            if source.attribute and re.search(rf"\b{re.escape(source.attribute)}\b", expr):
                return source
        return None

    def _identify_sink(
        self, module: ParsedModule, call: CallInfo
    ) -> Optional[TaintSink]:
        for sink in self.sink_registry.all_sinks():
            parts = sink.function.split(".", 1)
            if len(parts) == 2:
                pkg, method = parts
                # Match receiver.method (e.g. db.Query, exec.Command)
                if call.receiver == pkg and call.callee == method:
                    return sink
                # Also match bare method name
                if call.callee == method:
                    return sink
            else:
                # No dot — bare function name
                if call.callee == sink.function:
                    return sink
        return None

    def _identify_sanitizer(
        self, module: ParsedModule, expr: str
    ) -> Optional[Sanitizer]:
        for sanitizer in self.sanitizer_registry.all_sanitizers():
            sanitizer_name = sanitizer.function.split(".")[-1]
            if re.search(rf"\b{re.escape(sanitizer_name)}\b", expr):
                return sanitizer
        return None
