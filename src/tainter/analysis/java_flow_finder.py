"""
Java flow finder for detecting source-to-sink vulnerability paths.

This module provides a lightweight Java taint analyzer over ParsedModule
structures produced by the Java parser.
"""

from __future__ import annotations

import re
import uuid
from dataclasses import dataclass, field
from typing import Optional

from tainter.core.types import (
    AnalysisResult,
    Confidence,
    FlowStep,
    Location,
    TaintFlow,
    TaintSink,
    TaintSource,
    TaintState,
    VulnerabilityClass,
)
from tainter.models.lang.java.sanitizers import create_java_sanitizer_registry
from tainter.models.lang.java.sinks import create_java_sink_registry
from tainter.models.lang.java.sources import create_java_source_registry
from tainter.models.registry import SanitizerRegistry, SinkRegistry, SourceRegistry
from tainter.parser.ast_parser import CallInfo, FunctionInfo, ParsedModule


_JAVA_ASSIGNMENT_RE = re.compile(
    r"^(?:[\w<>\[\],.?]+\s+)?(?P<target>[A-Za-z_]\w*)\s*=\s*(?P<expr>.+);$"
)
_JAVA_RETURN_RE = re.compile(r"^return\s+(?P<expr>.+);$")


@dataclass(frozen=True)
class JavaCallSite:
    """A resolved call with argument expressions at a source line."""

    call: CallInfo
    arguments: tuple[str, ...]


@dataclass
class JavaFlowFinder:
    """Find Java source-to-sink flows using lightweight taint propagation."""

    source_registry: SourceRegistry = field(default_factory=create_java_source_registry)
    sink_registry: SinkRegistry = field(default_factory=create_java_sink_registry)
    sanitizer_registry: SanitizerRegistry = field(default_factory=create_java_sanitizer_registry)
    max_call_depth: int = 5

    def __post_init__(self) -> None:
        self._call_stack: list[str] = []

    def analyze_project(self, modules: list[ParsedModule]) -> AnalysisResult:
        """Analyze Java modules and return detected flows."""
        result = AnalysisResult()
        result.files_analyzed = len(modules)

        for module in modules:
            for cls in module.classes:
                for method in cls.methods:
                    result.functions_analyzed += 1
                    result.flows.extend(self._analyze_method(module, method))

        return result

    def _analyze_method(self, module: ParsedModule, method: FunctionInfo) -> list[TaintFlow]:
        """Analyze a single Java method for taint flows."""
        if method.qualified_name in self._call_stack:
            return []
        if len(self._call_stack) >= self.max_call_depth:
            return []

        self._call_stack.append(method.qualified_name)
        try:
            taints = self._seed_parameter_taints(module, method)
            flows: list[TaintFlow] = []

            for line_no in range(method.line_start, method.line_end + 1):
                raw_line = module.get_line(line_no)
                line = raw_line.strip()
                if not line or line.startswith("//"):
                    continue

                assignment = _JAVA_ASSIGNMENT_RE.match(line)
                if assignment:
                    target = assignment.group("target")
                    expr = assignment.group("expr")
                    expr_taint = self._expression_taint(
                        expr=expr,
                        module=module,
                        method=method,
                        line_no=line_no,
                        taints=taints,
                    )
                    if expr_taint and expr_taint.is_tainted:
                        state = expr_taint.copy()
                        state.add_step(
                            FlowStep(
                                location=Location(module.file_path, line_no),
                                description=f"Assigned to {target}",
                                variable=target,
                                code_snippet=raw_line.strip(),
                                function_name=method.qualified_name,
                            )
                        )
                        taints[target] = state
                    else:
                        taints[target] = TaintState()

                call_sites = self._line_call_sites(module, method, line_no)
                for call_site in call_sites:
                    sink = self._identify_sink(module, call_site.call)
                    if not sink:
                        continue
                    source_taint = self._sink_argument_taint(call_site, sink, taints)
                    if not source_taint:
                        continue
                    if not source_taint.is_tainted_for(sink.vulnerability_class):
                        continue
                    flows.append(
                        self._create_flow(
                            module=module,
                            method=method,
                            sink=sink,
                            sink_call=call_site.call,
                            source_taint=source_taint,
                        )
                    )

                ret = _JAVA_RETURN_RE.match(line)
                if ret:
                    expr = ret.group("expr")
                    ret_taint = self._expression_taint(
                        expr=expr,
                        module=module,
                        method=method,
                        line_no=line_no,
                        taints=taints,
                    )
                    if ret_taint and ret_taint.is_tainted:
                        # Keep return taint in synthetic variable for trace continuity.
                        taints["$return"] = ret_taint

            return flows
        finally:
            self._call_stack.pop()

    def _seed_parameter_taints(
        self,
        module: ParsedModule,
        method: FunctionInfo,
    ) -> dict[str, TaintState]:
        """Treat method parameters as untrusted by default for Java analysis."""
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

    def _line_call_sites(
        self,
        module: ParsedModule,
        method: FunctionInfo,
        line_no: int,
    ) -> list[JavaCallSite]:
        """Resolve method call sites and their argument lists on a source line."""
        raw_line = module.get_line(line_no)
        line_calls = [
            call
            for call in module.all_calls
            if call.line == line_no and method.line_start <= call.line <= method.line_end
        ]
        sites: list[JavaCallSite] = []
        cursor = 0
        for call in line_calls:
            if (
                line_no == method.line_start
                and call.callee == method.name
                and call.receiver is None
                and "{" in raw_line
            ):
                # Method declaration captured by regex call extraction.
                continue
            args, cursor = self._extract_call_arguments(raw_line, call, cursor)
            sites.append(JavaCallSite(call=call, arguments=tuple(args)))
        return sites

    def _extract_call_arguments(
        self,
        line: str,
        call: CallInfo,
        offset: int = 0,
    ) -> tuple[list[str], int]:
        """Extract call arguments from a source line using balanced-parenthesis scan."""
        token = f"{call.receiver}.{call.callee}" if call.receiver else call.callee
        search = line[offset:]
        match = re.search(rf"{re.escape(token)}\s*\(", search)
        if not match:
            return [], offset

        start = offset + match.end() - 1  # points at '('
        depth = 0
        end = start
        for idx in range(start, len(line)):
            char = line[idx]
            if char == "(":
                depth += 1
            elif char == ")":
                depth -= 1
                if depth == 0:
                    end = idx
                    break

        args_blob = line[start + 1:end].strip()
        return self._split_arguments(args_blob), end + 1

    def _split_arguments(self, args_blob: str) -> list[str]:
        """Split argument list while respecting nested calls and string literals."""
        if not args_blob:
            return []

        args: list[str] = []
        current: list[str] = []
        depth = 0
        in_string = False
        quote_char = ""
        escape = False

        for char in args_blob:
            if in_string:
                current.append(char)
                if escape:
                    escape = False
                elif char == "\\":
                    escape = True
                elif char == quote_char:
                    in_string = False
                continue

            if char in ("'", '"'):
                in_string = True
                quote_char = char
                current.append(char)
                continue

            if char == "(":
                depth += 1
                current.append(char)
                continue
            if char == ")":
                if depth > 0:
                    depth -= 1
                current.append(char)
                continue
            if char == "," and depth == 0:
                token = "".join(current).strip()
                if token:
                    args.append(token)
                current = []
                continue
            current.append(char)

        token = "".join(current).strip()
        if token:
            args.append(token)
        return args

    def _expression_taint(
        self,
        expr: str,
        module: ParsedModule,
        method: FunctionInfo,
        line_no: int,
        taints: dict[str, TaintState],
    ) -> Optional[TaintState]:
        """Evaluate taint of a Java expression."""
        source = self._identify_source(module, expr)
        if source:
            return TaintState(
                is_tainted=True,
                source=source,
                source_location=Location(module.file_path, line_no),
            )

        sanitizer = self._identify_sanitizer(module, expr)
        if sanitizer:
            call = self._first_call_in_expression(module, method, line_no)
            if call and call.arguments:
                arg_taint = self._taint_from_variables(call.arguments[0], taints)
                if arg_taint and arg_taint.is_tainted:
                    sanitized = arg_taint.copy()
                    sanitized.sanitize(sanitizer)
                    return sanitized
            return None

        return self._taint_from_variables(expr, taints)

    def _first_call_in_expression(
        self,
        module: ParsedModule,
        method: FunctionInfo,
        line_no: int,
    ) -> Optional[JavaCallSite]:
        sites = self._line_call_sites(module, method, line_no)
        if not sites:
            return None
        return sites[0]

    def _taint_from_variables(
        self,
        expr: str,
        taints: dict[str, TaintState],
    ) -> Optional[TaintState]:
        """Find taint state referenced by variable usage in an expression."""
        for name, state in taints.items():
            if not state.is_tainted:
                continue
            if re.search(rf"\b{re.escape(name)}\b", expr):
                return state.copy()
        return None

    def _identify_source(self, module: ParsedModule, expr: str) -> Optional[TaintSource]:
        """Identify Java source call patterns in an expression."""
        for source in self.source_registry.all_sources():
            source_name = source.attribute or source.function.split(".")[-1]
            if re.search(rf"\b{re.escape(source_name)}\s*\(", expr):
                return source
        return None

    def _identify_sanitizer(self, module: ParsedModule, expr: str):
        """Identify Java sanitizer call patterns in an expression."""
        for sanitizer in self.sanitizer_registry.all_sanitizers():
            sanitizer_name = sanitizer.function.split(".")[-1]
            if re.search(rf"\b{re.escape(sanitizer_name)}\s*\(", expr):
                return sanitizer
        return None

    def _identify_sink(self, module: ParsedModule, call: CallInfo) -> Optional[TaintSink]:
        """Match a Java call to a known sink."""
        for sink in self.sink_registry.all_sinks():
            sink_method = sink.function.split(".")[-1]
            if call.callee != sink_method:
                continue
            if self._sink_module_compatible(module, call, sink):
                return sink
        return None

    def _sink_module_compatible(
        self,
        module: ParsedModule,
        call: CallInfo,
        sink: TaintSink,
    ) -> bool:
        """Conservative compatibility check between call context and sink module."""
        if sink.module.startswith("java.lang"):
            return True

        imports = [imp.module for imp in module.imports]
        if any(imp == sink.module or imp.startswith(sink.module + ".") for imp in imports):
            return True

        sink_parts = sink.function.split(".")
        if len(sink_parts) >= 2 and call.receiver:
            expected_owner = sink_parts[-2]
            receiver_leaf = call.receiver.split(".")[-1]
            if receiver_leaf == expected_owner:
                return True

        return False

    def _sink_argument_taint(
        self,
        call_site: JavaCallSite,
        sink: TaintSink,
        taints: dict[str, TaintState],
    ) -> Optional[TaintState]:
        """Get taint for sink-relevant argument positions."""
        if not call_site.arguments:
            return None

        if not sink.vulnerable_parameters:
            for arg in call_site.arguments:
                taint = self._taint_from_variables(arg, taints)
                if taint and taint.is_tainted:
                    return taint
            return None

        for idx in sink.vulnerable_parameters:
            if idx < len(call_site.arguments):
                arg = call_site.arguments[idx]
                taint = self._taint_from_variables(arg, taints)
                if taint and taint.is_tainted:
                    return taint
        return None

    def _create_flow(
        self,
        module: ParsedModule,
        method: FunctionInfo,
        sink: TaintSink,
        sink_call: CallInfo,
        source_taint: TaintState,
    ) -> TaintFlow:
        """Create a TaintFlow from Java taint state and sink call."""
        source = source_taint.source or TaintSource(
            module="unknown",
            function="unknown",
            description="Untracked source",
        )
        source_location = source_taint.source_location or Location(module.file_path, method.line_start)
        sink_location = Location(module.file_path, sink_call.line, sink_call.column)
        call_chain = tuple(self._call_stack) if self._call_stack else (method.qualified_name,)
        variable_path = tuple(step.variable for step in source_taint.propagation_path)

        return TaintFlow(
            id=f"FLOW-{uuid.uuid4().hex[:8].upper()}",
            source=source,
            source_location=source_location,
            source_code=module.get_line(source_location.line).strip(),
            sink=sink,
            sink_location=sink_location,
            sink_code=module.get_line(sink_location.line).strip(),
            steps=tuple(source_taint.propagation_path),
            call_chain=call_chain,
            variable_path=variable_path,
            vulnerability_class=sink.vulnerability_class,
            confidence=Confidence.HIGH,
            message=(
                f"Potential {sink.vulnerability_class.name.title()} vulnerability: "
                f"Untrusted data from {source.function} flows to {sink.function} "
                f"in {method.name}()"
            ),
        )
