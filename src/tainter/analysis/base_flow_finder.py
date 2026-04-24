# src/tainter/analysis/base_flow_finder.py
"""Abstract base class for language-specific taint flow finders."""

from __future__ import annotations

import re
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Optional

from tainter.core.types import (
    AnalysisResult,
    Confidence,
    FlowStep,
    Location,
    Sanitizer,
    TaintFlow,
    TaintSink,
    TaintSource,
    TaintState,
)
from tainter.models.registry import SanitizerRegistry, SinkRegistry, SourceRegistry
from tainter.parser.ast_parser import CallInfo, FunctionInfo, ParsedModule


@dataclass(frozen=True)
class CallSite:
    """A resolved call with argument expressions at a source line."""

    call: CallInfo
    arguments: tuple[str, ...]


@dataclass
class BaseFlowFinder(ABC):
    """
    Abstract base for language-specific taint flow finders.

    Shared logic: project iteration, assignment/return tracking, call site
    extraction, argument splitting, sink argument taint, flow creation.

    Language subclasses implement: parameter seeding, assignment/return parsing,
    source/sink/sanitizer identification.
    """

    source_registry: SourceRegistry
    sink_registry: SinkRegistry
    sanitizer_registry: SanitizerRegistry
    max_call_depth: int = 5

    def __post_init__(self) -> None:
        self._call_stack: list[str] = []

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def analyze_project(self, modules: list[ParsedModule]) -> AnalysisResult:
        """Analyze all modules and return detected flows."""
        result = AnalysisResult()
        result.files_analyzed = len(modules)
        for module in modules:
            for cls in module.classes:
                for method in cls.methods:
                    result.functions_analyzed += 1
                    result.flows.extend(self._analyze_method(module, method))
            for func in module.functions:
                result.functions_analyzed += 1
                result.flows.extend(self._analyze_method(module, func))
        return result

    # ------------------------------------------------------------------
    # Abstract hooks — implemented per language
    # ------------------------------------------------------------------

    @abstractmethod
    def _seed_parameter_taints(
        self, module: ParsedModule, method: FunctionInfo
    ) -> dict[str, TaintState]:
        """Return initial taint state keyed by parameter name."""

    @abstractmethod
    def _parse_assignment(self, line: str) -> Optional[tuple[str, str]]:
        """Return (target_var, rhs_expr) if line is an assignment, else None."""

    @abstractmethod
    def _parse_return(self, line: str) -> Optional[str]:
        """Return the returned expression if line is a return statement, else None."""

    @abstractmethod
    def _identify_source(
        self, module: ParsedModule, expr: str
    ) -> Optional[TaintSource]:
        """Return a matching TaintSource if expr contains a source call, else None."""

    @abstractmethod
    def _identify_sink(
        self, module: ParsedModule, call: CallInfo
    ) -> Optional[TaintSink]:
        """Return a matching TaintSink for the given call, else None."""

    @abstractmethod
    def _identify_sanitizer(self, module: ParsedModule, expr: str) -> Optional[Sanitizer]:
        """Return a matching Sanitizer if expr contains a sanitizer call, else None."""

    # ------------------------------------------------------------------
    # Shared analysis logic
    # ------------------------------------------------------------------

    def _analyze_method(
        self, module: ParsedModule, method: FunctionInfo
    ) -> list[TaintFlow]:
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
                if not line or line.startswith("//") or line.startswith("#"):
                    continue

                assignment = self._parse_assignment(line)
                if assignment:
                    target, expr = assignment
                    expr_taint = self._expression_taint(
                        expr, module, method, line_no, taints
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

                ret_expr = self._parse_return(line)
                if ret_expr:
                    ret_taint = self._expression_taint(
                        ret_expr, module, method, line_no, taints
                    )
                    if ret_taint and ret_taint.is_tainted:
                        taints["$return"] = ret_taint

            return flows
        finally:
            self._call_stack.pop()

    def _expression_taint(
        self,
        expr: str,
        module: ParsedModule,
        method: FunctionInfo,
        line_no: int,
        taints: dict[str, TaintState],
    ) -> Optional[TaintState]:
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

    def _taint_from_variables(
        self, expr: str, taints: dict[str, TaintState]
    ) -> Optional[TaintState]:
        for name, state in taints.items():
            if not state.is_tainted:
                continue
            if re.search(rf"\b{re.escape(name)}\b", expr):
                return state.copy()
        return None

    def _sink_argument_taint(
        self,
        call_site: CallSite,
        sink: TaintSink,
        taints: dict[str, TaintState],
    ) -> Optional[TaintState]:
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
        source = source_taint.source or TaintSource(
            module="unknown", function="unknown", description="Untracked source"
        )
        source_location = source_taint.source_location or Location(
            module.file_path, method.line_start
        )
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

    def _line_call_sites(
        self, module: ParsedModule, method: FunctionInfo, line_no: int
    ) -> list[CallSite]:
        raw_line = module.get_line(line_no)
        line_calls = [
            call
            for call in module.all_calls
            if call.line == line_no and method.line_start <= call.line <= method.line_end
        ]
        sites: list[CallSite] = []
        cursor = 0
        for call in line_calls:
            if (
                line_no == method.line_start
                and call.callee == method.name
                and call.receiver is None
                and "{" in raw_line
            ):
                continue
            args, cursor = self._extract_call_arguments(raw_line, call, cursor)
            sites.append(CallSite(call=call, arguments=tuple(args)))
        return sites

    def _extract_call_arguments(
        self, line: str, call: CallInfo, offset: int = 0
    ) -> tuple[list[str], int]:
        token = f"{call.receiver}.{call.callee}" if call.receiver else call.callee
        search = line[offset:]
        match = re.search(rf"{re.escape(token)}\s*\(", search)
        if not match:
            return [], offset
        start = offset + match.end() - 1
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
        args_blob = line[start + 1 : end].strip()
        return self._split_arguments(args_blob), end + 1

    def _split_arguments(self, args_blob: str) -> list[str]:
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
            if char in ("'", '"', "`"):
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

    def _first_call_in_expression(
        self, module: ParsedModule, method: FunctionInfo, line_no: int
    ) -> Optional[CallSite]:
        sites = self._line_call_sites(module, method, line_no)
        return sites[0] if sites else None
