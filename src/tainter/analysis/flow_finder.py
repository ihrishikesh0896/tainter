"""
Flow finder for detecting source-to-sink vulnerability paths.

This module ties together the call graph and taint analysis to find
complete flows from sources to sinks.
"""

import ast
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, Iterator

from tainter.core.types import (
    TaintFlow, TaintSource, TaintSink, Location, FlowStep,
    VulnerabilityClass, Confidence, TaintState, AnalysisResult,
)
from tainter.parser.ast_parser import ParsedModule, FunctionInfo, CallInfo
from tainter.graph.call_graph import CallGraph, CallGraphBuilder
from tainter.models.sources import SourceRegistry, create_default_registry as create_source_registry
from tainter.models.sinks import SinkRegistry, create_default_registry as create_sink_registry
from tainter.models.sanitizers import SanitizerRegistry, create_default_registry as create_sanitizer_registry
from tainter.analysis.taint_tracker import TaintTracker, TaintContext


@dataclass
class FlowAnalysisResult:
    """Result of flow analysis for a single function."""
    
    function: FunctionInfo
    flows: list[TaintFlow] = field(default_factory=list)
    taint_context: Optional[TaintContext] = None


class FlowFinder:
    """
    Finds source-to-sink flows in a project.
    
    Combines call graph analysis with intra-procedural taint tracking
    to detect vulnerability flows.
    """
    
    def __init__(
        self,
        source_registry: Optional[SourceRegistry] = None,
        sink_registry: Optional[SinkRegistry] = None,
        sanitizer_registry: Optional[SanitizerRegistry] = None,
    ):
        self.sources = source_registry or create_source_registry()
        self.sinks = sink_registry or create_sink_registry()
        self.sanitizers = sanitizer_registry or create_sanitizer_registry()
        self.taint_tracker = TaintTracker(self.sources, self.sanitizers)
    
    def analyze_project(
        self,
        modules: list[ParsedModule],
        call_graph: Optional[CallGraph] = None,
    ) -> AnalysisResult:
        """
        Analyze an entire project for vulnerability flows.
        
        Args:
            modules: List of parsed modules
            call_graph: Optional pre-built call graph
            
        Returns:
            AnalysisResult with all detected flows
        """
        result = AnalysisResult()
        
        # Build call graph if not provided
        if call_graph is None:
            builder = CallGraphBuilder()
            for module in modules:
                builder.add_module(module)
            call_graph = builder.build()
        
        result.files_analyzed = len(modules)
        
        # Analyze each module
        for module in modules:
            module_flows = self._analyze_module(module, call_graph)
            result.flows.extend(module_flows)
            result.functions_analyzed += len(module.functions)
            for cls in module.classes:
                result.functions_analyzed += len(cls.methods)
        
        return result
    
    def _analyze_module(
        self,
        module: ParsedModule,
        call_graph: CallGraph,
    ) -> list[TaintFlow]:
        """Analyze a single module for flows."""
        flows: list[TaintFlow] = []
        
        # Analyze each function
        for func in module.functions:
            func_flows = self._analyze_function(func, module, call_graph)
            flows.extend(func_flows)
        
        # Analyze class methods
        for cls in module.classes:
            for method in cls.methods:
                method_flows = self._analyze_function(method, module, call_graph)
                flows.extend(method_flows)
        
        return flows
    
    def _analyze_function(
        self,
        func: FunctionInfo,
        module: ParsedModule,
        call_graph: CallGraph,
    ) -> list[TaintFlow]:
        """Analyze a function for source-to-sink flows."""
        flows: list[TaintFlow] = []
        
        if not func.body_ast:
            return flows
        
        # Run taint tracking
        context = self.taint_tracker.analyze_function(func, module)
        
        # Find sinks and check if they receive tainted data
        if isinstance(func.body_ast, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for stmt in ast.walk(func.body_ast):
                if isinstance(stmt, ast.Call):
                    flow = self._check_call_for_sink(stmt, context, module, func, call_graph)
                    if flow:
                        flows.append(flow)
        
        return flows
    
    def _check_call_for_sink(
        self,
        call: ast.Call,
        context: TaintContext,
        module: ParsedModule,
        func: FunctionInfo,
        call_graph: CallGraph,
    ) -> Optional[TaintFlow]:
        """Check if a call is a sink receiving tainted data."""
        # Identify the sink
        sink = self._identify_sink(call, module)
        if not sink:
            return None
        
        # Check if any vulnerable parameter is tainted
        if not sink.vulnerable_parameters:
            # No explicit parameter list: treat all positional and keyword values as dangerous
            for arg in call.args:
                arg_taint = self._get_arg_taint(arg, context, module)
                if arg_taint and arg_taint.is_tainted and arg_taint.is_tainted_for(sink.vulnerability_class):
                    return self._create_flow(
                        source=arg_taint.source,
                        source_taint=arg_taint,
                        sink=sink,
                        sink_call=call,
                        module=module,
                        func=func,
                    )

            for kw in call.keywords:
                kw_taint = self._get_arg_taint(kw.value, context, module)
                if kw_taint and kw_taint.is_tainted and kw_taint.is_tainted_for(sink.vulnerability_class):
                    return self._create_flow(
                        source=kw_taint.source,
                        source_taint=kw_taint,
                        sink=sink,
                        sink_call=call,
                        module=module,
                        func=func,
                    )
        else:
            for param_idx in sink.vulnerable_parameters:
                if param_idx < len(call.args):
                    arg = call.args[param_idx]
                    arg_taint = self._get_arg_taint(arg, context, module)

                    if arg_taint and arg_taint.is_tainted:
                        # Check if taint is relevant for this sink's vuln class
                        if arg_taint.is_tainted_for(sink.vulnerability_class):
                            return self._create_flow(
                                source=arg_taint.source,
                                source_taint=arg_taint,
                                sink=sink,
                                sink_call=call,
                                module=module,
                                func=func,
                            )

        return None

    def _identify_sink(self, call: ast.Call, module: ParsedModule) -> Optional[TaintSink]:
        """Identify if a call matches a known sink."""
        if isinstance(call.func, ast.Name):
            func_name = call.func.id
            for sink in self.sinks.all_sinks():
                if sink.function == func_name:
                    return sink
        elif isinstance(call.func, ast.Attribute):
            # Check for method calls like cursor.execute(), subprocess.run()
            # Build the full call chain: e.g., cursor.execute or subprocess.run
            attr_name = call.func.attr

            # Try to get the receiver object name and resolve imports
            parts = [attr_name]
            current = call.func.value
            while isinstance(current, ast.Attribute):
                parts.append(current.attr)
                current = current.value

            receiver_name = None
            if isinstance(current, ast.Name):
                receiver_name = current.id
                parts.append(receiver_name)

            parts.reverse()
            full_call = ".".join(parts)

            # Try to resolve the receiver to its imported module
            resolved_module = None
            if receiver_name:
                imp = module.resolve_import(receiver_name)
                if imp:
                    resolved_module = imp.module

            # Match against sinks
            for sink in self.sinks.all_sinks():
                # Check if this is an exact match with module.function
                sink_parts = sink.function.split(".")

                # Strategy 1: Exact match on the full call chain (e.g., subprocess.run)
                if full_call == sink.function:
                    return sink

                # Strategy 2: Match receiver module + method (e.g., subprocess module with run method)
                if resolved_module and len(sink_parts) == 1:
                    # Sink is just a method name, check if it matches with the resolved module
                    if resolved_module == sink.module and attr_name == sink.function:
                        return sink

                # Strategy 3: For sinks with Class.method pattern (e.g., Cursor.execute)
                # match if we know the method name and can infer context from imports
                if len(sink_parts) == 2:
                    # sink.function is like "Cursor.execute" or "cursor.execute"
                    class_name, method_name = sink_parts
                    if attr_name == method_name:
                        # Method name matches, check if we have the right module context
                        # Check if any import from this module exists in the current module
                        for imp in module.imports:
                            if imp.module == sink.module or imp.module.startswith(sink.module + "."):
                                # We have an import from the sink's module, so this is likely a match
                                return sink

                # Strategy 4: Match on receiver name if it matches expected module name
                if len(sink_parts) == 1 and receiver_name and resolved_module:
                    # Sink is a simple method, check if receiver module matches
                    if resolved_module == sink.module and attr_name == sink.function:
                        return sink

                # Strategy 5: For well-known dangerous methods with unique names,
                # allow matching based solely on method name if module is in scope
                if len(sink_parts) == 1:
                    # Check for uniquely dangerous method names
                    unique_dangerous_methods = {
                        "execute", "executemany", "executescript",  # SQL
                        "eval", "exec", "compile",  # Code execution
                        "system", "popen",  # OS commands
                    }
                    if attr_name == sink.function and attr_name in unique_dangerous_methods:
                        # Check if the sink's module is imported
                        for imp in module.imports:
                            if imp.module == sink.module or imp.module.startswith(sink.module + "."):
                                return sink

        return None
    
    def _get_arg_taint(
        self,
        arg: ast.expr,
        context: TaintContext,
        module: ParsedModule,
    ) -> Optional[TaintState]:
        """Get taint state for a call argument."""
        if isinstance(arg, ast.Name):
            return context.get_taint(arg.id)
        elif isinstance(arg, ast.JoinedStr):
            # f-string - check all formatted values
            for value in arg.values:
                if isinstance(value, ast.FormattedValue):
                    taint = self._get_arg_taint(value.value, context, module)
                    if taint and taint.is_tainted:
                        return taint
        elif isinstance(arg, ast.BinOp):
            # String concatenation
            left_taint = self._get_arg_taint(arg.left, context, module)
            right_taint = self._get_arg_taint(arg.right, context, module)
            if left_taint and left_taint.is_tainted:
                return left_taint
            if right_taint and right_taint.is_tainted:
                return right_taint
        elif isinstance(arg, ast.Call):
            # Check if return value of call is tainted
            for sub_arg in arg.args:
                taint = self._get_arg_taint(sub_arg, context, module)
                if taint and taint.is_tainted:
                    return taint
        return None
    
    def _create_flow(
        self,
        source: Optional[TaintSource],
        source_taint: TaintState,
        sink: TaintSink,
        sink_call: ast.Call,
        module: ParsedModule,
        func: FunctionInfo,
    ) -> TaintFlow:
        """Create a TaintFlow object for a detected vulnerability."""
        if not source:
            source = TaintSource(
                module="unknown",
                function="unknown",
                description="Untracked source",
            )
        
        source_loc = source_taint.source_location or Location(module.file_path, 0)
        sink_loc = Location(
            file=module.file_path,
            line=sink_call.lineno,
            column=sink_call.col_offset,
        )
        
        # Build call chain and variable path
        call_chain = [func.qualified_name]
        variable_path = [step.variable for step in source_taint.propagation_path]
        
        # Determine confidence
        confidence = Confidence.HIGH
        if not source_taint.source:
            confidence = Confidence.MEDIUM
        if len(source_taint.propagation_path) > 5:
            confidence = Confidence.MEDIUM
        
        return TaintFlow(
            id=f"FLOW-{uuid.uuid4().hex[:8].upper()}",
            source=source,
            source_location=source_loc,
            source_code=module.get_line(source_loc.line).strip() if source_loc.line > 0 else "",
            sink=sink,
            sink_location=sink_loc,
            sink_code=module.get_line(sink_loc.line).strip(),
            steps=tuple(source_taint.propagation_path),
            call_chain=tuple(call_chain),
            variable_path=tuple(variable_path),
            vulnerability_class=sink.vulnerability_class,
            confidence=confidence,
            message=self._generate_message(source, sink, func),
        )
    
    def _generate_message(
        self,
        source: TaintSource,
        sink: TaintSink,
        func: FunctionInfo,
    ) -> str:
        """Generate a human-readable message for the flow."""
        vuln_name = sink.vulnerability_class.name.replace("_", " ").title()
        return (
            f"Potential {vuln_name} vulnerability: "
            f"Untrusted data from {source.function} flows to {sink.function} "
            f"in {func.name}()"
        )
