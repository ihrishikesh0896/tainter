"""
Flow finder for detecting source-to-sink vulnerability paths.

This module ties together the call graph and taint analysis to find
complete flows from sources to sinks.
"""

import ast
import uuid
from dataclasses import dataclass, field
from typing import Optional

from tainter.core.types import (
    AnalysisResult,
    Confidence,
    Location,
    TaintFlow,
    TaintSink,
    TaintSource,
    TaintState,
)
from tainter.parser.ast_parser import FunctionInfo, ParsedModule
from tainter.graph.call_graph import CallGraph, CallGraphBuilder
from tainter.models.lang.python.sources import (
    SourceRegistry,
    create_default_registry as create_source_registry,
)
from tainter.models.lang.python.sinks import (
    SinkRegistry,
    create_default_registry as create_sink_registry,
)
from tainter.models.lang.python.sanitizers import (
    SanitizerRegistry,
    create_default_registry as create_sanitizer_registry,
)
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
        max_call_depth: int = 5,
    ):
        self.sources = source_registry or create_source_registry()
        self.sinks = sink_registry or create_sink_registry()
        self.sanitizers = sanitizer_registry or create_sanitizer_registry()
        self.max_call_depth = max_call_depth

        self.taint_tracker = TaintTracker(
            self.sources,
            self.sanitizers,
            return_taint_provider=self._resolve_call_return_taint,
        )

        # Inter-procedural bookkeeping
        self._function_index: dict[str, tuple[ParsedModule, FunctionInfo]] = {}
        self._return_cache: dict[str, Optional[TaintState]] = {}
        self._call_stack: list[str] = []
        # Track attribute taint per class for cross-method analysis
        # Key: class qualified name, Value: dict of "self.attr" -> TaintState
        self._class_attribute_taint: dict[str, dict[str, TaintState]] = {}
    
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

        # Reset all inter-procedural state for a fresh analysis run.
        self._function_index.clear()
        self._return_cache.clear()
        self._call_stack.clear()
        self._class_attribute_taint.clear()
        for module in modules:
            for func in module.functions:
                self._function_index[func.qualified_name] = (module, func)
            for cls in module.classes:
                for method in cls.methods:
                    self._function_index[method.qualified_name] = (module, method)
        
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
        
        # Analyze class methods with cross-method attribute tracking
        for cls in module.classes:
            class_qname = f"{module.module_name}.{cls.name}"
            
            # Initialize class attribute taint cache if not present
            if class_qname not in self._class_attribute_taint:
                self._class_attribute_taint[class_qname] = {}
            
            # Run multiple passes to propagate attribute taint across methods.
            # First pass discovers attributes, second pass may find flows using them.
            max_passes = 2
            for pass_num in range(max_passes):
                for method in cls.methods:
                    # Get current class attribute taint to pass to the method
                    class_attrs = self._class_attribute_taint[class_qname]
                    
                    method_flows, method_context = self._analyze_method(
                        method, module, call_graph, class_attrs
                    )
                    
                    # Only collect flows on the final pass
                    if pass_num == max_passes - 1:
                        flows.extend(method_flows)
                    
                    # Merge discovered attribute taints back to class level
                    if method_context:
                        for attr_key, taint_state in method_context.attributes.items():
                            if taint_state.is_tainted:
                                # Normalize to self.* keys (strip the receiver)
                                if attr_key.startswith("self."):
                                    self._class_attribute_taint[class_qname][attr_key] = taint_state
        
        return flows
    
    def _analyze_method(
        self,
        method: FunctionInfo,
        module: ParsedModule,
        call_graph: CallGraph,
        class_attrs: dict[str, TaintState],
    ) -> tuple[list[TaintFlow], Optional[TaintContext]]:
        """Analyze a class method with attribute taint context."""
        return self._analyze_callable(
            method,
            module,
            call_graph,
            attr_taints=class_attrs,
            seed_default_params=self._should_seed_default_params(method, call_graph),
        )
    
    def _analyze_function(
        self,
        func: FunctionInfo,
        module: ParsedModule,
        call_graph: CallGraph,
    ) -> list[TaintFlow]:
        """Analyze a function for source-to-sink flows (inter-procedural aware)."""
        flows, _ = self._analyze_callable(
            func,
            module,
            call_graph,
            seed_default_params=self._should_seed_default_params(func, call_graph),
        )
        return flows

    def _analyze_callable(
        self,
        func: FunctionInfo,
        module: ParsedModule,
        call_graph: CallGraph,
        param_taints: Optional[dict[str, TaintState]] = None,
        attr_taints: Optional[dict[str, TaintState]] = None,
        seed_default_params: bool = True,
    ) -> tuple[list[TaintFlow], Optional[TaintContext]]:
        """Analyze a function or method body under an optional incoming taint context."""
        flows: list[TaintFlow] = []

        if not func.body_ast:
            return flows, None

        self._call_stack.append(func.qualified_name)
        try:
            context, return_taint = self.taint_tracker.analyze_function(
                func,
                module,
                param_taints=param_taints,
                attr_taints=attr_taints,
                seed_default_params=seed_default_params,
            )

            # Cache only the default summary for the function. Context-sensitive analyses
            # are caller-specific and should not poison the shared cache.
            if (
                param_taints is None
                and attr_taints is None
                and return_taint
                and return_taint.is_tainted
            ):
                self._return_cache[func.qualified_name] = return_taint

            if isinstance(func.body_ast, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for stmt in ast.walk(func.body_ast):
                    if isinstance(stmt, ast.Call):
                        flows.extend(
                            self._analyze_call_site(stmt, context, module, func, call_graph)
                        )

            return flows, context
        finally:
            self._call_stack.pop()

    def _should_seed_default_params(
        self,
        func: FunctionInfo,
        call_graph: CallGraph,
    ) -> bool:
        """Treat parameters as external input only for unresolved entrypoints."""
        return not call_graph.get_callers(func.qualified_name)

    def _analyze_call_site(
        self,
        call: ast.Call,
        context: TaintContext,
        module: ParsedModule,
        func: FunctionInfo,
        call_graph: CallGraph,
    ) -> list[TaintFlow]:
        """Analyze a call for both direct sinks and nested project calls."""
        flows: list[TaintFlow] = []

        sink_flow = self._check_call_for_sink(call, context, module, func)
        if sink_flow:
            flows.append(sink_flow)

        flows.extend(self._analyze_nested_call(call, context, module, call_graph))
        return flows

    def _analyze_nested_call(
        self,
        call: ast.Call,
        context: TaintContext,
        module: ParsedModule,
        call_graph: CallGraph,
    ) -> list[TaintFlow]:
        """Propagate taint into a project-local callee and collect any nested sinks."""
        callee_qname = self._resolve_callee_name(call, module)
        if not callee_qname or callee_qname in self._call_stack:
            return []
        if len(self._call_stack) >= self.max_call_depth:
            return []

        target = self._function_index.get(callee_qname)
        if not target:
            return []

        callee_module, callee_func = target
        param_taints = self._map_args_to_params(call, context, callee_func, module, call.lineno)
        if not param_taints:
            return []

        attr_taints: Optional[dict[str, TaintState]] = None
        if callee_func.is_method:
            class_qname = callee_qname.rsplit(".", 1)[0]
            attr_taints = self._class_attribute_taint.get(class_qname)

        flows, callee_context = self._analyze_callable(
            callee_func,
            callee_module,
            call_graph,
            param_taints=param_taints,
            attr_taints=attr_taints,
            seed_default_params=False,
        )

        if callee_func.is_method and callee_context:
            class_qname = callee_qname.rsplit(".", 1)[0]
            class_attrs = self._class_attribute_taint.setdefault(class_qname, {})
            for attr_key, taint_state in callee_context.attributes.items():
                if attr_key.startswith("self.") and taint_state.is_tainted:
                    class_attrs[attr_key] = taint_state.copy()

        return flows

    # -------------------------------------------------------------
    # Inter-procedural helpers
    # -------------------------------------------------------------
    def _resolve_call_return_taint(
        self,
        call: ast.Call,
        context: TaintContext,
        module: ParsedModule,
        line: int,
    ) -> Optional[TaintState]:
        """Resolve the taint on a callee's return value, if known."""
        callee_qname = self._resolve_callee_name(call, module)
        if not callee_qname:
            return None

        # Avoid runaway recursion.
        if callee_qname in self._call_stack:
            return None

        if len(self._call_stack) >= self.max_call_depth:
            return None

        target = self._function_index.get(callee_qname)
        if not target:
            return None

        callee_module, callee_func = target
        param_taints = self._map_args_to_params(call, context, callee_func, module, line)
        use_cache = not param_taints

        # Reuse cached summary only for context-free lookups.
        if use_cache and callee_qname in self._return_cache:
            return self._return_cache[callee_qname]

        # Analyze callee with argument taints to get a precise return taint.
        self._call_stack.append(callee_qname)
        _, callee_return = self.taint_tracker.analyze_function(
            callee_func,
            callee_module,
            param_taints=param_taints,
            seed_default_params=False,
        )
        self._call_stack.pop()

        if callee_return and callee_return.is_tainted:
            if use_cache:
                self._return_cache[callee_qname] = callee_return
            return callee_return

        if use_cache:
            self._return_cache[callee_qname] = None
        return None

    def _resolve_callee_name(self, call: ast.Call, module: ParsedModule) -> Optional[str]:
        """Best-effort resolution of a call to a qualified function name."""
        # Direct name call
        if isinstance(call.func, ast.Name):
            func_name = call.func.id
            local_name = f"{module.module_name}.{func_name}"
            if local_name in self._function_index:
                return local_name

            imp = module.resolve_import(func_name)
            if imp:
                return imp.full_name

        # Attribute call (receiver.method)
        elif isinstance(call.func, ast.Attribute):
            attr = call.func.attr
            receiver = call.func.value
            # Walk down to the base name (handles both simple and chained receivers)
            base = receiver
            while isinstance(base, ast.Attribute):
                base = base.value
            if isinstance(base, ast.Name):
                imp = module.resolve_import(base.id)
                if imp:
                    return f"{imp.full_name}.{attr}"

        return None

    def _map_args_to_params(
        self,
        call: ast.Call,
        context: TaintContext,
        callee_func: FunctionInfo,
        caller_module: ParsedModule,
        line: int,
    ) -> dict[str, TaintState]:
        """Build a parameter->taint map for a callee based on call args."""
        param_taints: dict[str, TaintState] = {}

        # Positional arguments
        for idx, arg in enumerate(call.args):
            if idx < len(callee_func.parameters):
                taint = self._get_arg_taint(arg, context, caller_module)
                if taint and taint.is_tainted:
                    param_taints[callee_func.parameters[idx].name] = taint.copy()

        # Keyword arguments
        for kw in call.keywords:
            for param in callee_func.parameters:
                if param.name == kw.arg:
                    taint = self._get_arg_taint(kw.value, context, caller_module)
                    if taint and taint.is_tainted:
                        param_taints[param.name] = taint.copy()

        return param_taints
    
    def _check_call_for_sink(
        self,
        call: ast.Call,
        context: TaintContext,
        module: ParsedModule,
        func: FunctionInfo,
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

            # Fall back to keyword arguments when the vulnerable parameter is supplied by name.
            for kw in call.keywords:
                kw_taint = self._get_arg_taint(kw.value, context, module)
                if kw_taint and kw_taint.is_tainted:
                    if kw_taint.is_tainted_for(sink.vulnerability_class):
                        return self._create_flow(
                            source=kw_taint.source,
                            source_taint=kw_taint,
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
            # Alias resolution: `from subprocess import run as r` → r() matches subprocess.run
            imp = module.resolve_import(func_name)
            if imp and imp.name:
                for sink in self.sinks.get_by_module(imp.module):
                    if sink.module == imp.module and sink.function == imp.name:
                        return sink
                return None

            # Bare names only match builtins; otherwise local helpers get misclassified.
            for sink in self.sinks.get_by_module("builtins"):
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
        elif isinstance(arg, ast.Attribute):
            # Check for attribute taint (e.g., self.data)
            if isinstance(arg.value, ast.Name):
                receiver = arg.value.id
                attr_taint = context.get_attribute_taint(receiver, arg.attr)
                if attr_taint:
                    return attr_taint
            # Fall back to checking if base is tainted
            return self._get_arg_taint(arg.value, context, module)
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
        call_chain = list(self._call_stack) if self._call_stack else [func.qualified_name]
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
