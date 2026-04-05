"""
Taint tracker for propagating taint through Python code.

This is the Python-specific analysis engine that walks Python AST nodes
and delegates to TaintPropagator for language-agnostic propagation logic.
"""

import ast
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional, Callable

from tainter.core.types import (
    TaintState, TaintSource, Sanitizer, Location, FlowStep, VulnerabilityClass
)
from tainter.parser.ast_parser import ParsedModule, FunctionInfo, CallInfo
from tainter.models.lang.python.sources import (
    SourceRegistry,
    create_default_registry as create_source_registry,
)
from tainter.models.lang.python.sanitizers import (
    SanitizerRegistry,
    create_default_registry as create_sanitizer_registry,
)


@dataclass
class TaintContext:
    """
    Context for taint analysis within a function.

    Tracks the taint state of all variables in the current scope,
    as well as object attributes (e.g., self.data).
    """

    function_name: str
    file_path: Path
    variables: dict[str, TaintState] = field(default_factory=dict)
    parameters: dict[str, TaintState] = field(default_factory=dict)
    # Track taint on object attributes like self.data, obj.field
    # Key format: "receiver.attr" e.g., "self.user_input"
    attributes: dict[str, TaintState] = field(default_factory=dict)

    def get_taint(self, var_name: str) -> Optional[TaintState]:
        """Get taint state for a variable."""
        if var_name in self.variables:
            return self.variables[var_name]
        return self.parameters.get(var_name)

    def set_taint(self, var_name: str, state: TaintState) -> None:
        """Set taint state for a variable."""
        self.variables[var_name] = state

    def get_attribute_taint(self, receiver: str, attr: str) -> Optional[TaintState]:
        """Get taint state for an object attribute like self.data."""
        key = f"{receiver}.{attr}"
        return self.attributes.get(key)

    def set_attribute_taint(self, receiver: str, attr: str, state: TaintState) -> None:
        """Set taint state for an object attribute."""
        key = f"{receiver}.{attr}"
        self.attributes[key] = state

    def is_tainted(self, var_name: str) -> bool:
        """Check if a variable is tainted."""
        state = self.get_taint(var_name)
        return state.is_tainted if state else False

    def copy(self) -> "TaintContext":
        """Create a copy of this context (for branch analysis)."""
        return TaintContext(
            function_name=self.function_name,
            file_path=self.file_path,
            variables={k: v.copy() for k, v in self.variables.items()},
            parameters={k: v.copy() for k, v in self.parameters.items()},
            attributes={k: v.copy() for k, v in self.attributes.items()},
        )

    @staticmethod
    def _merge_taint_state(
        left: Optional[TaintState],
        right: Optional[TaintState],
    ) -> Optional[TaintState]:
        """Merge two taint states conservatively at a control-flow join."""
        if left is None:
            return right.copy() if right else None
        if right is None:
            return left.copy()

        if left.is_tainted and not right.is_tainted:
            return left.copy()
        if right.is_tainted and not left.is_tainted:
            return right.copy()

        merged = left.copy()
        merged.is_tainted = left.is_tainted or right.is_tainted
        merged.sanitized_for &= right.sanitized_for

        if right.source and not merged.source:
            merged.source = right.source
        if right.source_location and not merged.source_location:
            merged.source_location = right.source_location
        if len(right.propagation_path) > len(merged.propagation_path):
            merged.propagation_path = list(right.propagation_path)

        return merged

    @classmethod
    def merge(cls, left: "TaintContext", right: "TaintContext") -> "TaintContext":
        """Merge two branch contexts conservatively."""
        merged = cls(
            function_name=left.function_name,
            file_path=left.file_path,
        )

        for key in left.variables.keys() | right.variables.keys():
            state = cls._merge_taint_state(left.variables.get(key), right.variables.get(key))
            if state is not None:
                merged.variables[key] = state

        for key in left.parameters.keys() | right.parameters.keys():
            state = cls._merge_taint_state(left.parameters.get(key), right.parameters.get(key))
            if state is not None:
                merged.parameters[key] = state

        for key in left.attributes.keys() | right.attributes.keys():
            state = cls._merge_taint_state(left.attributes.get(key), right.attributes.get(key))
            if state is not None:
                merged.attributes[key] = state

        return merged


class TaintTracker:
    """
    Python-specific taint analysis engine.

    Walks Python AST nodes and delegates to TaintPropagator for
    language-agnostic propagation logic.
    """

    def __init__(
        self,
        source_registry: Optional[SourceRegistry] = None,
        sanitizer_registry: Optional[SanitizerRegistry] = None,
        return_taint_provider: Optional[
            Callable[[ast.Call, "TaintContext", ParsedModule, int], Optional[TaintState]]
        ] = None,
    ):
        self.sources = source_registry or create_source_registry()
        self.sanitizers = sanitizer_registry or create_sanitizer_registry()
        # Optional hook that allows inter-procedural return-taint resolution.
        self._return_taint_provider = return_taint_provider

        # Shared propagation engine
        from tainter.analysis.propagation import TaintPropagator
        self._propagator = TaintPropagator(self.sources, self.sanitizers)

    def analyze_function(
        self,
        func: FunctionInfo,
        module: ParsedModule,
        param_taints: Optional[dict[str, TaintState]] = None,
        attr_taints: Optional[dict[str, TaintState]] = None,
        seed_default_params: bool = True,
    ) -> tuple[TaintContext, Optional[TaintState]]:
        """
        Analyze taint propagation within a function.

        Args:
            func: Function to analyze
            module: Module containing the function
            param_taints: Optional taint states for parameters (for inter-procedural)
            attr_taints: Optional taint states for object attributes (for cross-method tracking)

        Returns:
            TaintContext with final taint states for all variables
        """
        context = self._propagator.init_context(
            func,
            module,
            param_taints=param_taints,
            attr_taints=attr_taints,
            seed_default_params=seed_default_params,
        )

        # Get function body AST
        if not func.body_ast:
            return context, None

        # Analyze each statement
        if isinstance(func.body_ast, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for stmt in func.body_ast.body:
                self._analyze_statement(stmt, context, module)

        # Walk the full AST to find return statements (including nested in if/for/etc.)
        return_taint: Optional[TaintState] = None
        if isinstance(func.body_ast, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for node in ast.walk(func.body_ast):
                if isinstance(node, ast.Return) and node.value:
                    value_taint = self._get_expression_taint(node.value, context, module, node.lineno)
                    if value_taint and value_taint.is_tainted:
                        return_taint = value_taint.copy()
                        break

        return context, return_taint

    def _analyze_statement(
        self,
        stmt: ast.stmt,
        context: TaintContext,
        module: ParsedModule,
    ) -> None:
        """Analyze a single statement for taint propagation."""
        if isinstance(stmt, ast.Assign):
            self._analyze_assignment(stmt, context, module)
        elif isinstance(stmt, ast.AugAssign):
            self._analyze_aug_assignment(stmt, context, module)
        elif isinstance(stmt, ast.Expr):
            self._analyze_expression(stmt.value, context, module)
        elif isinstance(stmt, ast.If):
            self._analyze_if(stmt, context, module)
        elif isinstance(stmt, ast.For):
            self._analyze_for(stmt, context, module)
        elif isinstance(stmt, ast.While):
            self._analyze_while(stmt, context, module)
        elif isinstance(stmt, ast.With):
            self._analyze_with(stmt, context, module)
        elif isinstance(stmt, ast.Return):
            if stmt.value:
                self._analyze_expression(stmt.value, context, module)

    def _analyze_assignment(
        self,
        stmt: ast.Assign,
        context: TaintContext,
        module: ParsedModule,
    ) -> None:
        """Analyze assignment statement for taint propagation."""
        value_taint = self._get_expression_taint(stmt.value, context, module, stmt.lineno)

        for target in stmt.targets:
            if isinstance(target, ast.Name):
                self._propagator.propagate_assignment(
                    context, target.id, value_taint, stmt.lineno, module
                )
            elif isinstance(target, ast.Tuple):
                names = [elt.id for elt in target.elts if isinstance(elt, ast.Name)]
                self._propagator.propagate_tuple_unpack(context, names, value_taint)
            elif isinstance(target, ast.Attribute):
                receiver_name = self._get_attribute_receiver_name(target)
                if receiver_name:
                    self._propagator.propagate_field_write(
                        context, receiver_name, target.attr, value_taint, stmt.lineno, module
                    )

    def _get_attribute_receiver_name(self, attr: ast.Attribute) -> Optional[str]:
        """Extract the base receiver name from an attribute (e.g., 'self' from self.data)."""
        if isinstance(attr.value, ast.Name):
            return attr.value.id
        return None

    def _analyze_aug_assignment(
        self,
        stmt: ast.AugAssign,
        context: TaintContext,
        module: ParsedModule,
    ) -> None:
        """Analyze augmented assignment (+=, etc.) for taint propagation."""
        if isinstance(stmt.target, ast.Name):
            value_taint = self._get_expression_taint(stmt.value, context, module, stmt.lineno)
            self._propagator.propagate_aug_assignment(context, stmt.target.id, value_taint)

    def _get_expression_taint(
        self,
        expr: ast.expr,
        context: TaintContext,
        module: ParsedModule,
        line: int,
    ) -> Optional[TaintState]:
        """Determine the taint state of an expression."""
        if isinstance(expr, ast.Name):
            return context.get_taint(expr.id)

        elif isinstance(expr, ast.Call):
            return self._analyze_call_taint(expr, context, module, line)

        elif isinstance(expr, ast.Attribute):
            # Check tracked object attribute like self.data
            receiver_name = self._get_attribute_receiver_name(expr)
            if receiver_name:
                field_taint = self._propagator.propagate_field_read(
                    context, receiver_name, expr.attr
                )
                if field_taint:
                    return field_taint

            # Check for source patterns like request.args
            parts = self._build_attribute_chain(expr)
            source = self._propagator.check_source_by_parts(parts, module)
            if source:
                return self._propagator.make_source_taint(source, module.file_path, line)
            # Otherwise, check if base is tainted
            return self._get_expression_taint(expr.value, context, module, line)

        elif isinstance(expr, ast.Subscript):
            return self._get_expression_taint(expr.value, context, module, line)

        elif isinstance(expr, ast.BinOp):
            left_taint = self._get_expression_taint(expr.left, context, module, line)
            right_taint = self._get_expression_taint(expr.right, context, module, line)

            # Special case: % operator for string formatting
            if isinstance(expr.op, ast.Mod):
                if right_taint and right_taint.is_tainted:
                    return right_taint.copy()
                if isinstance(expr.right, (ast.Tuple, ast.List)):
                    for elt in expr.right.elts:
                        elt_taint = self._get_expression_taint(elt, context, module, line)
                        if elt_taint and elt_taint.is_tainted:
                            return elt_taint.copy()

            return self._propagator.propagate_binary_op(left_taint, right_taint)

        elif isinstance(expr, ast.JoinedStr):
            for value in expr.values:
                if isinstance(value, ast.FormattedValue):
                    val_taint = self._get_expression_taint(value.value, context, module, line)
                    if val_taint and val_taint.is_tainted:
                        return val_taint.copy()
            return None

        elif isinstance(expr, (ast.List, ast.Tuple, ast.Set)):
            element_taints = [
                self._get_expression_taint(elt, context, module, line) for elt in expr.elts
            ]
            return self._propagator.propagate_collection(element_taints)

        elif isinstance(expr, ast.Dict):
            for key in expr.keys:
                if key:
                    key_taint = self._get_expression_taint(key, context, module, line)
                    if key_taint and key_taint.is_tainted:
                        return key_taint.copy()
            for val in expr.values:
                val_taint = self._get_expression_taint(val, context, module, line)
                if val_taint and val_taint.is_tainted:
                    return val_taint.copy()
            return None

        return None

    def _analyze_call_taint(
        self,
        call: ast.Call,
        context: TaintContext,
        module: ParsedModule,
        line: int,
    ) -> Optional[TaintState]:
        """Analyze a function call for taint sources/sanitizers."""
        # Check if this call is a source
        source = self._check_call_for_source(call, module)
        if source:
            return self._propagator.make_source_taint(source, module.file_path, line)

        # Check if this is a sanitizer
        sanitizer = self._check_call_for_sanitizer(call, module)
        if sanitizer:
            if call.args:
                arg_taint = self._get_expression_taint(call.args[0], context, module, line)
                return self._propagator.apply_sanitizer(sanitizer, arg_taint)
            return None

        # Ask the inter-procedural provider whether this call returns taint.
        if self._return_taint_provider:
            ret_taint = self._return_taint_provider(call, context, module, line)
            if ret_taint and ret_taint.is_tainted:
                return ret_taint.copy()

        # Check for .format() calls
        if isinstance(call.func, ast.Attribute) and call.func.attr == 'format':
            for arg in call.args:
                arg_taint = self._get_expression_taint(arg, context, module, line)
                if arg_taint and arg_taint.is_tainted:
                    return arg_taint.copy()
            for kw in call.keywords:
                kw_taint = self._get_expression_taint(kw.value, context, module, line)
                if kw_taint and kw_taint.is_tainted:
                    return kw_taint.copy()

        # Conservatively propagate taint through unknown calls
        arg_taints = [
            self._get_expression_taint(arg, context, module, line) for arg in call.args
        ]
        result = self._propagator.propagate_through_args(arg_taints)
        if result:
            return result

        kw_taints = [
            self._get_expression_taint(kw.value, context, module, line) for kw in call.keywords
        ]
        return self._propagator.propagate_through_args(kw_taints)

    # ------------------------------------------------------------------
    # Python AST helpers (language-specific)
    # ------------------------------------------------------------------

    def _build_attribute_chain(self, attr: ast.Attribute) -> list[str]:
        """Build an attribute chain list, e.g. request.args -> ["request", "args"]."""
        parts: list[str] = []
        current: ast.expr = attr
        while isinstance(current, ast.Attribute):
            parts.append(current.attr)
            current = current.value
        if isinstance(current, ast.Name):
            parts.append(current.id)
        parts.reverse()
        return parts

    def _check_call_for_source(self, call: ast.Call, module: ParsedModule) -> Optional[TaintSource]:
        """Check if a function call is a taint source."""
        if isinstance(call.func, ast.Name):
            func_name = call.func.id
            result = self._propagator.check_source_by_name(func_name)
            if result:
                return result
            # Alias resolution: `from sys import argv as args` → args matches sys.argv
            imp = module.resolve_import(func_name)
            if imp and imp.name:
                for source in self.sources.all_sources():
                    if source.module == imp.module and source.function == imp.name:
                        return source
            return None

        elif isinstance(call.func, ast.Attribute):
            parts = [call.func.attr]
            current = call.func.value
            while isinstance(current, ast.Attribute):
                parts.append(current.attr)
                current = current.value
            if isinstance(current, ast.Name):
                parts.append(current.id)
            parts.reverse()
            call_chain = ".".join(parts)

            flask_patterns = [
                "request.args.get", "request.form.get", "request.values.get",
                "request.json.get", "request.cookies.get", "request.headers.get",
                "request.get_json", "request.get_data",
            ]
            for pattern in flask_patterns:
                if pattern in call_chain or call_chain.endswith(pattern.split(".")[-1]) and "request" in call_chain:
                    return TaintSource(
                        module="flask", function="request",
                        attribute=".".join(parts[1:]),
                        framework="flask",
                        description=f"User input from {call_chain}",
                    )

            django_patterns = ["GET.get", "POST.get", "COOKIES.get", "META.get"]
            for pattern in django_patterns:
                if pattern in call_chain:
                    return TaintSource(
                        module="django.http", function="request",
                        attribute=pattern, framework="django",
                        description=f"User input from {call_chain}",
                    )

        return None

    def _check_call_for_sanitizer(self, call: ast.Call, module: ParsedModule) -> Optional[Sanitizer]:
        """Check if a function call is a sanitizer."""
        if isinstance(call.func, ast.Name):
            func_name = call.func.id
            # Direct name match (e.g. escape(), int())
            result = self._propagator.check_sanitizer_by_name(func_name)
            if result:
                return result
            # Alias resolution: `from html import escape as esc` → esc() matches html.escape
            imp = module.resolve_import(func_name)
            if imp and imp.name:
                for sanitizer in self.sanitizers.all_sanitizers():
                    if sanitizer.module == imp.module and sanitizer.function == imp.name:
                        return sanitizer
            return None

        elif isinstance(call.func, ast.Attribute):
            # Module-qualified calls: html.escape(x), shlex.quote(x), django.utils.html.escape(x)
            attr_name = call.func.attr
            parts = self._build_attribute_chain(call.func)
            # Resolve the base name to its import
            if parts:
                base = parts[0]
                imp = module.resolve_import(base)
                resolved_module = imp.module if imp else base
                for sanitizer in self.sanitizers.all_sanitizers():
                    if sanitizer.function == attr_name and sanitizer.module == resolved_module:
                        return sanitizer
                    # Also match when sanitizer.module ends with the attribute chain prefix
                    # e.g. sanitizer.module="django.utils.html", chain=["django","utils","html","escape"]
                    call_chain = ".".join(parts)
                    if call_chain == sanitizer.qualified_name:
                        return sanitizer
        return None

    def _analyze_expression(
        self, expr: ast.expr, context: TaintContext, module: ParsedModule,
    ) -> None:
        """Analyze a standalone expression (mainly for side effects)."""
        self._get_expression_taint(expr, context, module, getattr(expr, 'lineno', 0))

    def _analyze_if(
        self, stmt: ast.If, context: TaintContext, module: ParsedModule,
    ) -> None:
        """Analyze if statement with basic path sensitivity."""
        then_context = context.copy()
        else_context = context.copy()

        for body_stmt in stmt.body:
            self._analyze_statement(body_stmt, then_context, module)
        for else_stmt in stmt.orelse:
            self._analyze_statement(else_stmt, else_context, module)

        merged = TaintContext.merge(then_context, else_context)
        context.variables = merged.variables
        context.parameters = merged.parameters
        context.attributes = merged.attributes

    def _analyze_for(
        self, stmt: ast.For, context: TaintContext, module: ParsedModule,
    ) -> None:
        """Analyze for loop."""
        iter_taint = self._get_expression_taint(stmt.iter, context, module, stmt.lineno)
        if iter_taint and iter_taint.is_tainted:
            if isinstance(stmt.target, ast.Name):
                context.set_taint(stmt.target.id, iter_taint.copy())
        for body_stmt in stmt.body:
            self._analyze_statement(body_stmt, context, module)

    def _analyze_while(
        self, stmt: ast.While, context: TaintContext, module: ParsedModule,
    ) -> None:
        """Analyze while loop."""
        for body_stmt in stmt.body:
            self._analyze_statement(body_stmt, context, module)

    def _analyze_with(
        self, stmt: ast.With, context: TaintContext, module: ParsedModule,
    ) -> None:
        """Analyze with statement."""
        for item in stmt.items:
            item_taint = self._get_expression_taint(item.context_expr, context, module, stmt.lineno)
            if item_taint and item_taint.is_tainted and item.optional_vars:
                if isinstance(item.optional_vars, ast.Name):
                    context.set_taint(item.optional_vars.id, item_taint.copy())
        for body_stmt in stmt.body:
            self._analyze_statement(body_stmt, context, module)
