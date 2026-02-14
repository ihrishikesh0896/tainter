"""
Taint tracker for propagating taint through code.

This is the core analysis engine that tracks how tainted data flows through
assignments, function calls, and operations.
"""

import ast
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from tainter.core.types import (
    TaintState, TaintSource, Sanitizer, Location, FlowStep, VulnerabilityClass
)
from tainter.parser.ast_parser import ParsedModule, FunctionInfo, CallInfo
from tainter.models.sources import SourceRegistry, create_default_registry as create_source_registry
from tainter.models.sanitizers import SanitizerRegistry, create_default_registry as create_sanitizer_registry


@dataclass
class TaintContext:
    """
    Context for taint analysis within a function.
    
    Tracks the taint state of all variables in the current scope.
    """
    
    function_name: str
    file_path: Path
    variables: dict[str, TaintState] = field(default_factory=dict)
    parameters: dict[str, TaintState] = field(default_factory=dict)
    
    def get_taint(self, var_name: str) -> Optional[TaintState]:
        """Get taint state for a variable."""
        if var_name in self.variables:
            return self.variables[var_name]
        return self.parameters.get(var_name)
    
    def set_taint(self, var_name: str, state: TaintState) -> None:
        """Set taint state for a variable."""
        self.variables[var_name] = state
    
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
        )


class TaintTracker:
    """
    Core taint analysis engine.
    
    Tracks taint propagation through a function using AST analysis.
    """
    
    def __init__(
        self,
        source_registry: Optional[SourceRegistry] = None,
        sanitizer_registry: Optional[SanitizerRegistry] = None,
    ):
        self.sources = source_registry or create_source_registry()
        self.sanitizers = sanitizer_registry or create_sanitizer_registry()
    
    def analyze_function(
        self,
        func: FunctionInfo,
        module: ParsedModule,
        param_taints: Optional[dict[str, TaintState]] = None,
    ) -> TaintContext:
        """
        Analyze taint propagation within a function.
        
        Args:
            func: Function to analyze
            module: Module containing the function
            param_taints: Optional taint states for parameters (for inter-procedural)
            
        Returns:
            TaintContext with final taint states for all variables
        """
        context = TaintContext(
            function_name=func.qualified_name,
            file_path=module.file_path,
        )

        # Initialize parameter taints
        if param_taints:
            context.parameters = param_taints
        else:
            # Default to treating parameters as untrusted input so library-style
            # functions like libuser.login() are analyzed for unsafe usage.
            for param in func.parameters:
                # Skip implicit self/cls to avoid over-tainting methods.
                if param.position == 0 and param.name in {"self", "cls"}:
                    continue

                context.parameters[param.name] = TaintState(
                    is_tainted=True,
                    source=TaintSource(
                        module=module.module_name,
                        function=func.name,
                        attribute=f"param:{param.name}",
                        description="Function parameter treated as untrusted input",
                    ),
                    source_location=Location(module.file_path, func.line_start),
                )

        # Get function body AST
        if not func.body_ast:
            return context
        
        # Analyze each statement
        if isinstance(func.body_ast, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for stmt in func.body_ast.body:
                self._analyze_statement(stmt, context, module)
        
        return context
    
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
            # Expression statement (could be a call)
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
        # Determine taint of the value
        value_taint = self._get_expression_taint(stmt.value, context, module, stmt.lineno)
        
        # Propagate to all targets
        for target in stmt.targets:
            if isinstance(target, ast.Name):
                if value_taint and value_taint.is_tainted:
                    # Add propagation step
                    step = FlowStep(
                        location=Location(module.file_path, stmt.lineno),
                        description=f"Assigned to {target.id}",
                        variable=target.id,
                        code_snippet=module.get_line(stmt.lineno).strip(),
                        function_name=context.function_name,
                    )
                    value_taint.add_step(step)
                    context.set_taint(target.id, value_taint)
                else:
                    # Clear taint if value is not tainted
                    context.set_taint(target.id, TaintState())
            elif isinstance(target, ast.Tuple):
                # Handle tuple unpacking
                for elt in target.elts:
                    if isinstance(elt, ast.Name):
                        # Conservatively taint all elements
                        if value_taint and value_taint.is_tainted:
                            elem_taint = value_taint.copy()
                            context.set_taint(elt.id, elem_taint)
    
    def _analyze_aug_assignment(
        self,
        stmt: ast.AugAssign,
        context: TaintContext,
        module: ParsedModule,
    ) -> None:
        """Analyze augmented assignment (+=, etc.) for taint propagation."""
        if isinstance(stmt.target, ast.Name):
            target_name = stmt.target.id
            existing_taint = context.get_taint(target_name)
            value_taint = self._get_expression_taint(stmt.value, context, module, stmt.lineno)
            
            # If either is tainted, result is tainted
            if (existing_taint and existing_taint.is_tainted) or (value_taint and value_taint.is_tainted):
                combined = (existing_taint or TaintState()).copy()
                combined.is_tainted = True
                if value_taint and value_taint.source:
                    combined.source = value_taint.source
                context.set_taint(target_name, combined)
    
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
            # Check for source patterns like request.args
            source = self._check_for_source(expr, module)
            if source:
                return TaintState(
                    is_tainted=True,
                    source=source,
                    source_location=Location(module.file_path, line),
                )
            # Otherwise, check if base is tainted
            return self._get_expression_taint(expr.value, context, module, line)
        
        elif isinstance(expr, ast.Subscript):
            # Subscript propagates taint from the value
            return self._get_expression_taint(expr.value, context, module, line)
        
        elif isinstance(expr, ast.BinOp):
            # Binary op: tainted if either operand is tainted
            left_taint = self._get_expression_taint(expr.left, context, module, line)
            right_taint = self._get_expression_taint(expr.right, context, module, line)
            
            # Special case: % operator for string formatting ("SELECT ... %s" % (user_input,))
            if isinstance(expr.op, ast.Mod):
                # If right side (format args) is tainted, result is tainted
                if right_taint and right_taint.is_tainted:
                    return right_taint.copy()
                # Also check if it's a tuple of tainted values
                if isinstance(expr.right, (ast.Tuple, ast.List)):
                    for elt in expr.right.elts:
                        elt_taint = self._get_expression_taint(elt, context, module, line)
                        if elt_taint and elt_taint.is_tainted:
                            return elt_taint.copy()
            
            if (left_taint and left_taint.is_tainted) or (right_taint and right_taint.is_tainted):
                return (left_taint or right_taint).copy()
            return None
        
        elif isinstance(expr, ast.JoinedStr):
            # f-string: tainted if any value is tainted
            for value in expr.values:
                if isinstance(value, ast.FormattedValue):
                    val_taint = self._get_expression_taint(value.value, context, module, line)
                    if val_taint and val_taint.is_tainted:
                        return val_taint.copy()
            return None
        
        elif isinstance(expr, (ast.List, ast.Tuple, ast.Set)):
            # Collection: tainted if any element is tainted
            for elt in expr.elts:
                elt_taint = self._get_expression_taint(elt, context, module, line)
                if elt_taint and elt_taint.is_tainted:
                    return elt_taint.copy()
            return None
        
        elif isinstance(expr, ast.Dict):
            # Dict: tainted if any key or value is tainted
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
            return TaintState(
                is_tainted=True,
                source=source,
                source_location=Location(module.file_path, line),
            )
        
        # Check if this is a sanitizer
        sanitizer = self._check_call_for_sanitizer(call, module)
        if sanitizer:
            # If sanitizing a tainted value, clear appropriate classes
            if call.args:
                arg_taint = self._get_expression_taint(call.args[0], context, module, line)
                if arg_taint and arg_taint.is_tainted:
                    sanitized = arg_taint.copy()
                    sanitized.sanitize(sanitizer)
                    return sanitized
            return None
        
        # Check for .format() calls - these propagate taint from arguments
        if isinstance(call.func, ast.Attribute) and call.func.attr == 'format':
            # Check if any format arguments are tainted
            for arg in call.args:
                arg_taint = self._get_expression_taint(arg, context, module, line)
                if arg_taint and arg_taint.is_tainted:
                    return arg_taint.copy()
            # Also check keyword arguments
            for kw in call.keywords:
                kw_taint = self._get_expression_taint(kw.value, context, module, line)
                if kw_taint and kw_taint.is_tainted:
                    return kw_taint.copy()
        
        # Check if any arguments are tainted (for propagation through unknown functions)
        for arg in call.args:
            arg_taint = self._get_expression_taint(arg, context, module, line)
            if arg_taint and arg_taint.is_tainted:
                # Conservatively propagate taint through unknown calls
                return arg_taint.copy()
        
        for kw in call.keywords:
            kw_taint = self._get_expression_taint(kw.value, context, module, line)
            if kw_taint and kw_taint.is_tainted:
                return kw_taint.copy()

        return None

    def _check_for_source(self, attr: ast.Attribute, module: ParsedModule) -> Optional[TaintSource]:
        """Check if an attribute access is a taint source."""
        # Build attribute chain
        parts = []
        current = attr
        while isinstance(current, ast.Attribute):
            parts.append(current.attr)
            current = current.value

        if isinstance(current, ast.Name):
            parts.append(current.id)

        parts.reverse()

        # Check common patterns
        if len(parts) >= 2:
            base = parts[0]
            # Check if base is an imported request object
            imp = module.resolve_import(base)
            if imp:
                # Try to match source
                for source in self.sources.all_sources():
                    if source.attribute and source.attribute in ".".join(parts[1:]):
                        return source

        return None

    def _check_call_for_source(self, call: ast.Call, module: ParsedModule) -> Optional[TaintSource]:
        """Check if a function call is a taint source."""
        # Get function name
        if isinstance(call.func, ast.Name):
            func_name = call.func.id
            # Check for built-in sources like input()
            for source in self.sources.all_sources():
                if source.function == func_name:
                    return source
        elif isinstance(call.func, ast.Attribute):
            # Method call - check for patterns like request.args.get(), request.get_json()
            # Build the call chain: e.g., request.args.get -> ["request", "args", "get"]
            parts = [call.func.attr]
            current = call.func.value

            while isinstance(current, ast.Attribute):
                parts.append(current.attr)
                current = current.value

            if isinstance(current, ast.Name):
                parts.append(current.id)

            parts.reverse()
            call_chain = ".".join(parts)

            # Check for common Flask/web framework source patterns
            flask_patterns = [
                "request.args.get",
                "request.form.get",
                "request.values.get",
                "request.json.get",
                "request.cookies.get",
                "request.headers.get",
                "request.get_json",
                "request.get_data",
            ]

            for pattern in flask_patterns:
                if pattern in call_chain or call_chain.endswith(pattern.split(".")[-1]) and "request" in call_chain:
                    return TaintSource(
                        module="flask",
                        function="request",
                        attribute=".".join(parts[1:]),
                        framework="flask",
                        description=f"User input from {call_chain}",
                    )

            # Check for Django patterns
            django_patterns = ["GET.get", "POST.get", "COOKIES.get", "META.get"]
            for pattern in django_patterns:
                if pattern in call_chain:
                    return TaintSource(
                        module="django.http",
                        function="request",
                        attribute=pattern,
                        framework="django",
                        description=f"User input from {call_chain}",
                    )

        return None

    def _check_call_for_sanitizer(self, call: ast.Call, module: ParsedModule) -> Optional[Sanitizer]:
        """Check if a function call is a sanitizer."""
        if isinstance(call.func, ast.Name):
            func_name = call.func.id
            for sanitizer in self.sanitizers.all_sanitizers():
                if sanitizer.function == func_name:
                    return sanitizer
        return None

    def _analyze_expression(
        self,
        expr: ast.expr,
        context: TaintContext,
        module: ParsedModule,
    ) -> None:
        """Analyze a standalone expression (mainly for side effects)."""
        # Just check if it involves tainted data
        self._get_expression_taint(expr, context, module, getattr(expr, 'lineno', 0))

    def _analyze_if(
        self,
        stmt: ast.If,
        context: TaintContext,
        module: ParsedModule,
    ) -> None:
        """Analyze if statement with basic path sensitivity."""
        # Analyze both branches
        for body_stmt in stmt.body:
            self._analyze_statement(body_stmt, context, module)
        for else_stmt in stmt.orelse:
            self._analyze_statement(else_stmt, context, module)

    def _analyze_for(
        self,
        stmt: ast.For,
        context: TaintContext,
        module: ParsedModule,
    ) -> None:
        """Analyze for loop."""
        # Check if iterator is tainted
        iter_taint = self._get_expression_taint(stmt.iter, context, module, stmt.lineno)

        # If so, loop variable is tainted
        if iter_taint and iter_taint.is_tainted:
            if isinstance(stmt.target, ast.Name):
                context.set_taint(stmt.target.id, iter_taint.copy())

        for body_stmt in stmt.body:
            self._analyze_statement(body_stmt, context, module)

    def _analyze_while(
        self,
        stmt: ast.While,
        context: TaintContext,
        module: ParsedModule,
    ) -> None:
        """Analyze while loop."""
        for body_stmt in stmt.body:
            self._analyze_statement(body_stmt, context, module)

    def _analyze_with(
        self,
        stmt: ast.With,
        context: TaintContext,
        module: ParsedModule,
    ) -> None:
        """Analyze with statement."""
        for item in stmt.items:
            item_taint = self._get_expression_taint(item.context_expr, context, module, stmt.lineno)
            if item_taint and item_taint.is_tainted and item.optional_vars:
                if isinstance(item.optional_vars, ast.Name):
                    context.set_taint(item.optional_vars.id, item_taint.copy())

        for body_stmt in stmt.body:
            self._analyze_statement(body_stmt, context, module)
