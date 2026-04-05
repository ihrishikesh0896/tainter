"""
Shared taint propagation logic.

This module contains language-agnostic taint propagation rules.
Language-specific taint trackers translate AST nodes into semantic events
and delegate to TaintPropagator for the actual propagation logic.
"""

from typing import Optional

from tainter.core.types import (
    TaintState, TaintSource, Sanitizer, Location, FlowStep, VulnerabilityClass
)
from tainter.parser.ast_parser import ParsedModule, FunctionInfo
from tainter.analysis.taint_tracker import TaintContext
from tainter.models.lang.python.sources import (
    SourceRegistry,
    create_default_registry as create_source_registry,
)
from tainter.models.lang.python.sanitizers import (
    SanitizerRegistry,
    create_default_registry as create_sanitizer_registry,
)


class TaintPropagator:
    """Language-agnostic taint propagation engine.

    Language-specific trackers extract semantic events from their AST
    and call these methods to perform the actual taint propagation.
    """

    def __init__(
        self,
        source_registry: Optional[SourceRegistry] = None,
        sanitizer_registry: Optional[SanitizerRegistry] = None,
    ):
        self.sources = source_registry or create_source_registry()
        self.sanitizers = sanitizer_registry or create_sanitizer_registry()

    # ------------------------------------------------------------------
    # Assignment propagation
    # ------------------------------------------------------------------

    def propagate_assignment(
        self,
        context: TaintContext,
        target_name: str,
        value_taint: Optional[TaintState],
        line: int,
        module: ParsedModule,
    ) -> None:
        """Propagate taint through a simple variable assignment: target = value."""
        if value_taint and value_taint.is_tainted:
            step = FlowStep(
                location=Location(module.file_path, line),
                description=f"Assigned to {target_name}",
                variable=target_name,
                code_snippet=module.get_line(line).strip(),
                function_name=context.function_name,
            )
            value_taint.add_step(step)
            context.set_taint(target_name, value_taint)
        else:
            context.set_taint(target_name, TaintState())

    def propagate_tuple_unpack(
        self,
        context: TaintContext,
        element_names: list[str],
        value_taint: Optional[TaintState],
    ) -> None:
        """Propagate taint through tuple unpacking: a, b = value."""
        if value_taint and value_taint.is_tainted:
            for name in element_names:
                context.set_taint(name, value_taint.copy())

    def propagate_field_write(
        self,
        context: TaintContext,
        receiver: str,
        field: str,
        value_taint: Optional[TaintState],
        line: int,
        module: ParsedModule,
    ) -> None:
        """Propagate taint through field assignment: receiver.field = value."""
        if value_taint and value_taint.is_tainted:
            attr_path = f"{receiver}.{field}"
            step = FlowStep(
                location=Location(module.file_path, line),
                description=f"Assigned to {attr_path}",
                variable=attr_path,
                code_snippet=module.get_line(line).strip(),
                function_name=context.function_name,
            )
            value_taint.add_step(step)
            context.set_attribute_taint(receiver, field, value_taint)
        else:
            context.set_attribute_taint(receiver, field, TaintState())

    def propagate_aug_assignment(
        self,
        context: TaintContext,
        target_name: str,
        value_taint: Optional[TaintState],
    ) -> None:
        """Propagate taint through augmented assignment: target += value."""
        existing_taint = context.get_taint(target_name)
        if (existing_taint and existing_taint.is_tainted) or (
            value_taint and value_taint.is_tainted
        ):
            combined = (existing_taint or TaintState()).copy()
            combined.is_tainted = True
            if value_taint and value_taint.source:
                combined.source = value_taint.source
            context.set_taint(target_name, combined)

    # ------------------------------------------------------------------
    # Expression taint
    # ------------------------------------------------------------------

    def propagate_field_read(
        self, context: TaintContext, receiver: str, field: str
    ) -> Optional[TaintState]:
        """Get taint for reading receiver.field (e.g., self.data)."""
        attr_taint = context.get_attribute_taint(receiver, field)
        if attr_taint and attr_taint.is_tainted:
            return attr_taint.copy()
        return None

    def propagate_binary_op(
        self,
        left_taint: Optional[TaintState],
        right_taint: Optional[TaintState],
    ) -> Optional[TaintState]:
        """Taint from a binary operation (e.g., a + b)."""
        if (left_taint and left_taint.is_tainted) or (
            right_taint and right_taint.is_tainted
        ):
            return (left_taint or right_taint).copy()  # type: ignore[union-attr]
        return None

    def propagate_collection(
        self, element_taints: list[Optional[TaintState]]
    ) -> Optional[TaintState]:
        """Taint from a collection literal — tainted if any element is tainted."""
        for taint in element_taints:
            if taint and taint.is_tainted:
                return taint.copy()
        return None

    # ------------------------------------------------------------------
    # Source / sanitizer matching
    # ------------------------------------------------------------------

    def check_source_by_name(self, func_name: str) -> Optional[TaintSource]:
        """Check if a simple function name matches a source (e.g., input())."""
        for source in self.sources.all_sources():
            if source.function == func_name:
                return source
        return None

    def check_source_by_parts(
        self, parts: list[str], module: ParsedModule
    ) -> Optional[TaintSource]:
        """Check if an attribute chain matches a taint source.

        Args:
            parts: Attribute chain as list, e.g. ["request", "args"] for request.args
            module: Module for import resolution
        """
        if len(parts) < 2:
            return None

        base = parts[0]
        attr_chain = ".".join(parts[1:])

        # Strategy 1: base is a resolved import (e.g. `from flask import request`)
        imp = module.resolve_import(base)
        if imp:
            for source in self.sources.all_sources():
                if source.attribute and source.attribute in attr_chain:
                    return source

        # Strategy 2: base is a well-known request parameter name (Django/Flask views
        # receive `request` as a function parameter, not an import). Match by the
        # source's function name matching the base variable name.
        # e.g. base="request", parts=["request","GET"] → source.function="HttpRequest", attribute="GET"
        for source in self.sources.all_sources():
            if source.attribute and source.attribute in attr_chain:
                # Accept if the base variable name matches common request var names
                # OR if the source function name (lowercased) contains the base name
                if base in ("request", "req") or source.function.lower() == base.lower():
                    return source

        return None

    def check_sanitizer_by_name(self, func_name: str) -> Optional[Sanitizer]:
        """Check if a simple function name matches a sanitizer."""
        for sanitizer in self.sanitizers.all_sanitizers():
            if sanitizer.function == func_name:
                return sanitizer
        return None

    def make_source_taint(
        self, source: TaintSource, file_path, line: int
    ) -> TaintState:
        """Create a TaintState from a detected source."""
        return TaintState(
            is_tainted=True,
            source=source,
            source_location=Location(file_path, line),
        )

    def apply_sanitizer(
        self, sanitizer: Sanitizer, arg_taint: Optional[TaintState]
    ) -> Optional[TaintState]:
        """Apply a sanitizer to a tainted argument. Returns sanitized taint or None."""
        if arg_taint and arg_taint.is_tainted:
            sanitized = arg_taint.copy()
            sanitized.sanitize(sanitizer)
            return sanitized
        return None

    def propagate_through_args(
        self, arg_taints: list[Optional[TaintState]]
    ) -> Optional[TaintState]:
        """Conservatively propagate taint through an unknown function call.

        If any argument is tainted, the return value is considered tainted.
        """
        for taint in arg_taints:
            if taint and taint.is_tainted:
                return taint.copy()
        return None

    # ------------------------------------------------------------------
    # Parameter initialization
    # ------------------------------------------------------------------

    def init_param_taints(
        self,
        func: FunctionInfo,
        module: ParsedModule,
        implicit_self_names: frozenset[str] = frozenset({"self", "cls"}),
    ) -> dict[str, TaintState]:
        """Create default parameter taints (treat all non-self params as untrusted)."""
        taints: dict[str, TaintState] = {}
        for param in func.parameters:
            if param.position == 0 and param.name in implicit_self_names:
                continue
            taints[param.name] = TaintState(
                is_tainted=True,
                source=TaintSource(
                    module=module.module_name,
                    function=func.name,
                    attribute=f"param:{param.name}",
                    description="Function parameter treated as untrusted input",
                ),
                source_location=Location(module.file_path, func.line_start),
            )
        return taints

    def init_context(
        self,
        func: FunctionInfo,
        module: ParsedModule,
        param_taints: Optional[dict[str, TaintState]] = None,
        attr_taints: Optional[dict[str, TaintState]] = None,
        seed_default_params: bool = True,
    ) -> TaintContext:
        """Create and initialize a TaintContext for a function."""
        context = TaintContext(
            function_name=func.qualified_name,
            file_path=module.file_path,
        )
        if attr_taints:
            for key, taint in attr_taints.items():
                context.attributes[key] = taint.copy()
        if param_taints:
            context.parameters = param_taints
        elif seed_default_params:
            context.parameters = self.init_param_taints(func, module)
        else:
            context.parameters = {}
        return context
