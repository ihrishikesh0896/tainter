"""
Call graph construction for inter-procedural analysis.

Builds a graph of function calls to track how data flows between functions.
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, Iterator

from tainter.parser.ast_parser import ParsedModule, FunctionInfo, CallInfo


@dataclass(frozen=True, slots=True)
class CallNode:
    """A node in the call graph representing a function/method."""
    
    qualified_name: str
    file_path: Path
    line_start: int
    line_end: int
    is_method: bool = False
    class_name: Optional[str] = None
    
    def __hash__(self) -> int:
        return hash(self.qualified_name)
    
    def __eq__(self, other: object) -> bool:
        if not isinstance(other, CallNode):
            return False
        return self.qualified_name == other.qualified_name


@dataclass(frozen=True, slots=True)
class CallEdge:
    """An edge representing a function call from caller to callee."""
    
    caller: CallNode
    callee: str  # Qualified name of callee (may be unresolved)
    callee_node: Optional[CallNode]  # Resolved callee node if found
    line: int
    column: int
    arguments: tuple[str, ...]
    
    @property
    def is_resolved(self) -> bool:
        """Whether the callee was resolved to a known function."""
        return self.callee_node is not None


@dataclass
class CallGraph:
    """
    A call graph representing function calls in a project.
    
    Provides efficient lookup for:
    - What functions does this function call? (callees)
    - What functions call this function? (callers)
    """
    
    nodes: dict[str, CallNode] = field(default_factory=dict)
    edges: list[CallEdge] = field(default_factory=list)
    _callers: dict[str, list[CallEdge]] = field(default_factory=dict)
    _callees: dict[str, list[CallEdge]] = field(default_factory=dict)
    
    def add_node(self, node: CallNode) -> None:
        """Add a function node to the graph."""
        self.nodes[node.qualified_name] = node
    
    def add_edge(self, edge: CallEdge) -> None:
        """Add a call edge to the graph."""
        self.edges.append(edge)
        
        # Index by caller
        self._callees.setdefault(edge.caller.qualified_name, []).append(edge)
        
        # Index by callee if resolved
        if edge.callee_node:
            self._callers.setdefault(edge.callee_node.qualified_name, []).append(edge)
    
    def get_node(self, qualified_name: str) -> Optional[CallNode]:
        """Get a node by qualified name."""
        return self.nodes.get(qualified_name)
    
    def get_callers(self, qualified_name: str) -> list[CallEdge]:
        """Get all edges where this function is called."""
        return self._callers.get(qualified_name, [])
    
    def get_callees(self, qualified_name: str) -> list[CallEdge]:
        """Get all edges where this function calls others."""
        return self._callees.get(qualified_name, [])
    
    def find_paths(
        self, 
        start: str, 
        end: str, 
        max_depth: int = 10
    ) -> Iterator[list[CallEdge]]:
        """
        Find all call paths from start to end function.
        
        Args:
            start: Qualified name of start function
            end: Qualified name of end function
            max_depth: Maximum call chain depth
            
        Yields:
            Lists of edges representing paths from start to end
        """
        def dfs(current: str, path: list[CallEdge], visited: set[str]) -> Iterator[list[CallEdge]]:
            if len(path) > max_depth:
                return
            
            if current == end:
                yield list(path)
                return
            
            for edge in self.get_callees(current):
                callee_name = edge.callee_node.qualified_name if edge.callee_node else edge.callee
                if callee_name not in visited:
                    visited.add(callee_name)
                    path.append(edge)
                    yield from dfs(callee_name, path, visited)
                    path.pop()
                    visited.remove(callee_name)
        
        if start in self.nodes:
            yield from dfs(start, [], {start})
    
    @property
    def node_count(self) -> int:
        return len(self.nodes)
    
    @property
    def edge_count(self) -> int:
        return len(self.edges)


class CallGraphBuilder:
    """Builds a call graph from parsed modules."""
    
    def __init__(self) -> None:
        self.graph = CallGraph()
        self._modules: dict[str, ParsedModule] = {}
        self._function_index: dict[str, FunctionInfo] = {}
    
    def add_module(self, module: ParsedModule) -> None:
        """Add a parsed module to the builder."""
        self._modules[module.module_name] = module
        
        # Index all functions
        for func in module.functions:
            self._function_index[func.qualified_name] = func
            self.graph.add_node(CallNode(
                qualified_name=func.qualified_name,
                file_path=module.file_path,
                line_start=func.line_start,
                line_end=func.line_end,
                is_method=func.is_method,
            ))
        
        # Index class methods
        for cls in module.classes:
            for method in cls.methods:
                self._function_index[method.qualified_name] = method
                self.graph.add_node(CallNode(
                    qualified_name=method.qualified_name,
                    file_path=module.file_path,
                    line_start=method.line_start,
                    line_end=method.line_end,
                    is_method=True,
                    class_name=cls.name,
                ))
    
    def build(self) -> CallGraph:
        """Build the call graph by resolving all calls."""
        for module in self._modules.values():
            self._process_module_calls(module)
        return self.graph
    
    def _process_module_calls(self, module: ParsedModule) -> None:
        """Process all calls in a module."""
        # Group calls by their containing function
        for func in module.functions:
            self._process_function_calls(module, func)
        
        for cls in module.classes:
            for method in cls.methods:
                self._process_function_calls(module, method)
    
    def _process_function_calls(self, module: ParsedModule, func: FunctionInfo) -> None:
        """Process calls within a function."""
        caller_node = self.graph.get_node(func.qualified_name)
        if not caller_node:
            return
        
        # Find calls within this function's line range
        for call in module.all_calls:
            if func.line_start <= call.line <= func.line_end:
                callee_name = self._resolve_callee(module, call)
                callee_node = self.graph.get_node(callee_name) if callee_name else None
                
                edge = CallEdge(
                    caller=caller_node,
                    callee=call.full_callee,
                    callee_node=callee_node,
                    line=call.line,
                    column=call.column,
                    arguments=tuple(call.arguments),
                )
                self.graph.add_edge(edge)
    
    def _resolve_callee(self, module: ParsedModule, call: CallInfo) -> Optional[str]:
        """Attempt to resolve a call to a qualified function name."""
        callee = call.full_callee
        
        # Check if it's a local function
        local_name = f"{module.module_name}.{call.callee}"
        if local_name in self._function_index:
            return local_name
        
        # Check imports
        if call.receiver:
            # Method call - check if receiver is an imported module
            imp = module.resolve_import(call.receiver)
            if imp:
                return f"{imp.full_name}.{call.callee}"
        else:
            # Direct call - check if function is imported
            imp = module.resolve_import(call.callee)
            if imp:
                return imp.full_name
        
        # Check in other modules
        for mod_name, mod in self._modules.items():
            for func in mod.functions:
                if func.name == call.callee:
                    return func.qualified_name
        
        return None
