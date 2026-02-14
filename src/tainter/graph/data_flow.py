"""
Data flow graph for tracking variable assignments and data propagation.

Builds a graph showing how data flows between variables within and across functions.
"""

from dataclasses import dataclass, field
from enum import Enum, auto
from pathlib import Path
from typing import Optional


class FlowType(Enum):
    """Type of data flow edge."""
    ASSIGN = auto()       # Direct assignment: x = y
    CALL_ARG = auto()     # Passed as argument: func(x)
    CALL_RETURN = auto()  # Returned from call: x = func()
    ATTRIBUTE = auto()    # Attribute access: x = obj.attr
    INDEX = auto()        # Index access: x = arr[i]
    BINARY_OP = auto()    # Binary operation: x = a + b
    UNARY_OP = auto()     # Unary operation: x = -y
    PARAM = auto()        # Function parameter


@dataclass(frozen=True, slots=True)
class DataFlowNode:
    """A node representing a variable or expression in data flow."""
    
    name: str
    file_path: Path
    line: int
    column: int = 0
    function_scope: Optional[str] = None
    is_parameter: bool = False
    
    def __hash__(self) -> int:
        return hash((self.name, str(self.file_path), self.line, self.function_scope))
    
    @property
    def qualified_name(self) -> str:
        if self.function_scope:
            return f"{self.function_scope}.{self.name}"
        return self.name


@dataclass(frozen=True, slots=True)
class DataFlowEdge:
    """An edge representing data flow from source to target."""
    
    source: DataFlowNode
    target: DataFlowNode
    flow_type: FlowType
    expression: str = ""  # The full expression for context


@dataclass
class DataFlowGraph:
    """
    Graph tracking data flow between variables.
    
    Used to trace how values propagate through assignments and operations.
    """
    
    nodes: dict[str, DataFlowNode] = field(default_factory=dict)
    edges: list[DataFlowEdge] = field(default_factory=list)
    _incoming: dict[str, list[DataFlowEdge]] = field(default_factory=dict)
    _outgoing: dict[str, list[DataFlowEdge]] = field(default_factory=dict)
    
    def _node_key(self, node: DataFlowNode) -> str:
        return f"{node.qualified_name}:{node.line}"
    
    def add_node(self, node: DataFlowNode) -> None:
        key = self._node_key(node)
        self.nodes[key] = node
    
    def add_edge(self, edge: DataFlowEdge) -> None:
        self.edges.append(edge)
        source_key = self._node_key(edge.source)
        target_key = self._node_key(edge.target)
        
        self.add_node(edge.source)
        self.add_node(edge.target)
        
        self._outgoing.setdefault(source_key, []).append(edge)
        self._incoming.setdefault(target_key, []).append(edge)
    
    def get_incoming(self, node: DataFlowNode) -> list[DataFlowEdge]:
        """Get all edges flowing into this node."""
        return self._incoming.get(self._node_key(node), [])
    
    def get_outgoing(self, node: DataFlowNode) -> list[DataFlowEdge]:
        """Get all edges flowing out from this node."""
        return self._outgoing.get(self._node_key(node), [])
    
    def find_sources(self, target: DataFlowNode, max_depth: int = 20) -> list[list[DataFlowEdge]]:
        """
        Find all paths leading to a target node.
        
        Returns list of edge paths, each representing a flow from a source.
        """
        paths: list[list[DataFlowEdge]] = []
        
        def dfs(current: DataFlowNode, path: list[DataFlowEdge], visited: set[str]) -> None:
            if len(path) > max_depth:
                return
            
            incoming = self.get_incoming(current)
            if not incoming:
                if path:  # Found a source
                    paths.append(list(reversed(path)))
                return
            
            for edge in incoming:
                source_key = self._node_key(edge.source)
                if source_key not in visited:
                    visited.add(source_key)
                    path.append(edge)
                    dfs(edge.source, path, visited)
                    path.pop()
                    visited.remove(source_key)
        
        dfs(target, [], {self._node_key(target)})
        return paths
    
    @property
    def node_count(self) -> int:
        return len(self.nodes)
    
    @property
    def edge_count(self) -> int:
        return len(self.edges)
