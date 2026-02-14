"""
Core data structures for the taint analysis engine.

These types represent the fundamental concepts used throughout the analysis:
- Locations in source code
- Sources of tainted data
- Sinks where tainted data becomes dangerous
- Sanitizers that clear taint
- Flows representing complete source-to-sink paths
"""

from dataclasses import dataclass, field
from enum import Enum, auto
from pathlib import Path
from typing import Optional


class VulnerabilityClass(Enum):
    """Categories of vulnerabilities that can be detected."""
    
    SQLI = auto()           # SQL Injection
    RCE = auto()            # Remote Code Execution
    SSTI = auto()           # Server-Side Template Injection
    SSRF = auto()           # Server-Side Request Forgery
    DESERIALIZE = auto()    # Unsafe Deserialization
    PATH_TRAVERSAL = auto() # Path Traversal / LFI
    XSS = auto()            # Cross-Site Scripting (reflected)
    LDAP_INJECTION = auto()           # LDAP Injection
    XPATH = auto()          # XPath Injection
    LOG_INJECTION = auto()
    HEADER_INJECTION = auto()
    XXE = auto()           # XML External Entity Injection
    # Log Injection / Log Forging


class Confidence(Enum):
    """Confidence level for a detected flow."""
    
    HIGH = auto()     # Strong evidence, likely true positive
    MEDIUM = auto()   # Moderate evidence, needs review
    LOW = auto()      # Weak evidence, possible false positive


@dataclass(frozen=True, slots=True)
class Location:
    """
    A specific location in source code.
    
    Attributes:
        file: Absolute path to the source file
        line: Line number (1-indexed)
        column: Column number (0-indexed), optional
        end_line: End line number for multi-line spans
        end_column: End column number for multi-line spans
    """
    
    file: Path
    line: int
    column: int = 0
    end_line: Optional[int] = None
    end_column: Optional[int] = None
    
    def __str__(self) -> str:
        """Human-readable location string."""
        return f"{self.file}:{self.line}:{self.column}"
    
    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        result = {
            "file": str(self.file),
            "line": self.line,
            "column": self.column,
        }
        if self.end_line is not None:
            result["end_line"] = self.end_line
        if self.end_column is not None:
            result["end_column"] = self.end_column
        return result


@dataclass(frozen=True, slots=True)
class FlowStep:
    """
    A single step in a taint flow path.
    
    Represents either a function call, assignment, or data transformation
    that carries tainted data from source to sink.
    
    Attributes:
        location: Where this step occurs in source code
        description: Human-readable description of what happens at this step
        variable: The variable name carrying taint at this step
        code_snippet: The actual code at this location
        function_name: Name of the function this step is in, if applicable
    """
    
    location: Location
    description: str
    variable: str
    code_snippet: str = ""
    function_name: Optional[str] = None
    
    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        result = {
            "location": self.location.to_dict(),
            "description": self.description,
            "variable": self.variable,
            "code_snippet": self.code_snippet,
        }
        if self.function_name:
            result["function_name"] = self.function_name
        return result


@dataclass(frozen=True, slots=True)
class TaintSource:
    """
    Definition of a taint source.
    
    A source is where untrusted data enters the application. This can be:
    - HTTP request parameters (Flask, Django, FastAPI)
    - Command-line input (input(), sys.argv)
    - Environment variables
    - File contents
    - Database results (in some contexts)
    - Deserialized data
    
    Attributes:
        module: Fully qualified module name (e.g., 'flask', 'django.http')
        function: Function or method name that returns tainted data
        attribute: Attribute access path (e.g., 'args.get' for request.args.get())
        returns_tainted: Whether the return value is tainted
        tainted_parameters: Which parameters receive taint (for callbacks)
        framework: Associated framework name for grouping
        description: Human-readable description
    """
    
    module: str
    function: str
    attribute: Optional[str] = None
    returns_tainted: bool = True
    tainted_parameters: tuple[int, ...] = ()
    framework: Optional[str] = None
    description: str = ""
    
    @property
    def qualified_name(self) -> str:
        """Full qualified name for matching."""
        if self.attribute:
            return f"{self.module}.{self.function}.{self.attribute}"
        return f"{self.module}.{self.function}"
    
    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "module": self.module,
            "function": self.function,
            "attribute": self.attribute,
            "returns_tainted": self.returns_tainted,
            "framework": self.framework,
            "description": self.description,
        }


@dataclass(frozen=True, slots=True)
class TaintSink:
    """
    Definition of a taint sink.
    
    A sink is a dangerous operation where tainted data can cause harm:
    - SQL query execution
    - Command execution (os.system, subprocess)
    - Template rendering
    - HTTP requests (SSRF)
    - Deserialization operations
    - File operations with user-controlled paths
    
    Attributes:
        module: Fully qualified module name
        function: Function or method name
        vulnerable_parameters: Indices of parameters that are dangerous if tainted
        vulnerability_class: Type of vulnerability this sink can cause
        description: Human-readable description
        requires_taint_on_all: If True, all vulnerable_parameters must be tainted
    """
    
    module: str
    function: str
    vulnerable_parameters: tuple[int, ...] = (0,)
    vulnerability_class: VulnerabilityClass = VulnerabilityClass.RCE
    description: str = ""
    requires_taint_on_all: bool = False
    
    @property
    def qualified_name(self) -> str:
        """Full qualified name for matching."""
        return f"{self.module}.{self.function}"
    
    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "module": self.module,
            "function": self.function,
            "vulnerable_parameters": list(self.vulnerable_parameters),
            "vulnerability_class": self.vulnerability_class.name,
            "description": self.description,
        }


@dataclass(frozen=True, slots=True)
class Sanitizer:
    """
    Definition of a sanitizer that clears taint.
    
    Sanitizers are functions or operations that make tainted data safe:
    - SQL escaping functions
    - HTML encoding
    - Input validation that restricts format
    - Type coercion (int(), strict validation)
    
    Attributes:
        module: Fully qualified module name
        function: Function or method name
        clears: Which vulnerability classes this sanitizer protects against
        clears_all: If True, clears taint for all vulnerability classes
        parameter: Which parameter is sanitized (None = return value)
        description: Human-readable description
    """
    
    module: str
    function: str
    clears: tuple[VulnerabilityClass, ...] = ()
    clears_all: bool = False
    parameter: Optional[int] = None
    description: str = ""
    
    @property
    def qualified_name(self) -> str:
        """Full qualified name for matching."""
        return f"{self.module}.{self.function}"
    
    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "module": self.module,
            "function": self.function,
            "clears": [vc.name for vc in self.clears],
            "clears_all": self.clears_all,
            "description": self.description,
        }


@dataclass(slots=True)
class TaintState:
    """
    Tracks the taint state of a variable or expression.
    
    This is a mutable class used during analysis to track how taint
    propagates through the program.
    
    Attributes:
        is_tainted: Whether this value carries taint
        source: The original source of taint, if tainted
        source_location: Where the taint was introduced
        vulnerability_classes: Which vulnerability classes this taint is relevant to
        propagation_path: List of steps showing how taint reached this point
        sanitized_for: Vulnerability classes that have been sanitized
    """
    
    is_tainted: bool = False
    source: Optional[TaintSource] = None
    source_location: Optional[Location] = None
    vulnerability_classes: set[VulnerabilityClass] = field(default_factory=set)
    propagation_path: list[FlowStep] = field(default_factory=list)
    sanitized_for: set[VulnerabilityClass] = field(default_factory=set)
    
    def is_tainted_for(self, vuln_class: VulnerabilityClass) -> bool:
        """Check if still tainted for a specific vulnerability class."""
        if not self.is_tainted:
            return False
        if vuln_class in self.sanitized_for:
            return False
        # If no specific classes set, tainted for all
        if not self.vulnerability_classes:
            return True
        return vuln_class in self.vulnerability_classes
    
    def add_step(self, step: FlowStep) -> None:
        """Add a propagation step."""
        self.propagation_path.append(step)
    
    def sanitize(self, sanitizer: Sanitizer) -> None:
        """Apply a sanitizer to clear specific taint."""
        if sanitizer.clears_all:
            self.is_tainted = False
            self.sanitized_for = set(VulnerabilityClass)
        else:
            self.sanitized_for.update(sanitizer.clears)
    
    def copy(self) -> "TaintState":
        """Create a copy of this taint state."""
        return TaintState(
            is_tainted=self.is_tainted,
            source=self.source,
            source_location=self.source_location,
            vulnerability_classes=set(self.vulnerability_classes),
            propagation_path=list(self.propagation_path),
            sanitized_for=set(self.sanitized_for),
        )


@dataclass(frozen=True, slots=True)
class TaintFlow:
    """
    A complete taint flow from source to sink.
    
    This represents a detected vulnerability path through the code,
    with full context for understanding and remediation.
    
    Attributes:
        id: Unique identifier for this flow
        source: The taint source definition
        source_location: Where the source occurs in code
        source_code: Code snippet at the source
        sink: The taint sink definition
        sink_location: Where the sink occurs in code
        sink_code: Code snippet at the sink
        steps: All intermediate steps in the flow
        call_chain: List of function names in the call path
        variable_path: List of variable names that carried taint
        vulnerability_class: The type of vulnerability
        confidence: Confidence level of this finding
        message: Human-readable description of the vulnerability
    """
    
    id: str
    source: TaintSource
    source_location: Location
    source_code: str
    sink: TaintSink
    sink_location: Location
    sink_code: str
    steps: tuple[FlowStep, ...]
    call_chain: tuple[str, ...]
    variable_path: tuple[str, ...]
    vulnerability_class: VulnerabilityClass
    confidence: Confidence
    message: str = ""
    
    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "id": self.id,
            "vulnerability_class": self.vulnerability_class.name,
            "confidence": self.confidence.name,
            "message": self.message,
            "source": {
                "definition": self.source.to_dict(),
                "location": self.source_location.to_dict(),
                "code": self.source_code,
            },
            "sink": {
                "definition": self.sink.to_dict(),
                "location": self.sink_location.to_dict(),
                "code": self.sink_code,
            },
            "steps": [step.to_dict() for step in self.steps],
            "call_chain": list(self.call_chain),
            "variable_path": list(self.variable_path),
        }


@dataclass(slots=True)
class AnalysisResult:
    """
    Result of analyzing a project.
    
    Attributes:
        flows: All detected taint flows
        files_analyzed: Number of files analyzed
        functions_analyzed: Number of functions analyzed
        errors: Any errors encountered during analysis
        duration_seconds: How long the analysis took
    """
    
    flows: list[TaintFlow] = field(default_factory=list)
    files_analyzed: int = 0
    functions_analyzed: int = 0
    errors: list[str] = field(default_factory=list)
    duration_seconds: float = 0.0
    
    @property
    def flow_count(self) -> int:
        """Total number of flows detected."""
        return len(self.flows)
    
    def flows_by_class(self, vuln_class: VulnerabilityClass) -> list[TaintFlow]:
        """Get flows for a specific vulnerability class."""
        return [f for f in self.flows if f.vulnerability_class == vuln_class]
    
    def flows_by_confidence(self, confidence: Confidence) -> list[TaintFlow]:
        """Get flows with a specific confidence level."""
        return [f for f in self.flows if f.confidence == confidence]
    
    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "summary": {
                "flows_detected": self.flow_count,
                "files_analyzed": self.files_analyzed,
                "functions_analyzed": self.functions_analyzed,
                "errors": len(self.errors),
                "duration_seconds": self.duration_seconds,
            },
            "flows": [flow.to_dict() for flow in self.flows],
            "errors": self.errors,
        }
