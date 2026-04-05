"""
AST-based Python parser for taint analysis.

Parses Python source files into structured representations suitable for
building call graphs and performing taint analysis.
"""

import ast
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional, Iterator

from tainter.core.types import Language


@dataclass
class ImportInfo:
    """
    Information about an import statement.
    
    Attributes:
        module: The module being imported
        name: The name being imported (for 'from X import Y')
        alias: The alias used (for 'import X as Y')
        is_from_import: Whether this is a 'from X import Y' style
        line: Line number of the import
    """
    
    module: str
    name: Optional[str] = None
    alias: Optional[str] = None
    is_from_import: bool = False
    line: int = 0
    
    @property
    def local_name(self) -> str:
        """The name this import is bound to locally."""
        return self.alias or self.name or self.module.split(".")[-1]
    
    @property
    def full_name(self) -> str:
        """Full qualified name of what's imported."""
        if self.name:
            return f"{self.module}.{self.name}"
        return self.module


@dataclass
class ParameterInfo:
    """
    Information about a function parameter.
    
    Attributes:
        name: Parameter name
        annotation: Type annotation as string, if present
        default_value: Default value as string, if present
        position: Position index (0-based)
        is_args: Whether this is *args
        is_kwargs: Whether this is **kwargs
    """
    
    name: str
    annotation: Optional[str] = None
    default_value: Optional[str] = None
    position: int = 0
    is_args: bool = False
    is_kwargs: bool = False


@dataclass
class FunctionInfo:
    """
    Information about a function or method definition.
    
    Attributes:
        name: Function name
        qualified_name: Fully qualified name (including class if method)
        parameters: List of parameter information
        return_annotation: Return type annotation as string, if present
        decorators: List of decorator names
        body_ast: The AST node for the function body (for detailed analysis)
        line_start: Start line number
        line_end: End line number
        is_method: Whether this is a method (has self/cls first param)
        is_async: Whether this is an async function
        docstring: Function docstring, if present
    """
    
    name: str
    qualified_name: str
    parameters: list[ParameterInfo] = field(default_factory=list)
    return_annotation: Optional[str] = None
    decorators: list[str] = field(default_factory=list)
    body_ast: Optional[Any] = field(default=None, repr=False)
    line_start: int = 0
    line_end: int = 0
    is_method: bool = False
    is_async: bool = False
    docstring: Optional[str] = None
    
    @property
    def parameter_names(self) -> list[str]:
        """List of just parameter names."""
        return [p.name for p in self.parameters]


@dataclass
class ClassInfo:
    """
    Information about a class definition.
    
    Attributes:
        name: Class name
        qualified_name: Fully qualified name
        bases: List of base class names
        methods: Methods defined in this class
        class_variables: Class-level variable assignments
        decorators: List of decorator names
        line_start: Start line number
        line_end: End line number
        docstring: Class docstring, if present
    """
    
    name: str
    qualified_name: str
    bases: list[str] = field(default_factory=list)
    methods: list[FunctionInfo] = field(default_factory=list)
    class_variables: dict[str, str] = field(default_factory=dict)
    decorators: list[str] = field(default_factory=list)
    line_start: int = 0
    line_end: int = 0
    docstring: Optional[str] = None
    
    def get_method(self, name: str) -> Optional[FunctionInfo]:
        """Get a method by name."""
        for method in self.methods:
            if method.name == name:
                return method
        return None


@dataclass
class CallInfo:
    """
    Information about a function/method call.
    
    Attributes:
        callee: What's being called (function name or attribute chain)
        arguments: Positional argument expressions as strings
        keyword_arguments: Keyword argument name -> expression mapping
        line: Line number of the call
        column: Column offset of the call
        receiver: For method calls, the receiver object expression
    """
    
    callee: str
    arguments: list[str] = field(default_factory=list)
    keyword_arguments: dict[str, str] = field(default_factory=dict)
    line: int = 0
    column: int = 0
    receiver: Optional[str] = None
    
    @property
    def full_callee(self) -> str:
        """Full callee including receiver if present."""
        if self.receiver:
            return f"{self.receiver}.{self.callee}"
        return self.callee


@dataclass
class AssignmentInfo:
    """
    Information about a variable assignment.
    
    Attributes:
        targets: List of assignment targets (variable names)
        value_expr: The value expression as string
        value_ast: AST node of the value (for deeper analysis)
        line: Line number
        is_augmented: Whether this is an augmented assignment (+=, etc.)
    """
    
    targets: list[str] = field(default_factory=list)
    value_expr: str = ""
    value_ast: Optional[Any] = field(default=None, repr=False)
    line: int = 0
    is_augmented: bool = False


@dataclass
class ParsedModule:
    """
    A parsed Python module with extracted information.
    
    Attributes:
        file_path: Path to the source file
        module_name: Inferred module name
        imports: All imports in the module
        functions: Top-level functions
        classes: Class definitions
        global_assignments: Module-level variable assignments
        all_calls: All function/method calls in the module
        parse_errors: Any errors encountered during parsing
        source_lines: Source code split by lines (for snippets)
    """
    
    file_path: Path
    module_name: str
    imports: list[ImportInfo] = field(default_factory=list)
    functions: list[FunctionInfo] = field(default_factory=list)
    classes: list[ClassInfo] = field(default_factory=list)
    global_assignments: list[AssignmentInfo] = field(default_factory=list)
    all_calls: list[CallInfo] = field(default_factory=list)
    parse_errors: list[str] = field(default_factory=list)
    source_lines: list[str] = field(default_factory=list, repr=False)
    language: Language = Language.PYTHON
    _ast: Optional[Any] = field(default=None, repr=False)
    
    def get_function(self, name: str) -> Optional[FunctionInfo]:
        """Get a top-level function by name."""
        for func in self.functions:
            if func.name == name:
                return func
        return None
    
    def get_class(self, name: str) -> Optional[ClassInfo]:
        """Get a class by name."""
        for cls in self.classes:
            if cls.name == name:
                return cls
        return None
    
    def get_line(self, line_number: int) -> str:
        """Get source code for a specific line (1-indexed)."""
        if 1 <= line_number <= len(self.source_lines):
            return self.source_lines[line_number - 1]
        return ""
    
    def get_lines(self, start: int, end: int) -> str:
        """Get source code for a range of lines (1-indexed, inclusive)."""
        if start < 1:
            start = 1
        if end > len(self.source_lines):
            end = len(self.source_lines)
        return "\n".join(self.source_lines[start - 1:end])
    
    def resolve_import(self, name: str) -> Optional[ImportInfo]:
        """
        Resolve a local name to its import.
        
        Args:
            name: Local name used in code
            
        Returns:
            ImportInfo if this name was imported, None otherwise
        """
        for imp in self.imports:
            if imp.local_name == name:
                return imp
        return None


class ASTVisitor(ast.NodeVisitor):
    """
    AST visitor that extracts information for taint analysis.
    """
    
    def __init__(self, file_path: Path, module_name: str, source_lines: list[str]):
        self.file_path = file_path
        self.module_name = module_name
        self.source_lines = source_lines
        
        self.imports: list[ImportInfo] = []
        self.functions: list[FunctionInfo] = []
        self.classes: list[ClassInfo] = []
        self.global_assignments: list[AssignmentInfo] = []
        self.all_calls: list[CallInfo] = []
        
        # Context tracking
        self._current_class: Optional[str] = None
        self._current_function: Optional[str] = None
    
    def _get_name(self, node: ast.AST) -> str:
        """Extract a name string from various AST node types."""
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            value_name = self._get_name(node.value)
            return f"{value_name}.{node.attr}" if value_name else node.attr
        elif isinstance(node, ast.Subscript):
            return self._get_name(node.value)
        elif isinstance(node, ast.Call):
            return self._get_name(node.func)
        elif isinstance(node, ast.Constant):
            return repr(node.value)
        elif isinstance(node, ast.Starred):
            return f"*{self._get_name(node.value)}"
        else:
            return ""
    
    def _get_decorator_name(self, node: ast.expr) -> str:
        """Get the name of a decorator."""
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            return self._get_name(node)
        elif isinstance(node, ast.Call):
            return self._get_name(node.func)
        return ""
    
    def _extract_parameters(self, args: ast.arguments) -> list[ParameterInfo]:
        """Extract parameter information from function arguments."""
        params: list[ParameterInfo] = []
        
        # Calculate defaults offset
        num_defaults = len(args.defaults)
        num_args = len(args.args)
        defaults_offset = num_args - num_defaults
        
        # Regular arguments
        for i, arg in enumerate(args.args):
            default_idx = i - defaults_offset
            default_value = None
            if default_idx >= 0 and default_idx < len(args.defaults):
                default_value = self._get_name(args.defaults[default_idx])
            
            params.append(ParameterInfo(
                name=arg.arg,
                annotation=self._get_name(arg.annotation) if arg.annotation else None,
                default_value=default_value,
                position=i,
            ))
        
        # *args
        if args.vararg:
            params.append(ParameterInfo(
                name=args.vararg.arg,
                annotation=self._get_name(args.vararg.annotation) if args.vararg.annotation else None,
                position=len(args.args),
                is_args=True,
            ))
        
        # Keyword-only arguments
        for i, arg in enumerate(args.kwonlyargs):
            default_value = None
            if i < len(args.kw_defaults) and args.kw_defaults[i]:
                default_value = self._get_name(args.kw_defaults[i])
            
            params.append(ParameterInfo(
                name=arg.arg,
                annotation=self._get_name(arg.annotation) if arg.annotation else None,
                default_value=default_value,
                position=len(args.args) + (1 if args.vararg else 0) + i,
            ))
        
        # **kwargs
        if args.kwarg:
            params.append(ParameterInfo(
                name=args.kwarg.arg,
                annotation=self._get_name(args.kwarg.annotation) if args.kwarg.annotation else None,
                position=len(params),
                is_kwargs=True,
            ))
        
        return params
    
    def _extract_docstring(self, body: list[ast.stmt]) -> Optional[str]:
        """Extract docstring from function/class body."""
        if body and isinstance(body[0], ast.Expr):
            if isinstance(body[0].value, ast.Constant) and isinstance(body[0].value.value, str):
                return body[0].value.value
        return None
    
    def visit_Import(self, node: ast.Import) -> None:
        """Process import statements."""
        for alias in node.names:
            self.imports.append(ImportInfo(
                module=alias.name,
                alias=alias.asname,
                is_from_import=False,
                line=node.lineno,
            ))
        self.generic_visit(node)
    
    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        """Process from...import statements."""
        module = node.module or ""
        for alias in node.names:
            self.imports.append(ImportInfo(
                module=module,
                name=alias.name,
                alias=alias.asname,
                is_from_import=True,
                line=node.lineno,
            ))
        self.generic_visit(node)
    
    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        """Process function definitions."""
        self._process_function(node, is_async=False)
    
    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        """Process async function definitions."""
        self._process_function(node, is_async=True)
    
    def _process_function(
        self, 
        node: ast.FunctionDef | ast.AsyncFunctionDef, 
        is_async: bool
    ) -> None:
        """Process a function/method definition."""
        # Build qualified name
        if self._current_class:
            qualified_name = f"{self.module_name}.{self._current_class}.{node.name}"
        else:
            qualified_name = f"{self.module_name}.{node.name}"
        
        parameters = self._extract_parameters(node.args)
        
        # Check if method (first param is self/cls)
        is_method = (
            self._current_class is not None and 
            parameters and 
            parameters[0].name in ("self", "cls")
        )
        
        func_info = FunctionInfo(
            name=node.name,
            qualified_name=qualified_name,
            parameters=parameters,
            return_annotation=self._get_name(node.returns) if node.returns else None,
            decorators=[self._get_decorator_name(d) for d in node.decorator_list],
            body_ast=node,
            line_start=node.lineno,
            line_end=node.end_lineno or node.lineno,
            is_method=is_method,
            is_async=is_async,
            docstring=self._extract_docstring(node.body),
        )
        
        if self._current_class:
            # Add to current class's methods
            for cls in self.classes:
                if cls.name == self._current_class:
                    cls.methods.append(func_info)
                    break
        else:
            self.functions.append(func_info)
        
        # Visit function body for calls
        old_function = self._current_function
        self._current_function = node.name
        self.generic_visit(node)
        self._current_function = old_function
    
    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        """Process class definitions."""
        qualified_name = f"{self.module_name}.{node.name}"
        
        class_info = ClassInfo(
            name=node.name,
            qualified_name=qualified_name,
            bases=[self._get_name(base) for base in node.bases],
            decorators=[self._get_decorator_name(d) for d in node.decorator_list],
            line_start=node.lineno,
            line_end=node.end_lineno or node.lineno,
            docstring=self._extract_docstring(node.body),
        )
        
        self.classes.append(class_info)
        
        # Visit class body
        old_class = self._current_class
        self._current_class = node.name
        self.generic_visit(node)
        self._current_class = old_class
    
    def visit_Call(self, node: ast.Call) -> None:
        """Process function/method calls."""
        callee = self._get_name(node.func)
        receiver = None
        
        # Extract receiver for method calls
        if isinstance(node.func, ast.Attribute):
            receiver = self._get_name(node.func.value)
            callee = node.func.attr
        
        call_info = CallInfo(
            callee=callee if isinstance(node.func, ast.Attribute) else callee,
            arguments=[self._get_name(arg) for arg in node.args],
            keyword_arguments={kw.arg: self._get_name(kw.value) for kw in node.keywords if kw.arg},
            line=node.lineno,
            column=node.col_offset,
            receiver=receiver,
        )
        
        self.all_calls.append(call_info)
        self.generic_visit(node)
    
    def visit_Assign(self, node: ast.Assign) -> None:
        """Process assignment statements."""
        targets = [self._get_name(t) for t in node.targets]
        
        assignment = AssignmentInfo(
            targets=targets,
            value_expr=self._get_name(node.value),
            value_ast=node.value,
            line=node.lineno,
        )
        
        # Only track global assignments
        if self._current_function is None and self._current_class is None:
            self.global_assignments.append(assignment)
        
        self.generic_visit(node)
    
    def visit_AugAssign(self, node: ast.AugAssign) -> None:
        """Process augmented assignment statements (+=, etc.)."""
        assignment = AssignmentInfo(
            targets=[self._get_name(node.target)],
            value_expr=self._get_name(node.value),
            value_ast=node.value,
            line=node.lineno,
            is_augmented=True,
        )
        
        if self._current_function is None and self._current_class is None:
            self.global_assignments.append(assignment)
        
        self.generic_visit(node)


def infer_module_name(file_path: Path, project_root: Optional[Path] = None) -> str:
    """
    Infer module name from file path.
    
    Args:
        file_path: Path to the Python file
        project_root: Optional project root for relative naming
        
    Returns:
        Inferred module name (e.g., 'mypackage.submodule')
    """
    if project_root:
        try:
            relative = file_path.relative_to(project_root)
            parts = list(relative.parts)
        except ValueError:
            parts = [file_path.stem]
    else:
        parts = [file_path.stem]
    
    # Remove .py extension from last part
    if parts and parts[-1].endswith(".py"):
        parts[-1] = parts[-1][:-3]
    
    # Remove __init__ - it represents the package
    if parts and parts[-1] == "__init__":
        parts = parts[:-1]
    
    # Handle empty case
    if not parts:
        return file_path.stem
    
    return ".".join(parts)


def parse_file(
    file_path: Path | str, 
    project_root: Optional[Path] = None
) -> ParsedModule:
    """
    Parse a Python file and extract information for taint analysis.
    
    Args:
        file_path: Path to the Python file
        project_root: Optional project root for module name inference
        
    Returns:
        ParsedModule with extracted information
    """
    file_path = Path(file_path)
    module_name = infer_module_name(file_path, project_root)
    
    try:
        source = file_path.read_text(encoding="utf-8")
        source_lines = source.splitlines()
    except (OSError, UnicodeDecodeError) as e:
        return ParsedModule(
            file_path=file_path,
            module_name=module_name,
            parse_errors=[f"Failed to read file: {e}"],
        )
    
    try:
        tree = ast.parse(source, filename=str(file_path))
    except SyntaxError as e:
        return ParsedModule(
            file_path=file_path,
            module_name=module_name,
            source_lines=source_lines,
            parse_errors=[f"Syntax error at line {e.lineno}: {e.msg}"],
        )
    
    visitor = ASTVisitor(file_path, module_name, source_lines)
    visitor.visit(tree)
    
    return ParsedModule(
        file_path=file_path,
        module_name=module_name,
        imports=visitor.imports,
        functions=visitor.functions,
        classes=visitor.classes,
        global_assignments=visitor.global_assignments,
        all_calls=visitor.all_calls,
        source_lines=source_lines,
        _ast=tree,
    )


def parse_project(
    project_files: "ProjectFiles",
) -> Iterator[ParsedModule]:
    """
    Parse all Python files in a project.
    
    Args:
        project_files: ProjectFiles from file discovery
        
    Yields:
        ParsedModule for each file
    """
    for file_path in project_files:
        yield parse_file(file_path, project_files.root)
