"""Parser module for AST-based Python analysis."""

from tainter.parser.file_finder import find_python_files, ProjectFiles
from tainter.parser.ast_parser import parse_file, parse_project, ParsedModule

__all__ = [
    "find_python_files",
    "ProjectFiles",
    "parse_file",
    "parse_project",
    "ParsedModule",
]
