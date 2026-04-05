"""Parser module for language-specific source analysis."""

from tainter.parser.file_finder import find_python_files, find_source_files, ProjectFiles
from tainter.parser.ast_parser import parse_file, parse_project, ParsedModule
from tainter.parser.python_parser import PythonParser
from tainter.parser.java_parser import JavaParser, parse_java_file

__all__ = [
    "find_python_files",
    "find_source_files",
    "ProjectFiles",
    "parse_file",
    "parse_java_file",
    "parse_project",
    "ParsedModule",
    "PythonParser",
    "JavaParser",
]
