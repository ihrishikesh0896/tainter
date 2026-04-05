"""Python language parser implementation."""

from pathlib import Path
from typing import Optional

from tainter.parser.base import LanguageParser
from tainter.parser.ast_parser import ParsedModule, parse_file


class PythonParser(LanguageParser):
    """Parser for Python source files using the built-in ast module."""

    def can_parse(self, file_path: Path) -> bool:
        return file_path.suffix == ".py"

    def file_extensions(self) -> tuple[str, ...]:
        return (".py",)

    def parse_file(
        self, file_path: Path, project_root: Optional[Path] = None
    ) -> ParsedModule:
        return parse_file(file_path, project_root)
