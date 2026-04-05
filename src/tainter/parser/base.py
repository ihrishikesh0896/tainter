"""Abstract parser interface for language-specific parsing."""

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Optional

from tainter.parser.ast_parser import ParsedModule


class LanguageParser(ABC):
    """Abstract base class for language-specific parsers.

    Each supported language implements this interface to produce
    ParsedModule instances from source files.
    """

    @abstractmethod
    def can_parse(self, file_path: Path) -> bool:
        """Whether this parser can handle the given file."""
        ...

    @abstractmethod
    def parse_file(
        self, file_path: Path, project_root: Optional[Path] = None
    ) -> ParsedModule:
        """Parse a single source file into a ParsedModule."""
        ...

    @abstractmethod
    def file_extensions(self) -> tuple[str, ...]:
        """Return file extensions this parser handles (e.g., ('.py',))."""
        ...
