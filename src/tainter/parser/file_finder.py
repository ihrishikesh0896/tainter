"""
File discovery for Python projects.

Finds all Python files in a project while respecting common ignore patterns
like virtual environments, __pycache__, and build directories.
"""

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator


# Directories to always skip during file discovery
DEFAULT_IGNORE_DIRS: frozenset[str] = frozenset({
    # Virtual environments
    ".venv",
    "venv",
    "env",
    ".env",
    "virtualenv",
    # Cache and build
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    ".tox",
    "build",
    "dist",
    "*.egg-info",
    # Version control
    ".git",
    ".hg",
    ".svn",
    # IDE
    ".idea",
    ".vscode",
    # Node (in case of mixed projects)
    "node_modules",
    # Tainter agent folder
    ".agent",
})

# File patterns to ignore
DEFAULT_IGNORE_FILES: frozenset[str] = frozenset({
    "setup.py",  # Often has complex imports
    "conftest.py",  # pytest specific
})

# Maximum number of files to process (safety limit)
MAX_FILES_DEFAULT: int = 10000


@dataclass
class ProjectFiles:
    """
    Collection of Python files found in a project.
    
    Attributes:
        root: The project root directory
        files: List of Python file paths (absolute)
        ignored_dirs: Directories that were skipped
        error_paths: Paths that caused errors during discovery
    """
    
    root: Path
    files: list[Path] = field(default_factory=list)
    ignored_dirs: list[Path] = field(default_factory=list)
    error_paths: list[tuple[Path, str]] = field(default_factory=list)
    
    @property
    def file_count(self) -> int:
        """Number of Python files found."""
        return len(self.files)
    
    def relative_path(self, file: Path) -> Path:
        """Get path relative to project root."""
        try:
            return file.relative_to(self.root)
        except ValueError:
            return file
    
    def __iter__(self) -> Iterator[Path]:
        """Iterate over discovered files."""
        return iter(self.files)


def should_ignore_dir(dir_name: str, ignore_patterns: frozenset[str]) -> bool:
    """
    Check if a directory should be ignored.
    
    Args:
        dir_name: Name of the directory (not full path)
        ignore_patterns: Set of patterns to match against
        
    Returns:
        True if the directory should be skipped
    """
    # Direct match
    if dir_name in ignore_patterns:
        return True
    
    # Glob-like pattern matching for *.egg-info
    for pattern in ignore_patterns:
        if pattern.startswith("*") and dir_name.endswith(pattern[1:]):
            return True
    
    return False


def find_python_files(
    project_path: Path | str,
    ignore_dirs: frozenset[str] | None = None,
    ignore_files: frozenset[str] | None = None,
    max_files: int = MAX_FILES_DEFAULT,
    follow_symlinks: bool = False,
) -> ProjectFiles:
    """
    Find all Python files in a project directory.
    
    Recursively scans the project directory for .py files while respecting
    ignore patterns. Includes safety limits to prevent resource exhaustion.
    
    Args:
        project_path: Root directory to scan
        ignore_dirs: Additional directories to ignore (merged with defaults)
        ignore_files: Additional files to ignore (merged with defaults)
        max_files: Maximum number of files to return (safety limit)
        follow_symlinks: Whether to follow symbolic links (disabled by default for security)
        
    Returns:
        ProjectFiles containing all discovered Python files
        
    Raises:
        ValueError: If project_path doesn't exist or isn't a directory
    """
    root = Path(project_path).resolve()
    
    if not root.exists():
        raise ValueError(f"Project path does not exist: {root}")
    if not root.is_dir():
        raise ValueError(f"Project path is not a directory: {root}")
    
    # Merge ignore patterns
    all_ignore_dirs = DEFAULT_IGNORE_DIRS
    if ignore_dirs:
        all_ignore_dirs = all_ignore_dirs | ignore_dirs
    
    all_ignore_files = DEFAULT_IGNORE_FILES
    if ignore_files:
        all_ignore_files = all_ignore_files | ignore_files
    
    result = ProjectFiles(root=root)
    file_count = 0
    
    def scan_directory(current_dir: Path) -> None:
        """Recursively scan a directory for Python files."""
        nonlocal file_count
        
        if file_count >= max_files:
            return
        
        try:
            # Use scandir for efficiency
            with os.scandir(current_dir) as entries:
                dirs_to_recurse: list[Path] = []
                
                for entry in entries:
                    if file_count >= max_files:
                        return
                    
                    try:
                        # Skip symlinks if not following them (security measure)
                        if entry.is_symlink() and not follow_symlinks:
                            continue
                        
                        if entry.is_dir(follow_symlinks=follow_symlinks):
                            # Check if we should skip this directory
                            if should_ignore_dir(entry.name, all_ignore_dirs):
                                result.ignored_dirs.append(Path(entry.path))
                            else:
                                dirs_to_recurse.append(Path(entry.path))
                        
                        elif entry.is_file(follow_symlinks=follow_symlinks):
                            # Check for Python files
                            if entry.name.endswith(".py"):
                                if entry.name not in all_ignore_files:
                                    result.files.append(Path(entry.path))
                                    file_count += 1
                    
                    except (OSError, PermissionError) as e:
                        result.error_paths.append((Path(entry.path), str(e)))
                
                # Recurse into subdirectories
                for subdir in dirs_to_recurse:
                    scan_directory(subdir)
        
        except (OSError, PermissionError) as e:
            result.error_paths.append((current_dir, str(e)))
    
    scan_directory(root)
    
    # Sort files for consistent ordering
    result.files.sort()
    
    return result


def is_test_file(file_path: Path) -> bool:
    """
    Check if a file is likely a test file.
    
    Args:
        file_path: Path to check
        
    Returns:
        True if the file appears to be a test file
    """
    name = file_path.name
    parts = file_path.parts
    
    # Check filename patterns
    if name.startswith("test_") or name.endswith("_test.py"):
        return True
    
    # Check if in a tests directory
    if "tests" in parts or "test" in parts:
        return True
    
    return False


def filter_test_files(files: ProjectFiles, include_tests: bool = False) -> list[Path]:
    """
    Filter out test files from a ProjectFiles collection.
    
    Args:
        files: ProjectFiles to filter
        include_tests: If True, include test files; if False, exclude them
        
    Returns:
        Filtered list of file paths
    """
    if include_tests:
        return list(files.files)
    
    return [f for f in files.files if not is_test_file(f)]
