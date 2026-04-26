"""
Main Tainter engine orchestrating the analysis pipeline.

This is the primary entry point for running taint analysis on a project.
"""

import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from tainter.core.types import AnalysisResult, Language, VulnerabilityClass
from tainter.parser.file_finder import ProjectFiles, find_source_files
from tainter.parser.ast_parser import ParsedModule
from tainter.parser.base import LanguageParser
from tainter.parser.python_parser import PythonParser
from tainter.parser.java_parser import JavaParser
from tainter.parser.javascript_parser import JavaScriptParser
from tainter.parser.go_parser import GoParser
from tainter.graph.call_graph import CallGraph, CallGraphBuilder
from tainter.analysis.flow_finder import FlowFinder
from tainter.analysis.java_flow_finder import JavaFlowFinder
from tainter.analysis.javascript_flow_finder import JavaScriptFlowFinder
from tainter.analysis.go_flow_finder import GoFlowFinder
from tainter.models.lang.python.sources import (
    SourceRegistry,
    create_default_registry as create_source_registry,
)
from tainter.models.lang.python.sinks import (
    SinkRegistry,
    create_default_registry as create_sink_registry,
)
from tainter.models.lang.python.sanitizers import (
    SanitizerRegistry,
    create_default_registry as create_sanitizer_registry,
)


TARGET_EXTENSION_LANGUAGE: dict[str, Language] = {
    "py": Language.PYTHON,
    "java": Language.JAVA,
    "js": Language.JAVASCRIPT,
    "go": Language.GO,
}


@dataclass
class EngineConfig:
    """Configuration for the Tainter engine."""
    
    # Vulnerability classes to scan for (None = all)
    vuln_classes: Optional[set[VulnerabilityClass]] = None
    
    # Include test files in analysis
    include_tests: bool = False
    
    # Maximum files to process
    max_files: int = 10000
    
    # Additional directories to ignore
    ignore_dirs: Optional[frozenset[str]] = None
    
    # Follow symlinks (security risk)
    follow_symlinks: bool = False
    
    # Maximum call chain depth for inter-procedural analysis
    max_call_depth: int = 10

    # Languages to parse (None = all available parsers)
    languages: Optional[frozenset[Language]] = None


class TainterEngine:
    """
    Main orchestration engine for taint analysis.
    
    Coordinates parsing, graph building, and flow detection.
    """
    
    def __init__(
        self,
        config: Optional[EngineConfig] = None,
        source_registry: Optional[SourceRegistry] = None,
        sink_registry: Optional[SinkRegistry] = None,
        sanitizer_registry: Optional[SanitizerRegistry] = None,
    ):
        self.config = config or EngineConfig()
        self.sources = source_registry or create_source_registry()
        self.sinks = sink_registry or create_sink_registry()
        self.sanitizers = sanitizer_registry or create_sanitizer_registry()

        self._parsers: dict[Language, LanguageParser] = {
            Language.PYTHON: PythonParser(),
            Language.JAVA: JavaParser(),
            Language.JAVASCRIPT: JavaScriptParser(),
            Language.GO: GoParser(),
        }
        
        self._modules: list[ParsedModule] = []
        self._call_graph: Optional[CallGraph] = None
    
    def analyze(self, project_path: Path | str) -> AnalysisResult:
        """
        Run taint analysis on a project.
        
        Args:
            project_path: Path to the project root directory
            
        Returns:
            AnalysisResult with all detected flows
        """
        start_time = time.time()
        project_path = Path(project_path).resolve()
        
        result = AnalysisResult()
        
        try:
            # Phase 1: Discover files
            project_files = self._discover_files(project_path)
            result.extension_counts = self._count_extensions(project_files)
            result.detected_languages = self._detected_language_names(result.extension_counts)
            selected_parsers = self._resolve_active_parsers(result.extension_counts)
            result.active_analyzers = [language.value for language in selected_parsers]
            result.warnings.extend(self._unsupported_language_warnings(result.extension_counts))

            if not selected_parsers:
                result.warnings.append("No active analyzers selected for discovered file types.")
                result.duration_seconds = time.time() - start_time
                return result
            
            # Phase 2: Parse all files
            self._modules = self._parse_files(project_files, result, selected_parsers)
            result.files_analyzed = len(self._modules)
            
            # Phase 3: Build call graph
            python_modules = [m for m in self._modules if m.language == Language.PYTHON]
            java_modules = [m for m in self._modules if m.language == Language.JAVA]
            js_modules = [m for m in self._modules if m.language == Language.JAVASCRIPT]
            go_modules = [m for m in self._modules if m.language == Language.GO]
            self._call_graph = self._build_call_graph(python_modules)

            # Phase 4: Find flows
            if python_modules and Language.PYTHON in selected_parsers:
                flow_finder = FlowFinder(
                    source_registry=self.sources,
                    sink_registry=self.sinks,
                    sanitizer_registry=self.sanitizers,
                    max_call_depth=self.config.max_call_depth,
                )
                python_result = flow_finder.analyze_project(python_modules, self._call_graph)
                result.flows.extend(python_result.flows)
                result.functions_analyzed += python_result.functions_analyzed

            if java_modules and Language.JAVA in selected_parsers:
                java_finder = JavaFlowFinder(max_call_depth=self.config.max_call_depth)
                java_result = java_finder.analyze_project(java_modules)
                result.flows.extend(java_result.flows)
                result.functions_analyzed += java_result.functions_analyzed

            if js_modules and Language.JAVASCRIPT in selected_parsers:
                js_finder = JavaScriptFlowFinder(max_call_depth=self.config.max_call_depth)
                js_result = js_finder.analyze_project(js_modules)
                result.flows.extend(js_result.flows)
                result.functions_analyzed += js_result.functions_analyzed

            if go_modules and Language.GO in selected_parsers:
                go_finder = GoFlowFinder(max_call_depth=self.config.max_call_depth)
                go_result = go_finder.analyze_project(go_modules)
                result.flows.extend(go_result.flows)
                result.functions_analyzed += go_result.functions_analyzed

            # Filter by vulnerability class if configured
            if self.config.vuln_classes:
                result.flows = [
                    f for f in result.flows
                    if f.vulnerability_class in self.config.vuln_classes
                ]
        
        except Exception as e:
            result.errors.append(f"Analysis failed: {str(e)}")
        
        result.duration_seconds = time.time() - start_time
        return result
    
    def _discover_files(self, project_path: Path) -> ProjectFiles:
        """Discover target language files in the project."""
        extensions = self._target_extensions_for_scan()
        return find_source_files(
            project_path,
            file_extensions=extensions,
            ignore_dirs=self.config.ignore_dirs,
            max_files=self.config.max_files,
            follow_symlinks=self.config.follow_symlinks,
        )
    
    def _parse_files(
        self,
        project_files: ProjectFiles,
        result: AnalysisResult,
        parsers: dict[Language, LanguageParser],
    ) -> list[ParsedModule]:
        """Parse all discovered source files."""
        modules: list[ParsedModule] = []
        
        for file_path in project_files:
            # Skip test files if configured
            if not self.config.include_tests:
                if self._is_test_file(file_path):
                    continue

            parser = self._select_parser(file_path, parsers)
            if not parser:
                continue
            
            try:
                module = parser.parse_file(file_path, project_files.root)
                if module.parse_errors:
                    result.errors.extend(module.parse_errors)
                else:
                    modules.append(module)
            except Exception as e:
                result.errors.append(f"Failed to parse {file_path}: {e}")
        
        return modules

    def _select_parser(
        self,
        file_path: Path,
        parsers: dict[Language, LanguageParser],
    ) -> Optional[LanguageParser]:
        """Select a parser for a file path based on active language parsers."""
        for parser in parsers.values():
            if parser.can_parse(file_path):
                return parser
        return None

    def _target_extensions_for_scan(self) -> tuple[str, ...]:
        """Get file extensions to scan for auto-selection."""
        return tuple(f".{ext}" for ext in TARGET_EXTENSION_LANGUAGE)

    def _count_extensions(self, project_files: ProjectFiles) -> dict[str, int]:
        """Count target file extensions discovered in the project."""
        counts = {ext: 0 for ext in TARGET_EXTENSION_LANGUAGE}
        for file_path in project_files.files:
            extension = file_path.suffix.lower().lstrip(".")
            if extension in counts:
                counts[extension] += 1
        return counts

    def _ranked_detected_languages(self, extension_counts: dict[str, int]) -> list[Language]:
        """Rank detected languages by file count (descending)."""
        ranked = sorted(
            (
                (ext, count, TARGET_EXTENSION_LANGUAGE[ext] in self._parsers)
                for ext, count in extension_counts.items()
                if count > 0 and ext in TARGET_EXTENSION_LANGUAGE
            ),
            key=lambda item: (-item[1], not item[2], item[0]),
        )
        return [TARGET_EXTENSION_LANGUAGE[ext] for ext, _, _ in ranked]

    def _resolve_active_parsers(
        self,
        extension_counts: dict[str, int],
    ) -> dict[Language, LanguageParser]:
        """Select active parsers using explicit config or extension-count auto-detection."""
        if self.config.languages:
            requested_languages = sorted(self.config.languages, key=lambda lang: lang.value)
            return {
                language: parser
                for language, parser in self._parsers.items()
                if language in requested_languages
            }

        detected_languages = self._ranked_detected_languages(extension_counts)
        return {
            language: self._parsers[language]
            for language in detected_languages
            if language in self._parsers
        }

    def _detected_language_names(self, extension_counts: dict[str, int]) -> list[str]:
        """Return detected language names in count-priority order."""
        return [language.value for language in self._ranked_detected_languages(extension_counts)]

    def _unsupported_language_warnings(
        self,
        extension_counts: dict[str, int],
    ) -> list[str]:
        """Warnings for detected languages that don't have analyzer implementations yet."""
        warnings: list[str] = []

        for extension, language in TARGET_EXTENSION_LANGUAGE.items():
            if extension_counts.get(extension, 0) <= 0:
                continue
            if language not in self._parsers:
                warnings.append(
                    f"Detected {extension_counts[extension]} .{extension} files "
                    f"({language.value}) but no analyzer is implemented for that language."
                )
        return warnings
    
    def _build_call_graph(self, modules: list[ParsedModule]) -> CallGraph:
        """Build call graph from parsed modules."""
        builder = CallGraphBuilder()
        for module in modules:
            builder.add_module(module)
        return builder.build()
    
    def _is_test_file(self, file_path: Path) -> bool:
        """Check if a file is a test file."""
        name = file_path.name
        parts = file_path.parts
        
        if name.startswith("test_") or name.endswith("_test.py"):
            return True
        if "tests" in parts or "test" in parts:
            return True
        
        return False
    
    @property
    def modules(self) -> list[ParsedModule]:
        """Get parsed modules (after analysis)."""
        return self._modules
    
    @property
    def call_graph(self) -> Optional[CallGraph]:
        """Get call graph (after analysis)."""
        return self._call_graph


def analyze_project(
    project_path: Path | str,
    config: Optional[EngineConfig] = None,
) -> AnalysisResult:
    """
    Convenience function to analyze a project.
    
    Args:
        project_path: Path to project root
        config: Optional configuration
        
    Returns:
        AnalysisResult with detected flows
    """
    engine = TainterEngine(config)
    return engine.analyze(project_path)
