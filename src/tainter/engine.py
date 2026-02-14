"""
Main Tainter engine orchestrating the analysis pipeline.

This is the primary entry point for running taint analysis on a project.
"""

import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from tainter.core.types import AnalysisResult, VulnerabilityClass
from tainter.parser.file_finder import find_python_files, ProjectFiles
from tainter.parser.ast_parser import parse_file, ParsedModule
from tainter.graph.call_graph import CallGraph, CallGraphBuilder
from tainter.analysis.flow_finder import FlowFinder
from tainter.models.sources import SourceRegistry, create_default_registry as create_source_registry
from tainter.models.sinks import SinkRegistry, create_default_registry as create_sink_registry
from tainter.models.sanitizers import SanitizerRegistry, create_default_registry as create_sanitizer_registry


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
            
            # Phase 2: Parse all files
            self._modules = self._parse_files(project_files, result)
            result.files_analyzed = len(self._modules)
            
            # Phase 3: Build call graph
            self._call_graph = self._build_call_graph()
            
            # Phase 4: Find flows
            flow_finder = FlowFinder(
                source_registry=self.sources,
                sink_registry=self.sinks,
                sanitizer_registry=self.sanitizers,
            )
            
            flow_result = flow_finder.analyze_project(self._modules, self._call_graph)
            
            # Merge results
            result.flows = flow_result.flows
            result.functions_analyzed = flow_result.functions_analyzed
            
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
        """Discover Python files in the project."""
        return find_python_files(
            project_path,
            ignore_dirs=self.config.ignore_dirs,
            max_files=self.config.max_files,
            follow_symlinks=self.config.follow_symlinks,
        )
    
    def _parse_files(
        self,
        project_files: ProjectFiles,
        result: AnalysisResult,
    ) -> list[ParsedModule]:
        """Parse all discovered Python files."""
        modules = []
        
        for file_path in project_files:
            # Skip test files if configured
            if not self.config.include_tests:
                if self._is_test_file(file_path):
                    continue
            
            try:
                module = parse_file(file_path, project_files.root)
                if module.parse_errors:
                    result.errors.extend(module.parse_errors)
                else:
                    modules.append(module)
            except Exception as e:
                result.errors.append(f"Failed to parse {file_path}: {e}")
        
        return modules
    
    def _build_call_graph(self) -> CallGraph:
        """Build call graph from parsed modules."""
        builder = CallGraphBuilder()
        for module in self._modules:
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
