"""
Command-line interface for Tainter.
"""

import sys
from pathlib import Path
from typing import Optional

import click

from tainter.engine import TainterEngine, EngineConfig
from tainter.core.types import Language, VulnerabilityClass
from tainter.parser.java_parser import JavaParser
from tainter.parser.python_parser import PythonParser
from tainter.reporters.console_reporter import ConsoleReporter
from tainter.reporters.json_reporter import JSONReporter
from tainter.reporters.sarif_reporter import SARIFReporter


VULN_CLASS_MAP = {
    "sqli": VulnerabilityClass.SQLI,
    "rce": VulnerabilityClass.RCE,
    "ssti": VulnerabilityClass.SSTI,
    "ssrf": VulnerabilityClass.SSRF,
    "deserialize": VulnerabilityClass.DESERIALIZE,
    "path-traversal": VulnerabilityClass.PATH_TRAVERSAL,
    "xss": VulnerabilityClass.XSS,
}

LANGUAGE_MAP = {
    "python": Language.PYTHON,
    "java": Language.JAVA,
    "javascript": Language.JAVASCRIPT,
    "js": Language.JAVASCRIPT,
    "go": Language.GO,
}


@click.group()
@click.version_option(version="0.1.0", prog_name="tainter")
def main():
    """Tainter - Multi-language Taint Analysis Engine
    
    Detect source-to-sink vulnerability flows in source code.
    """
    pass


@main.command()
@click.argument("path", type=click.Path(exists=True, file_okay=False, dir_okay=True))
@click.option(
    "--format", "-f",
    type=click.Choice(["console", "json", "sarif"]),
    default="console",
    help="Output format"
)
@click.option(
    "--output", "-o",
    type=click.Path(),
    default=None,
    help="Output file path (default: stdout)"
)
@click.option(
    "--vuln-class", "-v",
    multiple=True,
    type=click.Choice(list(VULN_CLASS_MAP.keys())),
    help="Vulnerability classes to scan for (default: all)"
)
@click.option(
    "--include-tests/--no-include-tests",
    default=False,
    help="Include test files in analysis"
)
@click.option(
    "--language", "-l",
    multiple=True,
    type=click.Choice(list(LANGUAGE_MAP.keys())),
    help="Languages to analyze (default: all supported)"
)
@click.option(
    "--verbose/--quiet", "-V/-q",
    default=False,
    help="Verbose output"
)
@click.option(
    "--max-files",
    type=int,
    default=10000,
    help="Maximum number of files to analyze"
)
def scan(
    path: str,
    format: str,
    output: Optional[str],
    vuln_class: tuple[str, ...],
    include_tests: bool,
    language: tuple[str, ...],
    verbose: bool,
    max_files: int,
):
    """Scan a project for vulnerability flows.
    
    PATH is the root directory of the project to scan.
    """
    project_path = Path(path).resolve()
    
    # Build configuration
    vuln_classes = None
    if vuln_class:
        vuln_classes = {VULN_CLASS_MAP[vc] for vc in vuln_class}

    languages = None
    if language:
        languages = frozenset(LANGUAGE_MAP[lang] for lang in language)
    
    config = EngineConfig(
        vuln_classes=vuln_classes,
        include_tests=include_tests,
        max_files=max_files,
        languages=languages,
    )
    
    # Run analysis
    if verbose:
        click.echo(f"🔍 Scanning {project_path}...")
    
    engine = TainterEngine(config)
    result = engine.analyze(project_path)
    
    # Generate report
    if format == "console":
        reporter = ConsoleReporter(use_colors=True, verbose=verbose)
        reporter.report(result)
    elif format == "json":
        reporter = JSONReporter(pretty=True)
        if output:
            reporter.report(result, output_path=Path(output))
            if verbose:
                click.echo(f"📄 Report written to {output}")
        else:
            click.echo(reporter.report(result))
    elif format == "sarif":
        reporter = SARIFReporter()
        if output:
            reporter.report(result, output_path=Path(output))
            if verbose:
                click.echo(f"📄 Report written to {output}")
        else:
            click.echo(reporter.report(result))
    
    # Exit with error code if flows found
    if result.flows:
        sys.exit(1)


@main.command()
@click.argument("file", type=click.Path(exists=True, file_okay=True, dir_okay=False))
@click.option("--verbose/--quiet", "-V/-q", default=False)
def parse(file: str, verbose: bool):
    """Parse a single source file and show structure.
    
    Useful for debugging and understanding what Tainter extracts.
    """
    file_path = Path(file)
    parsers = (PythonParser(), JavaParser())
    parser = next((p for p in parsers if p.can_parse(file_path)), None)
    if not parser:
        raise click.ClickException(f"Unsupported file type: {file_path.suffix}")
    module = parser.parse_file(file_path)
    
    click.echo(f"\n📄 {file_path.name}")
    click.echo(f"   Module: {module.module_name}")
    click.echo(f"   Imports: {len(module.imports)}")
    click.echo(f"   Functions: {len(module.functions)}")
    click.echo(f"   Classes: {len(module.classes)}")
    click.echo(f"   Calls: {len(module.all_calls)}")
    
    if verbose:
        if module.functions:
            click.echo("\n   Functions:")
            for func in module.functions:
                params = ", ".join(func.parameter_names)
                click.echo(f"      - {func.name}({params})")
        
        if module.classes:
            click.echo("\n   Classes:")
            for cls in module.classes:
                click.echo(f"      - {cls.name}")
                for method in cls.methods:
                    click.echo(f"         .{method.name}()")
    
    if module.parse_errors:
        click.echo(f"\n   ⚠️  Parse errors: {module.parse_errors}")


@main.command()
def list_sources():
    """List all built-in taint sources."""
    from tainter.models.lang.python.sources import get_all_sources
    
    sources = get_all_sources()
    by_framework: dict[str, list] = {}
    
    for source in sources:
        key = source.framework or "stdlib"
        by_framework.setdefault(key, []).append(source)
    
    for framework, srcs in sorted(by_framework.items()):
        click.echo(f"\n{framework.upper()}")
        click.echo("-" * 40)
        for src in srcs:
            click.echo(f"  {src.qualified_name}")


@main.command()
def list_sinks():
    """List all built-in taint sinks."""
    from tainter.models.lang.python.sinks import get_all_sinks
    
    sinks = get_all_sinks()
    by_class: dict[VulnerabilityClass, list] = {}
    
    for sink in sinks:
        by_class.setdefault(sink.vulnerability_class, []).append(sink)
    
    for vuln_class, snks in sorted(by_class.items(), key=lambda x: x[0].name):
        click.echo(f"\n{vuln_class.name}")
        click.echo("-" * 40)
        for snk in snks:
            click.echo(f"  {snk.qualified_name}")


if __name__ == "__main__":
    main()
