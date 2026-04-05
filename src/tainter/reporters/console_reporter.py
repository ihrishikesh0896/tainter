"""Console reporter with ANSI formatting."""

from typing import Optional, TextIO
import sys

from tainter.core.types import AnalysisResult, TaintFlow, Confidence, VulnerabilityClass


# ANSI color codes
class Colors:
    RED = "\033[91m"
    YELLOW = "\033[93m"
    GREEN = "\033[92m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RESET = "\033[0m"


VULN_COLORS = {
    VulnerabilityClass.SQLI: Colors.RED,
    VulnerabilityClass.RCE: Colors.RED,
    VulnerabilityClass.SSTI: Colors.RED,
    VulnerabilityClass.SSRF: Colors.YELLOW,
    VulnerabilityClass.DESERIALIZE: Colors.RED,
    VulnerabilityClass.PATH_TRAVERSAL: Colors.YELLOW,
    VulnerabilityClass.XSS: Colors.YELLOW,
}


class ConsoleReporter:
    """Outputs analysis results to console with colors."""
    
    def __init__(self, use_colors: bool = True, verbose: bool = False):
        self.use_colors = use_colors
        self.verbose = verbose
    
    def _color(self, text: str, color: str) -> str:
        if self.use_colors:
            return f"{color}{text}{Colors.RESET}"
        return text
    
    def report(self, result: AnalysisResult, output: Optional[TextIO] = None) -> None:
        """Print analysis results to console."""
        out = output or sys.stdout
        
        # Header
        out.write("\n")
        out.write(self._color("═" * 60, Colors.CYAN) + "\n")
        out.write(self._color("  TAINTER - Taint Analysis Results", Colors.BOLD) + "\n")
        out.write(self._color("═" * 60, Colors.CYAN) + "\n\n")
        
        # Summary
        out.write(self._color("📊 Summary\n", Colors.BOLD))
        out.write(f"   Files analyzed: {result.files_analyzed}\n")
        out.write(f"   Functions analyzed: {result.functions_analyzed}\n")
        if result.extension_counts:
            counts = ", ".join(
                f"{ext}:{count}" for ext, count in sorted(result.extension_counts.items())
            )
            out.write(f"   Source file counts: {counts}\n")
        if result.active_analyzers:
            active = ", ".join(result.active_analyzers)
            out.write(f"   Active analyzers: {active}\n")
        if result.detected_languages:
            detected = ", ".join(result.detected_languages)
            out.write(f"   Detected languages: {detected}\n")
        
        if result.flows:
            out.write(self._color(f"   Flows detected: {len(result.flows)}\n", Colors.RED))
        else:
            out.write(self._color("   Flows detected: 0 ✓\n", Colors.GREEN))
        
        out.write("\n")
        
        # Group flows by vulnerability class
        by_class: dict[VulnerabilityClass, list[TaintFlow]] = {}
        for flow in result.flows:
            by_class.setdefault(flow.vulnerability_class, []).append(flow)
        
        # Print each flow
        for vuln_class, flows in by_class.items():
            color = VULN_COLORS.get(vuln_class, Colors.YELLOW)
            out.write(self._color(f"🔴 {vuln_class.name} ({len(flows)} findings)\n", color + Colors.BOLD))
            out.write(self._color("─" * 50, Colors.DIM) + "\n")
            
            for flow in flows:
                self._print_flow(flow, out)
            
            out.write("\n")
        
        # Footer
        if result.errors:
            out.write(self._color(f"\n⚠️  {len(result.errors)} errors during analysis\n", Colors.YELLOW))
            if self.verbose:
                for error in result.errors:
                    out.write(f"   - {error}\n")
        if result.warnings:
            out.write(self._color(f"\n⚠️  {len(result.warnings)} warnings\n", Colors.YELLOW))
            for warning in result.warnings:
                out.write(f"   - {warning}\n")
    
    def _print_flow(self, flow: TaintFlow, out: TextIO) -> None:
        """Print a single flow."""
        conf_color = Colors.RED if flow.confidence == Confidence.HIGH else Colors.YELLOW
        
        out.write(f"\n[{self._color(flow.id, Colors.BOLD)}] ")
        out.write(self._color(f"[{flow.confidence.name}]", conf_color))
        out.write("\n")
        
        out.write(f"   {self._color('Source:', Colors.CYAN)} {flow.source_location}\n")
        out.write(f"   {self._color('Code:', Colors.DIM)} {flow.source_code[:60]}...\n" if len(flow.source_code) > 60 else f"   {self._color('Code:', Colors.DIM)} {flow.source_code}\n")
        
        out.write(f"   {self._color('Sink:', Colors.MAGENTA)} {flow.sink_location}\n")
        out.write(f"   {self._color('Code:', Colors.DIM)} {flow.sink_code[:60]}...\n" if len(flow.sink_code) > 60 else f"   {self._color('Code:', Colors.DIM)} {flow.sink_code}\n")
        
        if self.verbose and flow.steps:
            out.write(f"   {self._color('Flow path:', Colors.BLUE)}\n")
            for step in flow.steps:
                out.write(f"      → {step.variable} @ line {step.location.line}\n")
        
        out.write(f"   {self._color('Message:', Colors.WHITE)} {flow.message}\n")
