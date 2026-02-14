"""JSON reporter for analysis results."""

import json
from pathlib import Path
from typing import Optional, TextIO
from tainter.core.types import AnalysisResult


class JSONReporter:
    """Outputs analysis results in JSON format."""
    
    def __init__(self, pretty: bool = True):
        self.pretty = pretty
    
    def report(
        self,
        result: AnalysisResult,
        output: Optional[TextIO] = None,
        output_path: Optional[Path] = None,
    ) -> str:
        """
        Generate JSON report.
        
        Args:
            result: Analysis result to report
            output: Optional file-like object to write to
            output_path: Optional path to write to
            
        Returns:
            JSON string
        """
        data = result.to_dict()
        
        indent = 2 if self.pretty else None
        json_str = json.dumps(data, indent=indent, default=str)
        
        if output:
            output.write(json_str)
        elif output_path:
            output_path.write_text(json_str)
        
        return json_str
