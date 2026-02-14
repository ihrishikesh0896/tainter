"""SARIF reporter for analysis results."""

import json
from pathlib import Path
from typing import Optional, TextIO
from tainter.core.types import AnalysisResult, TaintFlow, Confidence


class SARIFReporter:
    """Outputs analysis results in SARIF format for IDE/CI integration."""
    
    SARIF_VERSION = "2.1.0"
    SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
    
    def __init__(self, tool_name: str = "Tainter", tool_version: str = "0.1.0"):
        self.tool_name = tool_name
        self.tool_version = tool_version
    
    def report(
        self,
        result: AnalysisResult,
        output: Optional[TextIO] = None,
        output_path: Optional[Path] = None,
    ) -> str:
        """Generate SARIF report."""
        sarif = {
            "$schema": self.SCHEMA,
            "version": self.SARIF_VERSION,
            "runs": [self._create_run(result)],
        }
        
        json_str = json.dumps(sarif, indent=2, default=str)
        
        if output:
            output.write(json_str)
        elif output_path:
            output_path.write_text(json_str)
        
        return json_str
    
    def _create_run(self, result: AnalysisResult) -> dict:
        """Create a SARIF run object."""
        # Collect unique rules from flows
        rules = {}
        for flow in result.flows:
            rule_id = flow.vulnerability_class.name
            if rule_id not in rules:
                rules[rule_id] = self._create_rule(flow)
        
        return {
            "tool": {
                "driver": {
                    "name": self.tool_name,
                    "version": self.tool_version,
                    "informationUri": "https://github.com/your-org/tainter",
                    "rules": list(rules.values()),
                }
            },
            "results": [self._create_result(flow) for flow in result.flows],
        }
    
    def _create_rule(self, flow: TaintFlow) -> dict:
        """Create a SARIF rule from a flow's vulnerability class."""
        vuln_class = flow.vulnerability_class
        return {
            "id": vuln_class.name,
            "name": vuln_class.name.replace("_", " ").title(),
            "shortDescription": {"text": f"Potential {vuln_class.name} vulnerability"},
            "fullDescription": {"text": f"Data from untrusted source flows to dangerous sink"},
            "defaultConfiguration": {"level": "error"},
            "properties": {"tags": ["security", "vulnerability"]},
        }
    
    def _create_result(self, flow: TaintFlow) -> dict:
        """Create a SARIF result from a flow."""
        level = "error" if flow.confidence == Confidence.HIGH else "warning"
        
        return {
            "ruleId": flow.vulnerability_class.name,
            "level": level,
            "message": {"text": flow.message},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": str(flow.sink_location.file)},
                        "region": {
                            "startLine": flow.sink_location.line,
                            "startColumn": flow.sink_location.column + 1,
                        },
                    }
                }
            ],
            "relatedLocations": [
                {
                    "id": 0,
                    "message": {"text": "Taint source"},
                    "physicalLocation": {
                        "artifactLocation": {"uri": str(flow.source_location.file)},
                        "region": {"startLine": flow.source_location.line},
                    },
                }
            ],
            "codeFlows": [self._create_code_flow(flow)],
            "properties": {
                "flowId": flow.id,
                "confidence": flow.confidence.name,
            },
        }
    
    def _create_code_flow(self, flow: TaintFlow) -> dict:
        """Create a SARIF code flow from flow steps."""
        locations = []
        
        # Add source
        locations.append({
            "location": {
                "physicalLocation": {
                    "artifactLocation": {"uri": str(flow.source_location.file)},
                    "region": {"startLine": flow.source_location.line},
                },
                "message": {"text": f"Source: {flow.source.function}"},
            }
        })
        
        # Add intermediate steps
        for step in flow.steps:
            locations.append({
                "location": {
                    "physicalLocation": {
                        "artifactLocation": {"uri": str(step.location.file)},
                        "region": {"startLine": step.location.line},
                    },
                    "message": {"text": step.description},
                }
            })
        
        # Add sink
        locations.append({
            "location": {
                "physicalLocation": {
                    "artifactLocation": {"uri": str(flow.sink_location.file)},
                    "region": {"startLine": flow.sink_location.line},
                },
                "message": {"text": f"Sink: {flow.sink.function}"},
            }
        })
        
        return {"threadFlows": [{"locations": locations}]}
