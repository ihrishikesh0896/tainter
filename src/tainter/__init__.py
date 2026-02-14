"""
Tainter - A Python taint analysis engine for identifying source-to-sink vulnerability flows.
"""

__version__ = "0.1.0"
__author__ = "Tainter Team"

from tainter.core.types import (
    TaintFlow,
    TaintSource,
    TaintSink,
    VulnerabilityClass,
    Location,
    FlowStep,
)

__all__ = [
    "__version__",
    "TaintFlow",
    "TaintSource",
    "TaintSink",
    "VulnerabilityClass",
    "Location",
    "FlowStep",
]
