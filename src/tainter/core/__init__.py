"""Core types and data structures for the taint analysis engine."""

from tainter.core.types import (
    Location,
    FlowStep,
    TaintSource,
    TaintSink,
    Sanitizer,
    TaintFlow,
    TaintState,
    VulnerabilityClass,
    Confidence,
)

__all__ = [
    "Location",
    "FlowStep",
    "TaintSource",
    "TaintSink",
    "Sanitizer",
    "TaintFlow",
    "TaintState",
    "VulnerabilityClass",
    "Confidence",
]
