"""Core types and data structures for the taint analysis engine."""

from tainter.core.types import (
    Language,
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
    "Language",
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
