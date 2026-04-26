"""
Tainter - A Python taint analysis engine for identifying source-to-sink vulnerability flows.
"""

from importlib.metadata import version as _pkg_version, PackageNotFoundError
try:
    __version__ = _pkg_version("tainter")
except PackageNotFoundError:
    __version__ = "unknown"
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
