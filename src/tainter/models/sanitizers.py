"""Python taint sanitizers — re-exports from lang/python/sanitizers."""

from tainter.models.lang.python.sanitizers import (
    SQL_SANITIZERS,
    GENERAL_SANITIZERS,
    get_all_sanitizers,
    create_default_registry,
)
from tainter.models.registry import SanitizerRegistry

__all__ = [
    "SQL_SANITIZERS",
    "GENERAL_SANITIZERS",
    "get_all_sanitizers",
    "create_default_registry",
    "SanitizerRegistry",
]
