"""
Sanitizer definitions — backward-compatible re-export.

Content lives in models/lang/python/sanitizers.py.
Registry classes live in models/registry.py.
"""

from tainter.models.registry import SanitizerRegistry
from tainter.models.lang.python.sanitizers import (
    SQL_SANITIZERS,
    GENERAL_SANITIZERS,
    get_all_sanitizers,
    create_default_registry,
)

__all__ = [
    "SanitizerRegistry",
    "SQL_SANITIZERS",
    "GENERAL_SANITIZERS",
    "get_all_sanitizers",
    "create_default_registry",
]
