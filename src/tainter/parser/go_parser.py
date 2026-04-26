"""Go language parser implementation."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Optional

from tainter.core.types import Language
from tainter.parser.ast_parser import (
    CallInfo,
    FunctionInfo,
    ImportInfo,
    ParameterInfo,
    ParsedModule,
    infer_module_name,
)
from tainter.parser.base import LanguageParser

# package declaration: `package main`
_GO_PACKAGE_RE = re.compile(r"^\s*package\s+(\w+)")

# single import: `import "pkg/path"`
_GO_IMPORT_SINGLE_RE = re.compile(r"""^\s*import\s+(?:\w+\s+)?["']([^"']+)["']""")

# individual import line inside a grouped import block: optional alias then path
_GO_IMPORT_LINE_RE = re.compile(r"""^\s*(?:\w+\s+)?["']([^"']+)["']""")

# regular function: func FuncName(params) [returnType] {
_GO_FUNC_RE = re.compile(
    r"""^\s*func\s+(\w+)\s*\(([^)]*)\)"""
)

# method with receiver: func (recv RecvType) MethodName(params) [returnType] {
_GO_METHOD_RE = re.compile(
    r"""^\s*func\s+\(\s*\w+\s+\*?(\w+)\s*\)\s+(\w+)\s*\(([^)]*)\)"""
)

# call expressions: receiver.Method( or pkg.Func(
_GO_CALL_RE = re.compile(r"([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)\s*\(")

# grouped import block start
_GO_IMPORT_BLOCK_START_RE = re.compile(r"^\s*import\s*\(")

# grouped import block end
_GO_IMPORT_BLOCK_END_RE = re.compile(r"^\s*\)")

_GO_KEYWORDS = {
    "if", "for", "range", "switch", "select", "case", "return", "go",
    "defer", "break", "continue", "fallthrough", "default", "else",
    "func", "type", "struct", "interface", "map", "chan", "make", "new",
    "len", "cap", "append", "copy", "delete", "panic", "recover", "close",
    "print", "println",
}


def _parse_go_parameters(param_blob: str) -> list[ParameterInfo]:
    params: list[ParameterInfo] = []
    if not param_blob.strip():
        return params
    position = 0
    for chunk in param_blob.split(","):
        part = chunk.strip()
        if not part:
            continue
        # Strip pointer/variadic prefixes from the type token
        tokens = part.split()
        if not tokens:
            continue
        # If only one token (type, no name) or last token looks like a type,
        # take the first token as the name if there are two+ tokens.
        if len(tokens) >= 2:
            name = tokens[0].lstrip("*").strip()
            # Join remaining tokens as the type annotation
            annotation: Optional[str] = " ".join(tokens[1:])
        else:
            # Single token — likely a type-only param; use positional placeholder
            name = f"_p{position}"
            annotation = tokens[0] if tokens else None
        if name and re.match(r"[A-Za-z_]\w*", name):
            params.append(ParameterInfo(name=name, annotation=annotation, position=position))
        position += 1
    return params


def _find_block_end(source_lines: list[str], start_index: int) -> int:
    """Return the 1-based end line of the brace-delimited block starting at start_index."""
    depth = 0
    seen_open = False
    for idx in range(start_index, len(source_lines)):
        for char in source_lines[idx]:
            if char == "{":
                depth += 1
                seen_open = True
            elif char == "}" and seen_open:
                depth -= 1
                if depth == 0:
                    return idx + 1
    return start_index + 1


def _extract_calls(
    source_lines: list[str], start_line: int, end_line: int
) -> list[CallInfo]:
    """Extract approximate function/method calls from a Go source range."""
    calls: list[CallInfo] = []
    for line_no in range(start_line, min(end_line + 1, len(source_lines) + 1)):
        line = source_lines[line_no - 1]
        for match in _GO_CALL_RE.finditer(line):
            full = match.group(1)
            if full in _GO_KEYWORDS:
                continue
            if "." in full:
                receiver, callee = full.rsplit(".", 1)
            else:
                receiver, callee = None, full
            if callee in _GO_KEYWORDS:
                continue
            calls.append(
                CallInfo(
                    callee=callee,
                    line=line_no,
                    column=match.start(1),
                    receiver=receiver,
                )
            )
    return calls


def parse_go_file(
    file_path: Path | str, project_root: Optional[Path] = None
) -> ParsedModule:
    """Parse a Go source file into a ParsedModule."""
    file_path = Path(file_path)
    fallback_module = infer_module_name(file_path, project_root)

    try:
        source = file_path.read_text(encoding="utf-8")
        source_lines = source.splitlines()
    except (OSError, UnicodeDecodeError) as exc:
        return ParsedModule(
            file_path=file_path,
            module_name=fallback_module,
            parse_errors=[f"Failed to read file: {exc}"],
            language=Language.GO,
        )

    package_name: Optional[str] = None
    imports: list[ImportInfo] = []
    functions: list[FunctionInfo] = []
    all_calls: list[CallInfo] = []

    # --- First pass: package, imports ---
    in_import_block = False
    for idx, line in enumerate(source_lines, start=1):
        # Package
        pkg_match = _GO_PACKAGE_RE.match(line)
        if pkg_match and not package_name:
            package_name = pkg_match.group(1)
            continue

        # Grouped import block start
        if _GO_IMPORT_BLOCK_START_RE.match(line):
            in_import_block = True
            continue

        # Grouped import block end
        if in_import_block and _GO_IMPORT_BLOCK_END_RE.match(line):
            in_import_block = False
            continue

        # Import line inside a block
        if in_import_block:
            imp_match = _GO_IMPORT_LINE_RE.match(line)
            if imp_match:
                imports.append(ImportInfo(module=imp_match.group(1), line=idx))
            continue

        # Single-line import
        single_match = _GO_IMPORT_SINGLE_RE.match(line)
        if single_match:
            imports.append(ImportInfo(module=single_match.group(1), line=idx))

    module_name = package_name if package_name else fallback_module

    # --- Second pass: functions and methods ---
    function_line_ranges: set[int] = set()

    for idx, line in enumerate(source_lines, start=1):
        if idx in function_line_ranges:
            continue

        # Try method-with-receiver first (more specific pattern)
        method_match = _GO_METHOD_RE.match(line)
        if method_match and "{" in line:
            recv_type = method_match.group(1)
            func_name = method_match.group(2)
            param_blob = method_match.group(3)
            func_end = _find_block_end(source_lines, idx - 1)
            func = FunctionInfo(
                name=func_name,
                qualified_name=f"{module_name}.{recv_type}.{func_name}",
                parameters=_parse_go_parameters(param_blob),
                line_start=idx,
                line_end=func_end,
                is_method=True,
                body_ast=None,
            )
            functions.append(func)
            all_calls.extend(_extract_calls(source_lines, idx, func_end))
            function_line_ranges.update(range(idx, func_end + 1))
            continue

        # Regular function (no receiver)
        func_match = _GO_FUNC_RE.match(line)
        if func_match and "{" in line:
            func_name = func_match.group(1)
            param_blob = func_match.group(2)
            if func_name in _GO_KEYWORDS:
                continue
            func_end = _find_block_end(source_lines, idx - 1)
            func = FunctionInfo(
                name=func_name,
                qualified_name=f"{module_name}.{func_name}",
                parameters=_parse_go_parameters(param_blob),
                line_start=idx,
                line_end=func_end,
                is_method=False,
                body_ast=None,
            )
            functions.append(func)
            all_calls.extend(_extract_calls(source_lines, idx, func_end))
            function_line_ranges.update(range(idx, func_end + 1))

    return ParsedModule(
        file_path=file_path,
        module_name=module_name,
        imports=imports,
        functions=functions,
        all_calls=all_calls,
        source_lines=source_lines,
        language=Language.GO,
    )


class GoParser(LanguageParser):
    """Parser for Go source files."""

    def can_parse(self, file_path: Path) -> bool:
        return file_path.suffix == ".go"

    def file_extensions(self) -> tuple[str, ...]:
        return (".go",)

    def parse_file(
        self, file_path: Path, project_root: Optional[Path] = None
    ) -> ParsedModule:
        return parse_go_file(file_path, project_root)
