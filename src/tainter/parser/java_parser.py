"""Java language parser implementation."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Optional

from tainter.core.types import Language
from tainter.parser.ast_parser import (
    CallInfo,
    ClassInfo,
    FunctionInfo,
    ImportInfo,
    ParameterInfo,
    ParsedModule,
    infer_module_name,
)
from tainter.parser.base import LanguageParser


_JAVA_PACKAGE_RE = re.compile(r"^\s*package\s+([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)\s*;")
_JAVA_IMPORT_RE = re.compile(r"^\s*import\s+(?:static\s+)?([A-Za-z_]\w*(?:\.[A-Za-z_*]\w*|\.\*)*)\s*;")
_JAVA_CLASS_RE = re.compile(r"\bclass\s+([A-Za-z_]\w*)\b")
_JAVA_METHOD_RE = re.compile(
    r"""
    ^\s*
    (?:(?:public|private|protected)\s+)?
    (?:(?:static|final|abstract|synchronized|native|strictfp)\s+)*
    (?:[\w<>\[\],.?]+\s+)?        # optional return type (constructors have none)
    (?P<name>[A-Za-z_]\w*)
    \s*\((?P<params>[^)]*)\)\s*
    (?:throws[^{]+)?\{
    """,
    re.VERBOSE,
)
_JAVA_CALL_RE = re.compile(r"([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)\s*\(")

_JAVA_KEYWORDS = {
    "if",
    "for",
    "while",
    "switch",
    "catch",
    "return",
    "new",
    "throw",
    "synchronized",
    "try",
    "super",
    "this",
}


def _parse_java_parameters(param_blob: str) -> list[ParameterInfo]:
    """Extract parameter names from a Java method signature."""
    params: list[ParameterInfo] = []
    if not param_blob.strip():
        return params

    for position, chunk in enumerate(param_blob.split(",")):
        part = chunk.strip()
        if not part:
            continue
        # Handle varargs and annotations conservatively: keep final token as parameter name.
        tokens = [tok for tok in part.split() if tok and not tok.startswith("@")]
        if not tokens:
            continue
        name = tokens[-1].replace("...", "").strip()
        if name:
            params.append(ParameterInfo(name=name, position=position))
    return params


def _find_block_end(source_lines: list[str], start_index: int) -> int:
    """Find the 1-based end line for a Java brace-delimited block."""
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


def _extract_calls(source_lines: list[str], start_line: int, end_line: int) -> list[CallInfo]:
    """Extract approximate method calls from a Java source range."""
    calls: list[CallInfo] = []
    for line_no in range(start_line, end_line + 1):
        line = source_lines[line_no - 1]
        for match in _JAVA_CALL_RE.finditer(line):
            full = match.group(1)
            if full in _JAVA_KEYWORDS:
                continue
            if "." in full:
                receiver, callee = full.rsplit(".", 1)
            else:
                receiver, callee = None, full
            if callee in _JAVA_KEYWORDS:
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


def parse_java_file(file_path: Path | str, project_root: Optional[Path] = None) -> ParsedModule:
    """Parse a Java file into a ParsedModule."""
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
            language=Language.JAVA,
        )

    package_name: Optional[str] = None
    imports: list[ImportInfo] = []
    classes: list[ClassInfo] = []
    all_calls: list[CallInfo] = []

    for idx, line in enumerate(source_lines, start=1):
        pkg_match = _JAVA_PACKAGE_RE.match(line)
        if pkg_match:
            package_name = pkg_match.group(1)
            continue

        imp_match = _JAVA_IMPORT_RE.match(line)
        if imp_match:
            imports.append(ImportInfo(module=imp_match.group(1), line=idx))

    module_base = file_path.stem
    module_name = f"{package_name}.{module_base}" if package_name else fallback_module

    class_spans: list[tuple[ClassInfo, int, int]] = []
    for idx, line in enumerate(source_lines, start=1):
        class_match = _JAVA_CLASS_RE.search(line)
        if not class_match:
            continue
        if "{" not in line:
            continue
        class_name = class_match.group(1)
        line_end = _find_block_end(source_lines, idx - 1)
        cls = ClassInfo(
            name=class_name,
            qualified_name=f"{module_name}.{class_name}",
            line_start=idx,
            line_end=line_end,
        )
        classes.append(cls)
        class_spans.append((cls, idx, line_end))

    for cls, class_start, class_end in class_spans:
        for idx in range(class_start, class_end + 1):
            line = source_lines[idx - 1]
            method_match = _JAVA_METHOD_RE.match(line)
            if not method_match:
                continue
            method_name = method_match.group("name")
            if method_name in _JAVA_KEYWORDS:
                continue
            method_end = _find_block_end(source_lines, idx - 1)
            if method_end < idx:
                method_end = idx
            method = FunctionInfo(
                name=method_name,
                qualified_name=f"{module_name}.{cls.name}.{method_name}",
                parameters=_parse_java_parameters(method_match.group("params")),
                line_start=idx,
                line_end=method_end,
                is_method=True,
                body_ast=None,
            )
            cls.methods.append(method)
            all_calls.extend(_extract_calls(source_lines, idx, method_end))

    return ParsedModule(
        file_path=file_path,
        module_name=module_name,
        imports=imports,
        classes=classes,
        all_calls=all_calls,
        source_lines=source_lines,
        language=Language.JAVA,
    )


class JavaParser(LanguageParser):
    """Parser for Java source files."""

    def can_parse(self, file_path: Path) -> bool:
        return file_path.suffix == ".java"

    def file_extensions(self) -> tuple[str, ...]:
        return (".java",)

    def parse_file(self, file_path: Path, project_root: Optional[Path] = None) -> ParsedModule:
        return parse_java_file(file_path, project_root)
