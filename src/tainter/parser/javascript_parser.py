# src/tainter/parser/javascript_parser.py
"""JavaScript/TypeScript language parser implementation."""

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

_JS_IMPORT_RE = re.compile(
    r"""^\s*import\s+(?:[\w*{}\s,]+\s+from\s+)?['"]([^'"]+)['"]"""
)
_JS_REQUIRE_RE = re.compile(
    r"""(?:const|let|var)\s+[\w{}\s,]+\s*=\s*require\s*\(\s*['"]([^'"]+)['"]\s*\)"""
)
_JS_CLASS_RE = re.compile(
    r"""^\s*(?:export\s+)?(?:default\s+)?class\s+(\w+)"""
)
_JS_NAMED_FUNC_RE = re.compile(
    r"""^\s*(?:export\s+)?(?:default\s+)?(?:async\s+)?function\s*\*?\s*(\w+)\s*\(([^)]*)\)"""
)
_JS_ARROW_FUNC_RE = re.compile(
    r"""^\s*(?:export\s+)?(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s*)?\(([^)]*)\)\s*=>"""
)
_JS_ARROW_SINGLE_RE = re.compile(
    r"""^\s*(?:export\s+)?(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s+)?(\w+)\s*=>"""
)
_JS_FUNC_EXPR_RE = re.compile(
    r"""^\s*(?:export\s+)?(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s+)?function\s*\*?\s*\w*\s*\(([^)]*)\)"""
)
_JS_METHOD_RE = re.compile(
    r"""^\s*(?:static\s+)?(?:async\s+)?(?:get\s+|set\s+)?(\w+)\s*\(([^)]*)\)\s*\{"""
)
_JS_CALL_RE = re.compile(r"([A-Za-z_$][\w$]*(?:\.[\w$]+)*)\s*\(")
_JS_KEYWORDS = {
    "if", "for", "while", "switch", "catch", "return", "new", "throw",
    "super", "function", "class", "import", "export", "typeof", "instanceof",
    "await", "yield", "delete", "void", "in", "of",
}

# Matches inline arrow callbacks passed as arguments: (req, res) => {
# Anchored to a comma or opening paren to avoid matching named assignments
_JS_INLINE_ARROW_RE = re.compile(
    r"[,(]\s*(?:async\s+)?\(([^)]*)\)\s*=>\s*\{"
)


def _parse_js_parameters(param_blob: str) -> list[ParameterInfo]:
    params: list[ParameterInfo] = []
    if not param_blob.strip():
        return params
    for position, chunk in enumerate(param_blob.split(",")):
        part = chunk.strip()
        if not part:
            continue
        # Strip destructuring, defaults, rest, type annotations
        name = re.split(r"[=:{]", part)[0].strip().lstrip(".")
        name = re.sub(r"[^A-Za-z_$\w]", "", name)
        if name and name not in _JS_KEYWORDS:
            params.append(ParameterInfo(name=name, position=position))
    return params


def _find_block_end(source_lines: list[str], start_index: int) -> int:
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
    calls: list[CallInfo] = []
    for line_no in range(start_line, end_line + 1):
        line = source_lines[line_no - 1]
        for match in _JS_CALL_RE.finditer(line):
            full = match.group(1)
            parts = full.rsplit(".", 1)
            if len(parts) == 2:
                receiver, callee = parts
            else:
                receiver, callee = None, full
            if callee in _JS_KEYWORDS:
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


def parse_javascript_file(
    file_path: Path | str, project_root: Optional[Path] = None
) -> ParsedModule:
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
            language=Language.JAVASCRIPT,
        )

    imports: list[ImportInfo] = []
    classes: list[ClassInfo] = []
    functions: list[FunctionInfo] = []
    all_calls: list[CallInfo] = []

    for idx, line in enumerate(source_lines, start=1):
        imp = _JS_IMPORT_RE.match(line)
        if imp:
            imports.append(ImportInfo(module=imp.group(1), line=idx))
            continue
        req = _JS_REQUIRE_RE.search(line)
        if req:
            imports.append(ImportInfo(module=req.group(1), line=idx))

    class_spans: list[tuple[ClassInfo, int, int]] = []
    for idx, line in enumerate(source_lines, start=1):
        cls_match = _JS_CLASS_RE.match(line)
        if cls_match and "{" in line:
            cls_name = cls_match.group(1)
            line_end = _find_block_end(source_lines, idx - 1)
            cls = ClassInfo(
                name=cls_name,
                qualified_name=f"{fallback_module}.{cls_name}",
                line_start=idx,
                line_end=line_end,
            )
            classes.append(cls)
            class_spans.append((cls, idx, line_end))

    class_line_ranges = {
        line_no
        for _, start, end in class_spans
        for line_no in range(start, end + 1)
    }

    for cls, class_start, class_end in class_spans:
        for idx in range(class_start + 1, class_end):
            line = source_lines[idx - 1]
            m = _JS_METHOD_RE.match(line)
            if not m or m.group(1) in _JS_KEYWORDS:
                continue
            method_name = m.group(1)
            method_end = _find_block_end(source_lines, idx - 1)
            method = FunctionInfo(
                name=method_name,
                qualified_name=f"{fallback_module}.{cls.name}.{method_name}",
                parameters=_parse_js_parameters(m.group(2)),
                line_start=idx,
                line_end=method_end,
                is_method=True,
                body_ast=None,
            )
            cls.methods.append(method)
            all_calls.extend(_extract_calls(source_lines, idx, method_end))

    function_line_ranges: set[int] = set()
    for idx, line in enumerate(source_lines, start=1):
        if idx in class_line_ranges or idx in function_line_ranges:
            continue
        matched = False
        for pattern in (_JS_NAMED_FUNC_RE, _JS_ARROW_FUNC_RE, _JS_FUNC_EXPR_RE):
            m = pattern.match(line)
            if m:
                func_name = m.group(1)
                if func_name in _JS_KEYWORDS:
                    matched = True
                    break
                func_end = _find_block_end(source_lines, idx - 1)
                func = FunctionInfo(
                    name=func_name,
                    qualified_name=f"{fallback_module}.{func_name}",
                    parameters=_parse_js_parameters(m.group(2)),
                    line_start=idx,
                    line_end=func_end,
                    is_method=False,
                    body_ast=None,
                )
                functions.append(func)
                all_calls.extend(_extract_calls(source_lines, idx, func_end))
                function_line_ranges.update(range(idx, func_end + 1))
                matched = True
                break
        if matched:
            continue
        m = _JS_ARROW_SINGLE_RE.match(line)
        if m:
            func_name = m.group(1)
            if func_name not in _JS_KEYWORDS:
                func_end = _find_block_end(source_lines, idx - 1)
                func = FunctionInfo(
                    name=func_name,
                    qualified_name=f"{fallback_module}.{func_name}",
                    parameters=[ParameterInfo(name=m.group(2), position=0)],
                    line_start=idx,
                    line_end=func_end,
                    is_method=False,
                    body_ast=None,
                )
                functions.append(func)
                all_calls.extend(_extract_calls(source_lines, idx, func_end))
                function_line_ranges.update(range(idx, func_end + 1))

    # Second pass: detect inline arrow callbacks passed as arguments, e.g.
    #   app.post('/path', (req, res) => {
    # These are not captured by name-based patterns above.
    _inline_callback_counter = 0
    for idx, line in enumerate(source_lines, start=1):
        if idx in class_line_ranges or idx in function_line_ranges:
            continue
        for cb_match in _JS_INLINE_ARROW_RE.finditer(line):
            func_end = _find_block_end(source_lines, idx - 1)
            _inline_callback_counter += 1
            cb_name = f"_callback_{idx}_{_inline_callback_counter}"
            func = FunctionInfo(
                name=cb_name,
                qualified_name=f"{fallback_module}.{cb_name}",
                parameters=_parse_js_parameters(cb_match.group(1)),
                line_start=idx,
                line_end=func_end,
                is_method=False,
                body_ast=None,
            )
            functions.append(func)
            all_calls.extend(_extract_calls(source_lines, idx, func_end))
            function_line_ranges.update(range(idx, func_end + 1))
            # Only capture the first callback on a given line to avoid nesting issues
            break

    return ParsedModule(
        file_path=file_path,
        module_name=fallback_module,
        imports=imports,
        classes=classes,
        functions=functions,
        all_calls=all_calls,
        source_lines=source_lines,
        language=Language.JAVASCRIPT,
    )


class JavaScriptParser(LanguageParser):
    """Parser for JavaScript and TypeScript source files."""

    def can_parse(self, file_path: Path) -> bool:
        return file_path.suffix in (".js", ".ts")

    def file_extensions(self) -> tuple[str, ...]:
        return (".js", ".ts")

    def parse_file(
        self, file_path: Path, project_root: Optional[Path] = None
    ) -> ParsedModule:
        return parse_javascript_file(file_path, project_root)
