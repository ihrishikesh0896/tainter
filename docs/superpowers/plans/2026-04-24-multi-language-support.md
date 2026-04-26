# Multi-Language Support (JavaScript + Go) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add JavaScript and Go taint analysis to tainter by extracting a shared `BaseFlowFinder`, refactoring `JavaFlowFinder` to subclass it, then implementing JS and Go parsers, models, and flow finders wired into the engine.

**Architecture:** Extract common taint propagation logic (assignment tracking, sink argument matching, flow creation, call site extraction) from `JavaFlowFinder` into an abstract `BaseFlowFinder`. JS and Go subclass it, overriding only language-specific parsing hooks. Each language gets its own parser (regex-based, matching `java_parser.py`), sources/sinks/sanitizers models, and flow finder.

**Tech Stack:** Python 3.10+, pytest, regex-based parsing (no new deps)

**Working directory for all commands:** `/Users/hrishikesh/Desktop/github_projects/vulnreach-parent/tainter`

---

## File Map

| Action | File | Responsibility |
|--------|------|----------------|
| Create | `src/tainter/analysis/base_flow_finder.py` | Abstract base with shared taint propagation |
| Modify | `src/tainter/analysis/java_flow_finder.py` | Subclass BaseFlowFinder; remove duplicated logic |
| Create | `src/tainter/parser/javascript_parser.py` | Regex JS/TS parser → ParsedModule |
| Create | `src/tainter/models/lang/javascript/__init__.py` | Package marker |
| Create | `src/tainter/models/lang/javascript/sources.py` | Express, Next.js, NestJS sources |
| Create | `src/tainter/models/lang/javascript/sinks.py` | SQL, RCE, XSS, SSRF, path traversal sinks |
| Create | `src/tainter/models/lang/javascript/sanitizers.py` | JS sanitizers |
| Create | `src/tainter/analysis/javascript_flow_finder.py` | JS subclass of BaseFlowFinder |
| Create | `src/tainter/parser/go_parser.py` | Regex Go parser → ParsedModule |
| Create | `src/tainter/models/lang/go/__init__.py` | Package marker |
| Create | `src/tainter/models/lang/go/sources.py` | net/http, Gin, Echo sources |
| Create | `src/tainter/models/lang/go/sinks.py` | SQL, RCE, SSRF, path traversal sinks |
| Create | `src/tainter/models/lang/go/sanitizers.py` | Go sanitizers |
| Create | `src/tainter/analysis/go_flow_finder.py` | Go subclass of BaseFlowFinder |
| Modify | `src/tainter/engine.py` | Register JS and Go parsers + flow finders |
| Create | `tests/test_javascript_analysis.py` | Integration tests for JS taint flows |
| Create | `tests/test_go_analysis.py` | Integration tests for Go taint flows |

---

## Task 1: Create `BaseFlowFinder`

**Files:**
- Create: `src/tainter/analysis/base_flow_finder.py`
- Test: inline verification via existing Java tests

- [ ] **Step 1: Write `base_flow_finder.py`**

```python
# src/tainter/analysis/base_flow_finder.py
"""Abstract base class for language-specific taint flow finders."""

from __future__ import annotations

import re
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional

from tainter.core.types import (
    AnalysisResult,
    Confidence,
    FlowStep,
    Location,
    TaintFlow,
    TaintSink,
    TaintSource,
    TaintState,
    VulnerabilityClass,
)
from tainter.models.registry import SanitizerRegistry, SinkRegistry, SourceRegistry
from tainter.parser.ast_parser import CallInfo, FunctionInfo, ParsedModule


@dataclass(frozen=True)
class CallSite:
    """A resolved call with argument expressions at a source line."""

    call: CallInfo
    arguments: tuple[str, ...]


@dataclass
class BaseFlowFinder(ABC):
    """
    Abstract base for language-specific taint flow finders.

    Shared logic: project iteration, assignment/return tracking, call site
    extraction, argument splitting, sink argument taint, flow creation.

    Language subclasses implement: parameter seeding, assignment/return parsing,
    source/sink/sanitizer identification.
    """

    source_registry: SourceRegistry
    sink_registry: SinkRegistry
    sanitizer_registry: SanitizerRegistry
    max_call_depth: int = 5

    def __post_init__(self) -> None:
        self._call_stack: list[str] = []

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def analyze_project(self, modules: list[ParsedModule]) -> AnalysisResult:
        """Analyze all modules and return detected flows."""
        result = AnalysisResult()
        result.files_analyzed = len(modules)
        for module in modules:
            for cls in module.classes:
                for method in cls.methods:
                    result.functions_analyzed += 1
                    result.flows.extend(self._analyze_method(module, method))
            for func in module.functions:
                result.functions_analyzed += 1
                result.flows.extend(self._analyze_method(module, func))
        return result

    # ------------------------------------------------------------------
    # Abstract hooks — implemented per language
    # ------------------------------------------------------------------

    @abstractmethod
    def _seed_parameter_taints(
        self, module: ParsedModule, method: FunctionInfo
    ) -> dict[str, TaintState]:
        """Return initial taint state keyed by parameter name."""

    @abstractmethod
    def _parse_assignment(self, line: str) -> Optional[tuple[str, str]]:
        """Return (target_var, rhs_expr) if line is an assignment, else None."""

    @abstractmethod
    def _parse_return(self, line: str) -> Optional[str]:
        """Return the returned expression if line is a return statement, else None."""

    @abstractmethod
    def _identify_source(
        self, module: ParsedModule, expr: str
    ) -> Optional[TaintSource]:
        """Return a matching TaintSource if expr contains a source call, else None."""

    @abstractmethod
    def _identify_sink(
        self, module: ParsedModule, call: CallInfo
    ) -> Optional[TaintSink]:
        """Return a matching TaintSink for the given call, else None."""

    @abstractmethod
    def _identify_sanitizer(self, module: ParsedModule, expr: str):
        """Return a matching Sanitizer if expr contains a sanitizer call, else None."""

    # ------------------------------------------------------------------
    # Shared analysis logic
    # ------------------------------------------------------------------

    def _analyze_method(
        self, module: ParsedModule, method: FunctionInfo
    ) -> list[TaintFlow]:
        if method.qualified_name in self._call_stack:
            return []
        if len(self._call_stack) >= self.max_call_depth:
            return []

        self._call_stack.append(method.qualified_name)
        try:
            taints = self._seed_parameter_taints(module, method)
            flows: list[TaintFlow] = []

            for line_no in range(method.line_start, method.line_end + 1):
                raw_line = module.get_line(line_no)
                line = raw_line.strip()
                if not line or line.startswith("//") or line.startswith("#"):
                    continue

                assignment = self._parse_assignment(line)
                if assignment:
                    target, expr = assignment
                    expr_taint = self._expression_taint(
                        expr, module, method, line_no, taints
                    )
                    if expr_taint and expr_taint.is_tainted:
                        state = expr_taint.copy()
                        state.add_step(
                            FlowStep(
                                location=Location(module.file_path, line_no),
                                description=f"Assigned to {target}",
                                variable=target,
                                code_snippet=raw_line.strip(),
                                function_name=method.qualified_name,
                            )
                        )
                        taints[target] = state
                    else:
                        taints[target] = TaintState()

                call_sites = self._line_call_sites(module, method, line_no)
                for call_site in call_sites:
                    sink = self._identify_sink(module, call_site.call)
                    if not sink:
                        continue
                    source_taint = self._sink_argument_taint(call_site, sink, taints)
                    if not source_taint:
                        continue
                    if not source_taint.is_tainted_for(sink.vulnerability_class):
                        continue
                    flows.append(
                        self._create_flow(
                            module=module,
                            method=method,
                            sink=sink,
                            sink_call=call_site.call,
                            source_taint=source_taint,
                        )
                    )

                ret_expr = self._parse_return(line)
                if ret_expr:
                    ret_taint = self._expression_taint(
                        ret_expr, module, method, line_no, taints
                    )
                    if ret_taint and ret_taint.is_tainted:
                        taints["$return"] = ret_taint

            return flows
        finally:
            self._call_stack.pop()

    def _expression_taint(
        self,
        expr: str,
        module: ParsedModule,
        method: FunctionInfo,
        line_no: int,
        taints: dict[str, TaintState],
    ) -> Optional[TaintState]:
        source = self._identify_source(module, expr)
        if source:
            return TaintState(
                is_tainted=True,
                source=source,
                source_location=Location(module.file_path, line_no),
            )
        sanitizer = self._identify_sanitizer(module, expr)
        if sanitizer:
            call = self._first_call_in_expression(module, method, line_no)
            if call and call.arguments:
                arg_taint = self._taint_from_variables(call.arguments[0], taints)
                if arg_taint and arg_taint.is_tainted:
                    sanitized = arg_taint.copy()
                    sanitized.sanitize(sanitizer)
                    return sanitized
            return None
        return self._taint_from_variables(expr, taints)

    def _taint_from_variables(
        self, expr: str, taints: dict[str, TaintState]
    ) -> Optional[TaintState]:
        for name, state in taints.items():
            if not state.is_tainted:
                continue
            if re.search(rf"\b{re.escape(name)}\b", expr):
                return state.copy()
        return None

    def _sink_argument_taint(
        self,
        call_site: CallSite,
        sink: TaintSink,
        taints: dict[str, TaintState],
    ) -> Optional[TaintState]:
        if not call_site.arguments:
            return None
        if not sink.vulnerable_parameters:
            for arg in call_site.arguments:
                taint = self._taint_from_variables(arg, taints)
                if taint and taint.is_tainted:
                    return taint
            return None
        for idx in sink.vulnerable_parameters:
            if idx < len(call_site.arguments):
                arg = call_site.arguments[idx]
                taint = self._taint_from_variables(arg, taints)
                if taint and taint.is_tainted:
                    return taint
        return None

    def _create_flow(
        self,
        module: ParsedModule,
        method: FunctionInfo,
        sink: TaintSink,
        sink_call: CallInfo,
        source_taint: TaintState,
    ) -> TaintFlow:
        source = source_taint.source or TaintSource(
            module="unknown", function="unknown", description="Untracked source"
        )
        source_location = source_taint.source_location or Location(
            module.file_path, method.line_start
        )
        sink_location = Location(module.file_path, sink_call.line, sink_call.column)
        call_chain = tuple(self._call_stack) if self._call_stack else (method.qualified_name,)
        variable_path = tuple(step.variable for step in source_taint.propagation_path)
        return TaintFlow(
            id=f"FLOW-{uuid.uuid4().hex[:8].upper()}",
            source=source,
            source_location=source_location,
            source_code=module.get_line(source_location.line).strip(),
            sink=sink,
            sink_location=sink_location,
            sink_code=module.get_line(sink_location.line).strip(),
            steps=tuple(source_taint.propagation_path),
            call_chain=call_chain,
            variable_path=variable_path,
            vulnerability_class=sink.vulnerability_class,
            confidence=Confidence.HIGH,
            message=(
                f"Potential {sink.vulnerability_class.name.title()} vulnerability: "
                f"Untrusted data from {source.function} flows to {sink.function} "
                f"in {method.name}()"
            ),
        )

    def _line_call_sites(
        self, module: ParsedModule, method: FunctionInfo, line_no: int
    ) -> list[CallSite]:
        raw_line = module.get_line(line_no)
        line_calls = [
            call
            for call in module.all_calls
            if call.line == line_no and method.line_start <= call.line <= method.line_end
        ]
        sites: list[CallSite] = []
        cursor = 0
        for call in line_calls:
            if (
                line_no == method.line_start
                and call.callee == method.name
                and call.receiver is None
                and "{" in raw_line
            ):
                continue
            args, cursor = self._extract_call_arguments(raw_line, call, cursor)
            sites.append(CallSite(call=call, arguments=tuple(args)))
        return sites

    def _extract_call_arguments(
        self, line: str, call: CallInfo, offset: int = 0
    ) -> tuple[list[str], int]:
        token = f"{call.receiver}.{call.callee}" if call.receiver else call.callee
        search = line[offset:]
        match = re.search(rf"{re.escape(token)}\s*\(", search)
        if not match:
            return [], offset
        start = offset + match.end() - 1
        depth = 0
        end = start
        for idx in range(start, len(line)):
            char = line[idx]
            if char == "(":
                depth += 1
            elif char == ")":
                depth -= 1
                if depth == 0:
                    end = idx
                    break
        args_blob = line[start + 1 : end].strip()
        return self._split_arguments(args_blob), end + 1

    def _split_arguments(self, args_blob: str) -> list[str]:
        if not args_blob:
            return []
        args: list[str] = []
        current: list[str] = []
        depth = 0
        in_string = False
        quote_char = ""
        escape = False
        for char in args_blob:
            if in_string:
                current.append(char)
                if escape:
                    escape = False
                elif char == "\\":
                    escape = True
                elif char == quote_char:
                    in_string = False
                continue
            if char in ("'", '"', "`"):
                in_string = True
                quote_char = char
                current.append(char)
                continue
            if char == "(":
                depth += 1
                current.append(char)
                continue
            if char == ")":
                if depth > 0:
                    depth -= 1
                current.append(char)
                continue
            if char == "," and depth == 0:
                token = "".join(current).strip()
                if token:
                    args.append(token)
                current = []
                continue
            current.append(char)
        token = "".join(current).strip()
        if token:
            args.append(token)
        return args

    def _first_call_in_expression(
        self, module: ParsedModule, method: FunctionInfo, line_no: int
    ) -> Optional[CallSite]:
        sites = self._line_call_sites(module, method, line_no)
        return sites[0] if sites else None
```

- [ ] **Step 2: Commit**

```bash
git add src/tainter/analysis/base_flow_finder.py
git commit -m "feat: add BaseFlowFinder abstract base class"
```

---

## Task 2: Refactor `JavaFlowFinder` to subclass `BaseFlowFinder`

**Files:**
- Modify: `src/tainter/analysis/java_flow_finder.py`

- [ ] **Step 1: Write failing test to confirm refactored Java still detects SQLi**

```bash
python -m pytest tests/test_java_analysis.py::test_java_parameter_to_sql_sink -v
```

Expected: PASS (baseline before we touch anything)

- [ ] **Step 2: Replace `java_flow_finder.py` entirely**

```python
# src/tainter/analysis/java_flow_finder.py
"""Java taint flow finder — subclass of BaseFlowFinder."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional

from tainter.analysis.base_flow_finder import BaseFlowFinder, CallSite
from tainter.core.types import Location, TaintSink, TaintSource, TaintState
from tainter.models.lang.java.sanitizers import create_java_sanitizer_registry
from tainter.models.lang.java.sinks import create_java_sink_registry
from tainter.models.lang.java.sources import create_java_source_registry
from tainter.models.registry import SanitizerRegistry, SinkRegistry, SourceRegistry
from tainter.parser.ast_parser import CallInfo, FunctionInfo, ParsedModule

_JAVA_ASSIGNMENT_RE = re.compile(
    r"^(?:[\w<>\[\],.?]+\s+)?(?P<target>[A-Za-z_]\w*)\s*=\s*(?P<expr>.+);$"
)
_JAVA_RETURN_RE = re.compile(r"^return\s+(?P<expr>.+);$")


@dataclass
class JavaFlowFinder(BaseFlowFinder):
    """Find Java source-to-sink flows using lightweight taint propagation."""

    source_registry: SourceRegistry = field(default_factory=create_java_source_registry)
    sink_registry: SinkRegistry = field(default_factory=create_java_sink_registry)
    sanitizer_registry: SanitizerRegistry = field(
        default_factory=create_java_sanitizer_registry
    )

    def _parse_assignment(self, line: str) -> Optional[tuple[str, str]]:
        m = _JAVA_ASSIGNMENT_RE.match(line)
        return (m.group("target"), m.group("expr")) if m else None

    def _parse_return(self, line: str) -> Optional[str]:
        m = _JAVA_RETURN_RE.match(line)
        return m.group("expr") if m else None

    def _seed_parameter_taints(
        self, module: ParsedModule, method: FunctionInfo
    ) -> dict[str, TaintState]:
        taints: dict[str, TaintState] = {}
        for param in method.parameters:
            taints[param.name] = TaintState(
                is_tainted=True,
                source=TaintSource(
                    module=module.module_name,
                    function=method.name,
                    attribute=f"param:{param.name}",
                    description="Method parameter treated as untrusted input",
                ),
                source_location=Location(module.file_path, method.line_start),
            )
        return taints

    def _identify_source(
        self, module: ParsedModule, expr: str
    ) -> Optional[TaintSource]:
        for source in self.source_registry.all_sources():
            source_name = source.attribute or source.function.split(".")[-1]
            if re.search(rf"\b{re.escape(source_name)}\s*\(", expr):
                return source
        return None

    def _identify_sink(
        self, module: ParsedModule, call: CallInfo
    ) -> Optional[TaintSink]:
        for sink in self.sink_registry.all_sinks():
            sink_method = sink.function.split(".")[-1]
            if call.callee != sink_method:
                continue
            if self._sink_module_compatible(module, call, sink):
                return sink
        return None

    def _identify_sanitizer(self, module: ParsedModule, expr: str):
        for sanitizer in self.sanitizer_registry.all_sanitizers():
            sanitizer_name = sanitizer.function.split(".")[-1]
            if re.search(rf"\b{re.escape(sanitizer_name)}\s*\(", expr):
                return sanitizer
        return None

    def _sink_module_compatible(
        self, module: ParsedModule, call: CallInfo, sink: TaintSink
    ) -> bool:
        if sink.module.startswith("java.lang"):
            return True
        imports = [imp.module for imp in module.imports]
        if any(
            imp == sink.module or imp.startswith(sink.module + ".") for imp in imports
        ):
            return True
        sink_parts = sink.function.split(".")
        if len(sink_parts) >= 2 and call.receiver:
            expected_owner = sink_parts[-2]
            receiver_leaf = call.receiver.split(".")[-1]
            if receiver_leaf == expected_owner:
                return True
        return False
```

- [ ] **Step 3: Run all existing Java tests — must all pass**

```bash
python -m pytest tests/test_java_analysis.py -v
```

Expected: all tests PASS

- [ ] **Step 4: Run full test suite — no regressions**

```bash
python -m pytest tests/ -v
```

Expected: all tests PASS

- [ ] **Step 5: Commit**

```bash
git add src/tainter/analysis/java_flow_finder.py
git commit -m "refactor: JavaFlowFinder subclasses BaseFlowFinder"
```

---

## Task 3: JavaScript Parser

**Files:**
- Create: `src/tainter/parser/javascript_parser.py`
- Test: `tests/test_parser.py` (add JS section) or inline

- [ ] **Step 1: Write the failing test**

Add to `tests/test_parser.py`:

```python
def test_js_parser_extracts_function_and_calls(tmp_path):
    from tainter.parser.javascript_parser import JavaScriptParser
    js = tmp_path / "app.js"
    js.write_text(
        "const express = require('express');\n"
        "\n"
        "async function handler(req, res) {\n"
        "    const userId = req.query.id;\n"
        "    db.query(userId);\n"
        "    res.send('ok');\n"
        "}\n"
    )
    parser = JavaScriptParser()
    module = parser.parse_file(js)
    assert len(module.functions) >= 1
    fn = module.functions[0]
    assert fn.name == "handler"
    assert len(fn.parameters) == 2
    assert any(c.callee == "query" for c in module.all_calls)


def test_js_parser_extracts_imports(tmp_path):
    from tainter.parser.javascript_parser import JavaScriptParser
    js = tmp_path / "app.js"
    js.write_text(
        "import express from 'express';\n"
        "import { readFile } from 'fs';\n"
        "const axios = require('axios');\n"
    )
    parser = JavaScriptParser()
    module = parser.parse_file(js)
    modules = [imp.module for imp in module.imports]
    assert "express" in modules
    assert "fs" in modules
    assert "axios" in modules
```

- [ ] **Step 2: Run to confirm failure**

```bash
python -m pytest tests/test_parser.py::test_js_parser_extracts_function_and_calls -v
```

Expected: FAIL with `ModuleNotFoundError` or `ImportError`

- [ ] **Step 3: Write `javascript_parser.py`**

```python
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

    for idx, line in enumerate(source_lines, start=1):
        if idx in class_line_ranges:
            continue
        for pattern in (_JS_NAMED_FUNC_RE, _JS_ARROW_FUNC_RE, _JS_FUNC_EXPR_RE):
            m = pattern.match(line)
            if m:
                func_name = m.group(1)
                if func_name in _JS_KEYWORDS:
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
```

- [ ] **Step 4: Run tests — must pass**

```bash
python -m pytest tests/test_parser.py::test_js_parser_extracts_function_and_calls tests/test_parser.py::test_js_parser_extracts_imports -v
```

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/tainter/parser/javascript_parser.py tests/test_parser.py
git commit -m "feat: add JavaScript/TypeScript parser"
```

---

## Task 4: JavaScript Models (Sources, Sinks, Sanitizers)

**Files:**
- Create: `src/tainter/models/lang/javascript/__init__.py`
- Create: `src/tainter/models/lang/javascript/sources.py`
- Create: `src/tainter/models/lang/javascript/sinks.py`
- Create: `src/tainter/models/lang/javascript/sanitizers.py`

- [ ] **Step 1: Create `__init__.py`**

```python
# src/tainter/models/lang/javascript/__init__.py
```

(empty file)

- [ ] **Step 2: Create `sources.py`**

```python
# src/tainter/models/lang/javascript/sources.py
"""JavaScript taint source definitions — Express, Next.js, NestJS."""

from tainter.core.types import TaintSource
from tainter.models.registry import SourceRegistry

# --- Express ---

EXPRESS_SOURCES: tuple[TaintSource, ...] = (
    TaintSource(
        module="express", function="Request", attribute="body",
        framework="express", description="Express request body",
    ),
    TaintSource(
        module="express", function="Request", attribute="params",
        framework="express", description="Express route parameters",
    ),
    TaintSource(
        module="express", function="Request", attribute="query",
        framework="express", description="Express query string parameters",
    ),
    TaintSource(
        module="express", function="Request", attribute="headers",
        framework="express", description="Express request headers",
    ),
    TaintSource(
        module="express", function="Request", attribute="cookies",
        framework="express", description="Express cookies",
    ),
)

# --- Next.js ---

NEXTJS_SOURCES: tuple[TaintSource, ...] = (
    TaintSource(
        module="next", function="NextApiRequest", attribute="query",
        framework="nextjs", description="Next.js API route query parameters",
    ),
    TaintSource(
        module="next", function="context", attribute="params",
        framework="nextjs", description="Next.js page context params",
    ),
    TaintSource(
        module="next/navigation", function="searchParams",
        framework="nextjs", description="Next.js searchParams (App Router)",
    ),
)

# --- NestJS ---

NESTJS_SOURCES: tuple[TaintSource, ...] = (
    TaintSource(
        module="@nestjs/common", function="Body",
        framework="nestjs", description="NestJS @Body() decorator parameter",
    ),
    TaintSource(
        module="@nestjs/common", function="Param",
        framework="nestjs", description="NestJS @Param() decorator parameter",
    ),
    TaintSource(
        module="@nestjs/common", function="Query",
        framework="nestjs", description="NestJS @Query() decorator parameter",
    ),
    TaintSource(
        module="@nestjs/common", function="Headers",
        framework="nestjs", description="NestJS @Headers() decorator parameter",
    ),
)


def get_all_javascript_sources() -> tuple[TaintSource, ...]:
    return EXPRESS_SOURCES + NEXTJS_SOURCES + NESTJS_SOURCES


def create_javascript_source_registry() -> SourceRegistry:
    registry = SourceRegistry()
    registry.register_all(get_all_javascript_sources())
    return registry
```

- [ ] **Step 3: Create `sinks.py`**

```python
# src/tainter/models/lang/javascript/sinks.py
"""JavaScript taint sink definitions."""

from tainter.core.types import TaintSink, VulnerabilityClass
from tainter.models.registry import SinkRegistry

# --- SQL Injection ---

JS_SQL_SINKS: tuple[TaintSink, ...] = (
    TaintSink(
        module="mysql", function="query",
        vulnerable_parameters=(0,),
        vulnerability_class=VulnerabilityClass.SQLI,
        description="MySQL query() with tainted SQL string",
    ),
    TaintSink(
        module="mysql2", function="query",
        vulnerable_parameters=(0,),
        vulnerability_class=VulnerabilityClass.SQLI,
        description="mysql2 query() with tainted SQL string",
    ),
    TaintSink(
        module="pg", function="query",
        vulnerable_parameters=(0,),
        vulnerability_class=VulnerabilityClass.SQLI,
        description="pg (PostgreSQL) query() with tainted SQL string",
    ),
    TaintSink(
        module="sequelize", function="query",
        vulnerable_parameters=(0,),
        vulnerability_class=VulnerabilityClass.SQLI,
        description="Sequelize raw query() with tainted SQL string",
    ),
    TaintSink(
        module="knex", function="raw",
        vulnerable_parameters=(0,),
        vulnerability_class=VulnerabilityClass.SQLI,
        description="Knex raw() with tainted SQL string",
    ),
)

# --- Remote Code Execution ---

JS_RCE_SINKS: tuple[TaintSink, ...] = (
    TaintSink(
        module="child_process", function="exec",
        vulnerable_parameters=(0,),
        vulnerability_class=VulnerabilityClass.RCE,
        description="child_process.exec() with tainted command",
    ),
    TaintSink(
        module="child_process", function="execSync",
        vulnerable_parameters=(0,),
        vulnerability_class=VulnerabilityClass.RCE,
        description="child_process.execSync() with tainted command",
    ),
    TaintSink(
        module="child_process", function="spawn",
        vulnerable_parameters=(0,),
        vulnerability_class=VulnerabilityClass.RCE,
        description="child_process.spawn() with tainted command",
    ),
    TaintSink(
        module="child_process", function="spawnSync",
        vulnerable_parameters=(0,),
        vulnerability_class=VulnerabilityClass.RCE,
        description="child_process.spawnSync() with tainted command",
    ),
    TaintSink(
        module="builtins", function="eval",
        vulnerable_parameters=(0,),
        vulnerability_class=VulnerabilityClass.RCE,
        description="eval() with tainted code string",
    ),
    TaintSink(
        module="vm", function="runInNewContext",
        vulnerable_parameters=(0,),
        vulnerability_class=VulnerabilityClass.RCE,
        description="vm.runInNewContext() with tainted code",
    ),
)

# --- Cross-Site Scripting ---

JS_XSS_SINKS: tuple[TaintSink, ...] = (
    TaintSink(
        module="dom", function="innerHTML",
        vulnerable_parameters=(0,),
        vulnerability_class=VulnerabilityClass.XSS,
        description="innerHTML assignment with tainted HTML",
    ),
    TaintSink(
        module="dom", function="outerHTML",
        vulnerable_parameters=(0,),
        vulnerability_class=VulnerabilityClass.XSS,
        description="outerHTML assignment with tainted HTML",
    ),
    TaintSink(
        module="react", function="dangerouslySetInnerHTML",
        vulnerable_parameters=(0,),
        vulnerability_class=VulnerabilityClass.XSS,
        description="React dangerouslySetInnerHTML with tainted HTML",
    ),
    TaintSink(
        module="dom", function="document.write",
        vulnerable_parameters=(0,),
        vulnerability_class=VulnerabilityClass.XSS,
        description="document.write() with tainted content",
    ),
)

# --- SSRF ---

JS_SSRF_SINKS: tuple[TaintSink, ...] = (
    TaintSink(
        module="node-fetch", function="fetch",
        vulnerable_parameters=(0,),
        vulnerability_class=VulnerabilityClass.SSRF,
        description="fetch() with tainted URL",
    ),
    TaintSink(
        module="axios", function="get",
        vulnerable_parameters=(0,),
        vulnerability_class=VulnerabilityClass.SSRF,
        description="axios.get() with tainted URL",
    ),
    TaintSink(
        module="axios", function="post",
        vulnerable_parameters=(0,),
        vulnerability_class=VulnerabilityClass.SSRF,
        description="axios.post() with tainted URL",
    ),
    TaintSink(
        module="axios", function="request",
        vulnerable_parameters=(0,),
        vulnerability_class=VulnerabilityClass.SSRF,
        description="axios.request() with tainted URL",
    ),
    TaintSink(
        module="http", function="request",
        vulnerable_parameters=(0,),
        vulnerability_class=VulnerabilityClass.SSRF,
        description="http.request() with tainted options",
    ),
    TaintSink(
        module="https", function="request",
        vulnerable_parameters=(0,),
        vulnerability_class=VulnerabilityClass.SSRF,
        description="https.request() with tainted options",
    ),
)

# --- Path Traversal ---

JS_PATH_TRAVERSAL_SINKS: tuple[TaintSink, ...] = (
    TaintSink(
        module="fs", function="readFile",
        vulnerable_parameters=(0,),
        vulnerability_class=VulnerabilityClass.PATH_TRAVERSAL,
        description="fs.readFile() with tainted path",
    ),
    TaintSink(
        module="fs", function="readFileSync",
        vulnerable_parameters=(0,),
        vulnerability_class=VulnerabilityClass.PATH_TRAVERSAL,
        description="fs.readFileSync() with tainted path",
    ),
    TaintSink(
        module="fs", function="writeFile",
        vulnerable_parameters=(0,),
        vulnerability_class=VulnerabilityClass.PATH_TRAVERSAL,
        description="fs.writeFile() with tainted path",
    ),
    TaintSink(
        module="fs", function="writeFileSync",
        vulnerable_parameters=(0,),
        vulnerability_class=VulnerabilityClass.PATH_TRAVERSAL,
        description="fs.writeFileSync() with tainted path",
    ),
    TaintSink(
        module="fs", function="createReadStream",
        vulnerable_parameters=(0,),
        vulnerability_class=VulnerabilityClass.PATH_TRAVERSAL,
        description="fs.createReadStream() with tainted path",
    ),
    TaintSink(
        module="path", function="join",
        vulnerable_parameters=(0,),
        vulnerability_class=VulnerabilityClass.PATH_TRAVERSAL,
        description="path.join() with tainted path component",
    ),
)


def get_all_javascript_sinks() -> tuple[TaintSink, ...]:
    return (
        JS_SQL_SINKS + JS_RCE_SINKS + JS_XSS_SINKS
        + JS_SSRF_SINKS + JS_PATH_TRAVERSAL_SINKS
    )


def create_javascript_sink_registry() -> SinkRegistry:
    registry = SinkRegistry()
    registry.register_all(get_all_javascript_sinks())
    return registry
```

- [ ] **Step 4: Create `sanitizers.py`**

```python
# src/tainter/models/lang/javascript/sanitizers.py
"""JavaScript sanitizer definitions."""

from tainter.core.types import Sanitizer, VulnerabilityClass
from tainter.models.registry import SanitizerRegistry

JS_SANITIZERS: tuple[Sanitizer, ...] = (
    Sanitizer(
        module="he", function="encode",
        clears=(VulnerabilityClass.XSS,),
        description="HTML entity encoding via 'he' library",
    ),
    Sanitizer(
        module="dompurify", function="sanitize",
        clears=(VulnerabilityClass.XSS,),
        description="DOMPurify HTML sanitization",
    ),
    Sanitizer(
        module="validator", function="escape",
        clears=(VulnerabilityClass.XSS,),
        description="validator.js HTML escape",
    ),
    Sanitizer(
        module="mysql", function="escape",
        clears=(VulnerabilityClass.SQLI,),
        description="MySQL string escaping",
    ),
    Sanitizer(
        module="mysql2", function="escape",
        clears=(VulnerabilityClass.SQLI,),
        description="mysql2 string escaping",
    ),
    Sanitizer(
        module="path", function="resolve",
        clears=(VulnerabilityClass.PATH_TRAVERSAL,),
        description="path.resolve() normalizes traversal sequences",
    ),
)


def get_all_javascript_sanitizers() -> tuple[Sanitizer, ...]:
    return JS_SANITIZERS


def create_javascript_sanitizer_registry() -> SanitizerRegistry:
    registry = SanitizerRegistry()
    registry.register_all(get_all_javascript_sanitizers())
    return registry
```

- [ ] **Step 5: Commit**

```bash
git add src/tainter/models/lang/javascript/
git commit -m "feat: add JavaScript taint source/sink/sanitizer models"
```

---

## Task 5: JavaScript FlowFinder + Integration Tests

**Files:**
- Create: `src/tainter/analysis/javascript_flow_finder.py`
- Create: `tests/test_javascript_analysis.py`

- [ ] **Step 1: Write the failing integration tests**

```python
# tests/test_javascript_analysis.py
"""Integration tests for JavaScript taint flow analysis."""

from tainter.core.types import Language, VulnerabilityClass
from tainter.engine import EngineConfig, TainterEngine


def _scan_js(tmp_path, js_source: str, filename: str = "app.js"):
    project = tmp_path / "js_project"
    project.mkdir()
    (project / filename).write_text(js_source)
    engine = TainterEngine(
        EngineConfig(include_tests=True, languages=frozenset({Language.JAVASCRIPT}))
    )
    result = engine.analyze(project)
    return engine, result


def test_express_req_body_to_sql_sink(tmp_path):
    js = """
const express = require('express');
const mysql = require('mysql');

const app = express();

app.post('/users', (req, res) => {
    const userId = req.body.id;
    const sqlQuery = "SELECT * FROM users WHERE id = " + userId;
    db.query(sqlQuery, (err, results) => {
        res.json(results);
    });
});
"""
    _engine, result = _scan_js(tmp_path, js)
    sqli = [f for f in result.flows if f.vulnerability_class == VulnerabilityClass.SQLI]
    assert len(sqli) >= 1


def test_express_req_query_to_exec_sink(tmp_path):
    js = """
const { exec } = require('child_process');
const express = require('express');
const app = express();

app.get('/run', (req, res) => {
    const cmd = req.query.command;
    exec(cmd, (err, stdout) => {
        res.send(stdout);
    });
});
"""
    _engine, result = _scan_js(tmp_path, js)
    rce = [f for f in result.flows if f.vulnerability_class == VulnerabilityClass.RCE]
    assert len(rce) >= 1


def test_express_req_params_to_fs_read(tmp_path):
    js = """
const express = require('express');
const fs = require('fs');
const app = express();

app.get('/file/:name', (req, res) => {
    const filename = req.params.name;
    fs.readFileSync(filename);
});
"""
    _engine, result = _scan_js(tmp_path, js)
    path = [
        f for f in result.flows
        if f.vulnerability_class == VulnerabilityClass.PATH_TRAVERSAL
    ]
    assert len(path) >= 1


def test_js_language_is_active_analyzer(tmp_path):
    js = """
const express = require('express');
function handler(req, res) { res.send('ok'); }
"""
    engine, result = _scan_js(tmp_path, js)
    assert "javascript" in result.active_analyzers
    assert result.files_analyzed >= 1
```

- [ ] **Step 2: Run to confirm failure**

```bash
python -m pytest tests/test_javascript_analysis.py -v
```

Expected: FAIL (JavaScriptFlowFinder does not exist yet)

- [ ] **Step 3: Write `javascript_flow_finder.py`**

```python
# src/tainter/analysis/javascript_flow_finder.py
"""JavaScript taint flow finder — subclass of BaseFlowFinder."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional

from tainter.analysis.base_flow_finder import BaseFlowFinder
from tainter.core.types import Location, TaintSink, TaintSource, TaintState
from tainter.models.lang.javascript.sanitizers import create_javascript_sanitizer_registry
from tainter.models.lang.javascript.sinks import create_javascript_sink_registry
from tainter.models.lang.javascript.sources import create_javascript_source_registry
from tainter.models.registry import SanitizerRegistry, SinkRegistry, SourceRegistry
from tainter.parser.ast_parser import CallInfo, FunctionInfo, ParsedModule

_JS_ASSIGNMENT_RE = re.compile(
    r"^(?:(?:const|let|var)\s+)?(?P<target>[A-Za-z_$][\w$]*)\s*=(?!=)\s*(?P<expr>.+?);?\s*$"
)
_JS_RETURN_RE = re.compile(r"^return\s+(?P<expr>.+?);?\s*$")

_JS_HTTP_HANDLER_PARAMS = {
    # Express: (req, res) or (req, res, next)
    "req", "request",
    # NestJS injected decorator names handled via source matching
}


@dataclass
class JavaScriptFlowFinder(BaseFlowFinder):
    """Find JavaScript source-to-sink flows using lightweight taint propagation."""

    source_registry: SourceRegistry = field(
        default_factory=create_javascript_source_registry
    )
    sink_registry: SinkRegistry = field(
        default_factory=create_javascript_sink_registry
    )
    sanitizer_registry: SanitizerRegistry = field(
        default_factory=create_javascript_sanitizer_registry
    )

    def _parse_assignment(self, line: str) -> Optional[tuple[str, str]]:
        m = _JS_ASSIGNMENT_RE.match(line)
        if not m:
            return None
        target = m.group("target")
        expr = m.group("expr").strip().rstrip(";")
        return (target, expr)

    def _parse_return(self, line: str) -> Optional[str]:
        m = _JS_RETURN_RE.match(line)
        return m.group("expr").strip().rstrip(";") if m else None

    def _seed_parameter_taints(
        self, module: ParsedModule, method: FunctionInfo
    ) -> dict[str, TaintState]:
        taints: dict[str, TaintState] = {}
        for param in method.parameters:
            if param.name in _JS_HTTP_HANDLER_PARAMS:
                taints[param.name] = TaintState(
                    is_tainted=True,
                    source=TaintSource(
                        module=module.module_name,
                        function=method.name,
                        attribute=f"param:{param.name}",
                        description="HTTP handler request object",
                    ),
                    source_location=Location(module.file_path, method.line_start),
                )
        return taints

    def _identify_source(
        self, module: ParsedModule, expr: str
    ) -> Optional[TaintSource]:
        for source in self.source_registry.all_sources():
            pattern = source.attribute or source.function
            if re.search(rf"\b{re.escape(pattern)}\b", expr):
                return source
        return None

    def _identify_sink(
        self, module: ParsedModule, call: CallInfo
    ) -> Optional[TaintSink]:
        for sink in self.sink_registry.all_sinks():
            sink_func = sink.function.split(".")[-1]
            if call.callee == sink_func:
                return sink
        return None

    def _identify_sanitizer(self, module: ParsedModule, expr: str):
        for sanitizer in self.sanitizer_registry.all_sanitizers():
            sanitizer_name = sanitizer.function.split(".")[-1]
            if re.search(rf"\b{re.escape(sanitizer_name)}\s*\(", expr):
                return sanitizer
        return None
```

- [ ] **Step 4: Wire JavaScript into `engine.py`** (preview — full wiring in Task 9; only add JS here)

Add to the imports at the top of `src/tainter/engine.py`:

```python
from tainter.parser.javascript_parser import JavaScriptParser
from tainter.analysis.javascript_flow_finder import JavaScriptFlowFinder
```

In `TainterEngine.__init__`, update `self._parsers`:

```python
self._parsers: dict[Language, LanguageParser] = {
    Language.PYTHON: PythonParser(),
    Language.JAVA: JavaParser(),
    Language.JAVASCRIPT: JavaScriptParser(),
}
```

Add JS flow dispatch in `TainterEngine.analyze`, after the Java block:

```python
js_modules = [m for m in self._modules if m.language == Language.JAVASCRIPT]
if js_modules and Language.JAVASCRIPT in selected_parsers:
    js_finder = JavaScriptFlowFinder(max_call_depth=self.config.max_call_depth)
    js_result = js_finder.analyze_project(js_modules)
    result.flows.extend(js_result.flows)
    result.functions_analyzed += js_result.functions_analyzed
```

Also update `TARGET_EXTENSION_LANGUAGE` in `engine.py` — it already maps `"js": Language.JAVASCRIPT` so no change needed there.

- [ ] **Step 5: Run JS integration tests — must pass**

```bash
python -m pytest tests/test_javascript_analysis.py -v
```

Expected: all PASS

- [ ] **Step 6: Run full suite — no regressions**

```bash
python -m pytest tests/ -v
```

Expected: all PASS

- [ ] **Step 7: Commit**

```bash
git add src/tainter/analysis/javascript_flow_finder.py tests/test_javascript_analysis.py src/tainter/engine.py
git commit -m "feat: add JavaScript taint flow analysis"
```

---

## Task 6: Go Parser

**Files:**
- Create: `src/tainter/parser/go_parser.py`
- Test: `tests/test_parser.py` (add Go section)

- [ ] **Step 1: Write the failing tests**

Add to `tests/test_parser.py`:

```python
def test_go_parser_extracts_functions_and_calls(tmp_path):
    from tainter.parser.go_parser import GoParser
    go = tmp_path / "main.go"
    go.write_text(
        'package main\n'
        '\n'
        'import (\n'
        '    "database/sql"\n'
        '    "net/http"\n'
        ')\n'
        '\n'
        'func handler(w http.ResponseWriter, r *http.Request) {\n'
        '    userId := r.FormValue("id")\n'
        '    db.Query(userId)\n'
        '}\n'
    )
    parser = GoParser()
    module = parser.parse_file(go)
    assert len(module.functions) >= 1
    fn = module.functions[0]
    assert fn.name == "handler"
    assert len(fn.parameters) == 2
    assert any(c.callee == "Query" for c in module.all_calls)


def test_go_parser_extracts_imports(tmp_path):
    from tainter.parser.go_parser import GoParser
    go = tmp_path / "main.go"
    go.write_text(
        'package main\n'
        'import "net/http"\n'
        'import "database/sql"\n'
    )
    parser = GoParser()
    module = parser.parse_file(go)
    modules = [imp.module for imp in module.imports]
    assert "net/http" in modules
    assert "database/sql" in modules
```

- [ ] **Step 2: Run to confirm failure**

```bash
python -m pytest tests/test_parser.py::test_go_parser_extracts_functions_and_calls -v
```

Expected: FAIL with `ModuleNotFoundError`

- [ ] **Step 3: Write `go_parser.py`**

```python
# src/tainter/parser/go_parser.py
"""Go language parser implementation."""

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

_GO_PACKAGE_RE = re.compile(r"^package\s+(\w+)")
_GO_IMPORT_SINGLE_RE = re.compile(r'^\s*import\s+"([^"]+)"')
_GO_IMPORT_PATH_RE = re.compile(r'^\s*(?:\w+\s+)?"([^"]+)"')
_GO_FUNC_RE = re.compile(
    r"""^func\s+(?:\((?P<recv>[^)]+)\)\s+)?(?P<name>\w+)\s*\((?P<params>[^)]*)\)"""
)
_GO_CALL_RE = re.compile(r"([A-Za-z_][\w]*(?:\.[\w]+)*)\s*\(")
_GO_KEYWORDS = {
    "if", "for", "range", "switch", "select", "case", "return", "go",
    "defer", "make", "new", "len", "cap", "append", "copy", "close",
    "delete", "panic", "recover", "print", "println",
}


def _parse_go_parameters(param_blob: str) -> list[ParameterInfo]:
    params: list[ParameterInfo] = []
    if not param_blob.strip():
        return params
    for position, chunk in enumerate(param_blob.split(",")):
        part = chunk.strip()
        if not part:
            continue
        tokens = part.split()
        if not tokens:
            continue
        # "name type" or just "type" for unnamed params
        name = tokens[0].lstrip("*")
        if name and name not in _GO_KEYWORDS:
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
        for match in _GO_CALL_RE.finditer(line):
            full = match.group(1)
            parts = full.rsplit(".", 1)
            if len(parts) == 2:
                receiver, callee = parts
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

    imports: list[ImportInfo] = []
    functions: list[FunctionInfo] = []
    all_calls: list[CallInfo] = []
    in_import_block = False

    for idx, line in enumerate(source_lines, start=1):
        if _GO_IMPORT_SINGLE_RE.match(line):
            m = _GO_IMPORT_SINGLE_RE.match(line)
            imports.append(ImportInfo(module=m.group(1), line=idx))
            continue

        if re.match(r"^\s*import\s*\(", line):
            in_import_block = True
            continue

        if in_import_block:
            if re.match(r"^\s*\)", line):
                in_import_block = False
                continue
            m = _GO_IMPORT_PATH_RE.match(line)
            if m:
                imports.append(ImportInfo(module=m.group(1), line=idx))
            continue

    for idx, line in enumerate(source_lines, start=1):
        m = _GO_FUNC_RE.match(line)
        if not m:
            continue
        func_name = m.group("name")
        if func_name in _GO_KEYWORDS:
            continue
        func_end = _find_block_end(source_lines, idx - 1)
        func = FunctionInfo(
            name=func_name,
            qualified_name=f"{fallback_module}.{func_name}",
            parameters=_parse_go_parameters(m.group("params")),
            line_start=idx,
            line_end=func_end,
            is_method=bool(m.group("recv")),
            body_ast=None,
        )
        functions.append(func)
        all_calls.extend(_extract_calls(source_lines, idx, func_end))

    return ParsedModule(
        file_path=file_path,
        module_name=fallback_module,
        imports=imports,
        classes=[],
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
```

- [ ] **Step 4: Run tests — must pass**

```bash
python -m pytest tests/test_parser.py::test_go_parser_extracts_functions_and_calls tests/test_parser.py::test_go_parser_extracts_imports -v
```

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/tainter/parser/go_parser.py tests/test_parser.py
git commit -m "feat: add Go parser"
```

---

## Task 7: Go Models (Sources, Sinks, Sanitizers)

**Files:**
- Create: `src/tainter/models/lang/go/__init__.py`
- Create: `src/tainter/models/lang/go/sources.py`
- Create: `src/tainter/models/lang/go/sinks.py`
- Create: `src/tainter/models/lang/go/sanitizers.py`

- [ ] **Step 1: Create `__init__.py`**

```python
# src/tainter/models/lang/go/__init__.py
```

(empty file)

- [ ] **Step 2: Create `sources.py`**

```python
# src/tainter/models/lang/go/sources.py
"""Go taint source definitions — net/http, Gin, Echo."""

from tainter.core.types import TaintSource
from tainter.models.registry import SourceRegistry

# --- net/http ---

NET_HTTP_SOURCES: tuple[TaintSource, ...] = (
    TaintSource(
        module="net/http", function="Request", attribute="FormValue",
        framework="net/http", description="HTTP form value",
    ),
    TaintSource(
        module="net/http", function="Request", attribute="PathValue",
        framework="net/http", description="HTTP path value (Go 1.22+)",
    ),
    TaintSource(
        module="net/http", function="Request", attribute="Header.Get",
        framework="net/http", description="HTTP request header",
    ),
    TaintSource(
        module="net/http", function="Values", attribute="Get",
        framework="net/http", description="URL query parameter via Values.Get",
    ),
)

# --- Gin ---

GIN_SOURCES: tuple[TaintSource, ...] = (
    TaintSource(
        module="github.com/gin-gonic/gin", function="Context", attribute="Param",
        framework="gin", description="Gin route parameter",
    ),
    TaintSource(
        module="github.com/gin-gonic/gin", function="Context", attribute="Query",
        framework="gin", description="Gin query string parameter",
    ),
    TaintSource(
        module="github.com/gin-gonic/gin", function="Context", attribute="PostForm",
        framework="gin", description="Gin POST form value",
    ),
    TaintSource(
        module="github.com/gin-gonic/gin", function="Context", attribute="GetHeader",
        framework="gin", description="Gin request header",
    ),
    TaintSource(
        module="github.com/gin-gonic/gin", function="Context", attribute="ShouldBind",
        framework="gin", description="Gin struct binding from request",
    ),
    TaintSource(
        module="github.com/gin-gonic/gin", function="Context", attribute="ShouldBindJSON",
        framework="gin", description="Gin JSON binding from request body",
    ),
)

# --- Echo ---

ECHO_SOURCES: tuple[TaintSource, ...] = (
    TaintSource(
        module="github.com/labstack/echo/v4", function="Context", attribute="Param",
        framework="echo", description="Echo route parameter",
    ),
    TaintSource(
        module="github.com/labstack/echo/v4", function="Context", attribute="QueryParam",
        framework="echo", description="Echo query string parameter",
    ),
    TaintSource(
        module="github.com/labstack/echo/v4", function="Context", attribute="FormValue",
        framework="echo", description="Echo form value",
    ),
    TaintSource(
        module="github.com/labstack/echo/v4", function="Context", attribute="PathParam",
        framework="echo", description="Echo path parameter",
    ),
)


def get_all_go_sources() -> tuple[TaintSource, ...]:
    return NET_HTTP_SOURCES + GIN_SOURCES + ECHO_SOURCES


def create_go_source_registry() -> SourceRegistry:
    registry = SourceRegistry()
    registry.register_all(get_all_go_sources())
    return registry
```

- [ ] **Step 3: Create `sinks.py`**

```python
# src/tainter/models/lang/go/sinks.py
"""Go taint sink definitions."""

from tainter.core.types import TaintSink, VulnerabilityClass
from tainter.models.registry import SinkRegistry

# --- SQL Injection ---

GO_SQL_SINKS: tuple[TaintSink, ...] = (
    TaintSink(
        module="database/sql", function="Query",
        vulnerable_parameters=(0,),
        vulnerability_class=VulnerabilityClass.SQLI,
        description="sql.DB.Query() with tainted SQL string",
    ),
    TaintSink(
        module="database/sql", function="QueryRow",
        vulnerable_parameters=(0,),
        vulnerability_class=VulnerabilityClass.SQLI,
        description="sql.DB.QueryRow() with tainted SQL string",
    ),
    TaintSink(
        module="database/sql", function="Exec",
        vulnerable_parameters=(0,),
        vulnerability_class=VulnerabilityClass.SQLI,
        description="sql.DB.Exec() with tainted SQL string",
    ),
    TaintSink(
        module="database/sql", function="QueryContext",
        vulnerable_parameters=(1,),
        vulnerability_class=VulnerabilityClass.SQLI,
        description="sql.DB.QueryContext() with tainted SQL string",
    ),
    TaintSink(
        module="database/sql", function="ExecContext",
        vulnerable_parameters=(1,),
        vulnerability_class=VulnerabilityClass.SQLI,
        description="sql.DB.ExecContext() with tainted SQL string",
    ),
)

# --- Remote Code Execution ---

GO_RCE_SINKS: tuple[TaintSink, ...] = (
    TaintSink(
        module="os/exec", function="Command",
        vulnerable_parameters=(0,),
        vulnerability_class=VulnerabilityClass.RCE,
        description="exec.Command() with tainted command string",
    ),
    TaintSink(
        module="os/exec", function="CommandContext",
        vulnerable_parameters=(1,),
        vulnerability_class=VulnerabilityClass.RCE,
        description="exec.CommandContext() with tainted command string",
    ),
)

# --- SSRF ---

GO_SSRF_SINKS: tuple[TaintSink, ...] = (
    TaintSink(
        module="net/http", function="Get",
        vulnerable_parameters=(0,),
        vulnerability_class=VulnerabilityClass.SSRF,
        description="http.Get() with tainted URL",
    ),
    TaintSink(
        module="net/http", function="Post",
        vulnerable_parameters=(0,),
        vulnerability_class=VulnerabilityClass.SSRF,
        description="http.Post() with tainted URL",
    ),
    TaintSink(
        module="net/http", function="NewRequest",
        vulnerable_parameters=(1,),
        vulnerability_class=VulnerabilityClass.SSRF,
        description="http.NewRequest() with tainted URL",
    ),
    TaintSink(
        module="net/http", function="NewRequestWithContext",
        vulnerable_parameters=(2,),
        vulnerability_class=VulnerabilityClass.SSRF,
        description="http.NewRequestWithContext() with tainted URL",
    ),
)

# --- Path Traversal ---

GO_PATH_TRAVERSAL_SINKS: tuple[TaintSink, ...] = (
    TaintSink(
        module="os", function="Open",
        vulnerable_parameters=(0,),
        vulnerability_class=VulnerabilityClass.PATH_TRAVERSAL,
        description="os.Open() with tainted path",
    ),
    TaintSink(
        module="os", function="Create",
        vulnerable_parameters=(0,),
        vulnerability_class=VulnerabilityClass.PATH_TRAVERSAL,
        description="os.Create() with tainted path",
    ),
    TaintSink(
        module="os", function="ReadFile",
        vulnerable_parameters=(0,),
        vulnerability_class=VulnerabilityClass.PATH_TRAVERSAL,
        description="os.ReadFile() with tainted path",
    ),
    TaintSink(
        module="os", function="WriteFile",
        vulnerable_parameters=(0,),
        vulnerability_class=VulnerabilityClass.PATH_TRAVERSAL,
        description="os.WriteFile() with tainted path",
    ),
    TaintSink(
        module="io/ioutil", function="ReadFile",
        vulnerable_parameters=(0,),
        vulnerability_class=VulnerabilityClass.PATH_TRAVERSAL,
        description="ioutil.ReadFile() with tainted path",
    ),
)


def get_all_go_sinks() -> tuple[TaintSink, ...]:
    return GO_SQL_SINKS + GO_RCE_SINKS + GO_SSRF_SINKS + GO_PATH_TRAVERSAL_SINKS


def create_go_sink_registry() -> SinkRegistry:
    registry = SinkRegistry()
    registry.register_all(get_all_go_sinks())
    return registry
```

- [ ] **Step 4: Create `sanitizers.py`**

```python
# src/tainter/models/lang/go/sanitizers.py
"""Go sanitizer definitions."""

from tainter.core.types import Sanitizer, VulnerabilityClass
from tainter.models.registry import SanitizerRegistry

GO_SANITIZERS: tuple[Sanitizer, ...] = (
    Sanitizer(
        module="html", function="EscapeString",
        clears=(VulnerabilityClass.XSS,),
        description="html.EscapeString() HTML entity encoding",
    ),
    Sanitizer(
        module="regexp", function="QuoteMeta",
        clears=(VulnerabilityClass.SQLI,),
        description="regexp.QuoteMeta() escapes regex metacharacters",
    ),
    Sanitizer(
        module="path/filepath", function="Clean",
        clears=(VulnerabilityClass.PATH_TRAVERSAL,),
        description="filepath.Clean() normalizes path traversal sequences",
    ),
)


def get_all_go_sanitizers() -> tuple[Sanitizer, ...]:
    return GO_SANITIZERS


def create_go_sanitizer_registry() -> SanitizerRegistry:
    registry = SanitizerRegistry()
    registry.register_all(get_all_go_sanitizers())
    return registry
```

- [ ] **Step 5: Commit**

```bash
git add src/tainter/models/lang/go/
git commit -m "feat: add Go taint source/sink/sanitizer models"
```

---

## Task 8: Go FlowFinder + Integration Tests

**Files:**
- Create: `src/tainter/analysis/go_flow_finder.py`
- Create: `tests/test_go_analysis.py`

- [ ] **Step 1: Write the failing integration tests**

```python
# tests/test_go_analysis.py
"""Integration tests for Go taint flow analysis."""

from tainter.core.types import Language, VulnerabilityClass
from tainter.engine import EngineConfig, TainterEngine


def _scan_go(tmp_path, go_source: str, filename: str = "main.go"):
    project = tmp_path / "go_project"
    project.mkdir()
    (project / filename).write_text(go_source)
    engine = TainterEngine(
        EngineConfig(include_tests=True, languages=frozenset({Language.GO}))
    )
    result = engine.analyze(project)
    return engine, result


def test_net_http_form_value_to_sql_sink(tmp_path):
    go = """
package main

import (
    "database/sql"
    "net/http"
)

func handler(w http.ResponseWriter, r *http.Request) {
    userId := r.FormValue("id")
    db.Query("SELECT * FROM users WHERE id = " + userId)
}
"""
    _engine, result = _scan_go(tmp_path, go)
    sqli = [f for f in result.flows if f.vulnerability_class == VulnerabilityClass.SQLI]
    assert len(sqli) >= 1


def test_gin_param_to_exec_sink(tmp_path):
    go = """
package main

import (
    "os/exec"
    "github.com/gin-gonic/gin"
)

func handler(c *gin.Context) {
    cmd := c.Param("command")
    exec.Command(cmd)
}
"""
    _engine, result = _scan_go(tmp_path, go)
    rce = [f for f in result.flows if f.vulnerability_class == VulnerabilityClass.RCE]
    assert len(rce) >= 1


def test_echo_query_param_to_file_read(tmp_path):
    go = """
package main

import (
    "os"
    "github.com/labstack/echo/v4"
)

func handler(c echo.Context) error {
    filename := c.QueryParam("file")
    os.Open(filename)
    return nil
}
"""
    _engine, result = _scan_go(tmp_path, go)
    path = [
        f for f in result.flows
        if f.vulnerability_class == VulnerabilityClass.PATH_TRAVERSAL
    ]
    assert len(path) >= 1


def test_go_language_is_active_analyzer(tmp_path):
    go = "package main\n\nfunc main() {}\n"
    engine, result = _scan_go(tmp_path, go)
    assert "go" in result.active_analyzers
    assert result.files_analyzed >= 1
```

- [ ] **Step 2: Run to confirm failure**

```bash
python -m pytest tests/test_go_analysis.py -v
```

Expected: FAIL (GoFlowFinder does not exist yet)

- [ ] **Step 3: Write `go_flow_finder.py`**

```python
# src/tainter/analysis/go_flow_finder.py
"""Go taint flow finder — subclass of BaseFlowFinder."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional

from tainter.analysis.base_flow_finder import BaseFlowFinder
from tainter.core.types import Location, TaintSink, TaintSource, TaintState
from tainter.models.lang.go.sanitizers import create_go_sanitizer_registry
from tainter.models.lang.go.sinks import create_go_sink_registry
from tainter.models.lang.go.sources import create_go_source_registry
from tainter.models.registry import SanitizerRegistry, SinkRegistry, SourceRegistry
from tainter.parser.ast_parser import CallInfo, FunctionInfo, ParsedModule

# Matches both := (short variable declaration) and = (assignment), but not ==
_GO_ASSIGN_RE = re.compile(
    r"^(?P<target>[A-Za-z_]\w*)\s*:?=(?!=)\s*(?P<expr>.+)$"
)
_GO_RETURN_RE = re.compile(r"^return\s+(?P<expr>.+)$")

_GO_HTTP_HANDLER_PARAMS = {"w", "r", "c", "ctx", "req", "res", "request", "response"}


@dataclass
class GoFlowFinder(BaseFlowFinder):
    """Find Go source-to-sink flows using lightweight taint propagation."""

    source_registry: SourceRegistry = field(default_factory=create_go_source_registry)
    sink_registry: SinkRegistry = field(default_factory=create_go_sink_registry)
    sanitizer_registry: SanitizerRegistry = field(
        default_factory=create_go_sanitizer_registry
    )

    def _parse_assignment(self, line: str) -> Optional[tuple[str, str]]:
        m = _GO_ASSIGN_RE.match(line)
        if not m:
            return None
        return (m.group("target"), m.group("expr").strip())

    def _parse_return(self, line: str) -> Optional[str]:
        m = _GO_RETURN_RE.match(line)
        return m.group("expr").strip() if m else None

    def _seed_parameter_taints(
        self, module: ParsedModule, method: FunctionInfo
    ) -> dict[str, TaintState]:
        taints: dict[str, TaintState] = {}
        for param in method.parameters:
            if param.name in _GO_HTTP_HANDLER_PARAMS:
                taints[param.name] = TaintState(
                    is_tainted=True,
                    source=TaintSource(
                        module=module.module_name,
                        function=method.name,
                        attribute=f"param:{param.name}",
                        description="HTTP handler request object",
                    ),
                    source_location=Location(module.file_path, method.line_start),
                )
        return taints

    def _identify_source(
        self, module: ParsedModule, expr: str
    ) -> Optional[TaintSource]:
        for source in self.source_registry.all_sources():
            pattern = source.attribute or source.function
            if re.search(rf"\b{re.escape(pattern)}\s*\(", expr):
                return source
        return None

    def _identify_sink(
        self, module: ParsedModule, call: CallInfo
    ) -> Optional[TaintSink]:
        for sink in self.sink_registry.all_sinks():
            sink_func = sink.function.split(".")[-1]
            if call.callee == sink_func:
                if self._sink_import_compatible(module, sink):
                    return sink
        return None

    def _identify_sanitizer(self, module: ParsedModule, expr: str):
        for sanitizer in self.sanitizer_registry.all_sanitizers():
            sanitizer_name = sanitizer.function.split(".")[-1]
            if re.search(rf"\b{re.escape(sanitizer_name)}\s*\(", expr):
                return sanitizer
        return None

    def _sink_import_compatible(self, module: ParsedModule, sink: TaintSink) -> bool:
        import_paths = [imp.module for imp in module.imports]
        return any(
            imp == sink.module or imp.startswith(sink.module)
            for imp in import_paths
        )
```

- [ ] **Step 4: Wire Go into `engine.py`**

Add to imports in `src/tainter/engine.py`:

```python
from tainter.parser.go_parser import GoParser
from tainter.analysis.go_flow_finder import GoFlowFinder
```

Update `self._parsers` in `TainterEngine.__init__`:

```python
self._parsers: dict[Language, LanguageParser] = {
    Language.PYTHON: PythonParser(),
    Language.JAVA: JavaParser(),
    Language.JAVASCRIPT: JavaScriptParser(),
    Language.GO: GoParser(),
}
```

Add Go flow dispatch in `TainterEngine.analyze`, after the JS block:

```python
go_modules = [m for m in self._modules if m.language == Language.GO]
if go_modules and Language.GO in selected_parsers:
    go_finder = GoFlowFinder(max_call_depth=self.config.max_call_depth)
    go_result = go_finder.analyze_project(go_modules)
    result.flows.extend(go_result.flows)
    result.functions_analyzed += go_result.functions_analyzed
```

- [ ] **Step 5: Run Go integration tests — must pass**

```bash
python -m pytest tests/test_go_analysis.py -v
```

Expected: all PASS

- [ ] **Step 6: Run full suite — no regressions**

```bash
python -m pytest tests/ -v
```

Expected: all PASS

- [ ] **Step 7: Commit**

```bash
git add src/tainter/analysis/go_flow_finder.py tests/test_go_analysis.py src/tainter/engine.py
git commit -m "feat: add Go taint flow analysis"
```

---

## Task 9: Final Integration — Mixed-Language Project Test

**Files:**
- Modify: `tests/test_engine.py` (add multi-language test)

- [ ] **Step 1: Write the failing test**

Add to `tests/test_engine.py`:

```python
def test_mixed_three_language_project(tmp_path):
    from tainter.engine import EngineConfig, TainterEngine

    project = tmp_path / "mixed"
    project.mkdir()

    # Python: Flask SQLi
    (project / "app.py").write_text(
        "from flask import request\nimport os\n\n"
        "def run():\n"
        "    cmd = request.args.get('cmd')\n"
        "    return os.system(cmd)\n"
    )

    # Java: Servlet SQLi
    (project / "Vuln.java").write_text(
        "package com.example;\n"
        "import java.sql.Statement;\n"
        "public class Vuln {\n"
        "  public void run(String userId) throws Exception {\n"
        "    Statement stmt = null;\n"
        '    String query = "SELECT * FROM users WHERE id = " + userId;\n'
        "    stmt.executeQuery(query);\n"
        "  }\n"
        "}\n"
    )

    # JS: Express RCE
    (project / "server.js").write_text(
        "const { exec } = require('child_process');\n"
        "const express = require('express');\n"
        "const app = express();\n"
        "app.get('/run', (req, res) => {\n"
        "    const cmd = req.query.command;\n"
        "    exec(cmd);\n"
        "});\n"
    )

    # Go: net/http SQLi
    (project / "main.go").write_text(
        "package main\n\n"
        'import (\n    "database/sql"\n    "net/http"\n)\n\n'
        "func handler(w http.ResponseWriter, r *http.Request) {\n"
        '    userId := r.FormValue("id")\n'
        '    db.Query("SELECT * FROM users WHERE id = " + userId)\n'
        "}\n"
    )

    engine = TainterEngine(EngineConfig(include_tests=True))
    result = engine.analyze(project)

    active = set(result.active_analyzers)
    assert "python" in active
    assert "java" in active
    assert "javascript" in active
    assert "go" in active
    assert result.flow_count >= 4
```

- [ ] **Step 2: Run to confirm it passes (all wiring done in prior tasks)**

```bash
python -m pytest tests/test_engine.py::test_mixed_three_language_project -v
```

Expected: PASS

- [ ] **Step 3: Run complete test suite one final time**

```bash
python -m pytest tests/ -v --tb=short
```

Expected: all PASS, 0 errors

- [ ] **Step 4: Final commit**

```bash
git add tests/test_engine.py
git commit -m "test: add mixed four-language integration test"
```

---

## Known Limitations (Out of Scope)

- **JS template literals** — taint through `` `SELECT ${userId}` `` not detected. Track as follow-up.
- **Inter-language flows** — cross-service taint not in scope.
- **Type inference** — sink matching is pattern-based, not type-aware.
