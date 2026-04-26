# Multi-Language Support: JavaScript & Go — Design Spec

**Date:** 2026-04-24
**Status:** Approved

## Summary

Add JavaScript and Go taint analysis to tainter, mirroring the existing Java implementation. Java is already complete and remains unchanged except for a refactor into the shared `BaseFlowFinder`.

**Languages added:** JavaScript (`.js`, `.ts`), Go (`.go`)
**JS frameworks:** Express, Next.js, NestJS
**Go frameworks:** `net/http`, Gin, Echo

---

## Architecture

### Approach: Shared `BaseFlowFinder` + language subclasses

Extract common taint propagation logic from `JavaFlowFinder` into `analysis/base_flow_finder.py`. Java, JavaScript, and Go each subclass it, overriding only language-specific logic.

**What lives in `BaseFlowFinder` (shared):**
- `analyze_project(modules)` — iterates modules → classes/functions → `_analyze_method`
- `_taint_from_variables(expr, taints)` — regex variable reference scan
- `_sink_argument_taint(call_site, sink, taints)` — argument position matching
- `_create_flow(...)` — assembles `TaintFlow` from taint state + sink
- `_split_arguments(args_blob)` — balanced-paren argument splitter
- Call stack depth tracking

**What language subclasses override:**
- `_seed_parameter_taints()` — Java: all params untrusted; JS/Go: HTTP handler params only
- `_identify_source()` — language-specific source pattern matching
- `_identify_sink()` — language-specific sink + import compatibility check
- `_identify_sanitizer()` — language-specific sanitizer matching
- `_expression_taint()` — handles language idioms (Go `:=`, JS destructuring)

---

## New Files

```
src/tainter/
├── analysis/
│   ├── base_flow_finder.py          # NEW
│   ├── java_flow_finder.py          # REFACTOR — subclass of BaseFlowFinder
│   ├── javascript_flow_finder.py    # NEW
│   └── go_flow_finder.py            # NEW
├── parser/
│   ├── javascript_parser.py         # NEW
│   └── go_parser.py                 # NEW
└── models/lang/
    ├── javascript/
    │   ├── __init__.py
    │   ├── sources.py
    │   ├── sinks.py
    │   └── sanitizers.py
    └── go/
        ├── __init__.py
        ├── sources.py
        ├── sinks.py
        └── sanitizers.py
```

---

## Parsers

Both use regex-based parsing, consistent with `java_parser.py`.

### `javascript_parser.py`
- **Extensions:** `.js`, `.ts`
- **Imports:** `import X from 'y'`, `const X = require('y')`
- **Classes:** `class Foo {`
- **Functions:** named functions, `const foo = async (`, arrow functions, class methods
- **Calls:** `receiver.method(` patterns

### `go_parser.py`
- **Extensions:** `.go`
- **Package:** `package name`
- **Imports:** single `import "pkg"` and grouped `import ( ... )`
- **Functions:** `func Name(params)` and `func (recv Type) Name(params)`
- **Calls:** `receiver.Method(` and `pkg.Func(` patterns

---

## Sources & Sinks

### JavaScript Sources
| Framework | Sources |
|-----------|---------|
| Express | `req.body`, `req.params`, `req.query`, `req.headers`, `req.cookies` |
| Next.js | `req.query`, `context.params`, `searchParams` (API routes & SSR) |
| NestJS | `@Body()`, `@Param()`, `@Query()`, `@Headers()` decorator-injected params |

### JavaScript Sinks
| Class | Sinks |
|-------|-------|
| SQL injection | `query()`, `execute()`, `raw()` |
| RCE | `exec()`, `execSync()`, `spawn()`, `eval()` |
| XSS | `innerHTML`, `dangerouslySetInnerHTML` |
| SSRF | `fetch()`, `axios.get/post`, `http.request()` |
| Path traversal | `fs.readFile()`, `fs.writeFile()`, `fs.readFileSync()` |

### Go Sources
| Framework | Sources |
|-----------|---------|
| `net/http` | `r.URL.Query().Get()`, `r.FormValue()`, `r.Header.Get()`, `r.PathValue()` |
| Gin | `c.Param()`, `c.Query()`, `c.PostForm()`, `c.GetHeader()`, `c.ShouldBind()` |
| Echo | `c.Param()`, `c.QueryParam()`, `c.FormValue()`, `c.Request().Header.Get()` |

### Go Sinks
| Class | Sinks |
|-------|-------|
| SQL injection | `db.Query()`, `db.Exec()`, `db.QueryRow()` |
| RCE | `exec.Command()` |
| SSRF | `http.Get()`, `http.Post()`, `http.NewRequest()` |
| Path traversal | `os.Open()`, `os.ReadFile()`, `ioutil.ReadFile()` |

---

## Engine Wiring (`engine.py`)

```python
self._parsers = {
    Language.PYTHON: PythonParser(),
    Language.JAVA: JavaParser(),
    Language.JAVASCRIPT: JavaScriptParser(),
    Language.GO: GoParser(),
}
self._flow_finders = {
    Language.PYTHON: PythonFlowFinder(),
    Language.JAVA: JavaFlowFinder(),
    Language.JAVASCRIPT: JavaScriptFlowFinder(),
    Language.GO: GoFlowFinder(),
}
```

---

## Known Limitations / Out of Scope

- **JS template literals** (`\`SELECT ${userId}\``) — taint through string interpolation not detected. Tracked as a follow-up.
- **Inter-language flows** — taint crossing JS→Java boundaries (e.g., microservices) not in scope.
- **Type inference** — no type-aware analysis; sink matching is pattern-based.

---

## Testing

Each new language gets an integration test file mirroring `tests/test_java_analysis.py`:
- `tests/test_javascript_analysis.py` — SQLi and RCE detection via Express/Next.js/NestJS
- `tests/test_go_analysis.py` — SQLi and RCE detection via net/http, Gin, Echo
