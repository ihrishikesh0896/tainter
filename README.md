# 🔍 Tainter

A Python taint analysis engine for identifying **source → sink** vulnerability flows in real-world codebases.

## Features

- **Inter-procedural analysis**: Track taint across function boundaries and multiple files
- **Framework-aware**: Built-in support for Flask, Django, FastAPI, and CLI applications
- **Extensible models**: Define custom sources, sinks, and sanitizers
- **Rich reporting**: JSON and SARIF output with detailed flow explanations

## Vulnerability Classes

Tainter detects flows leading to:

| Class | Description |
|-------|-------------|
| **SQLi** | SQL Injection via unsanitized database queries |
| **RCE** | Remote Code Execution via `eval`, `exec`, `os.system`, etc. |
| **SSTI** | Server-Side Template Injection |
| **SSRF** | Server-Side Request Forgery |
| **Deserialization** | Unsafe deserialization via `pickle`, `yaml.load`, etc. |
| **Path Traversal** | Unvalidated file path operations |

## Installation

```bash
pip install tainter
```

Or for development:

```bash
git clone https://github.com/your-org/tainter.git
cd tainter
pip install -e ".[dev]"
```

## Quick Start

```bash
# Scan a Python project
tainter scan /path/to/project

# Scan with specific vulnerability focus
tainter scan /path/to/project --vuln-class sqli,rce

# Output in SARIF format
tainter scan /path/to/project --format sarif -o results.sarif
```

## How It Works

```
┌─────────┐    ┌─────────┐    ┌─────────┐    ┌─────────┐
│ Sources │───▶│ Taint   │───▶│ Flow    │───▶│ Report  │
│ (input) │    │ Tracker │    │ Finder  │    │ Builder │
└─────────┘    └─────────┘    └─────────┘    └─────────┘
     │              │              │              │
     ▼              ▼              ▼              ▼
  request.args   propagate    find paths    JSON/SARIF
  input()        across       to sinks      with context
  os.environ     functions
```

## Example Output

```json
{
  "flows": [
    {
      "id": "FLOW-001",
      "vulnerability_class": "sqli",
      "confidence": 0.95,
      "source": {
        "file": "app/routes.py",
        "line": 15,
        "code": "user_id = request.args.get('id')"
      },
      "sink": {
        "file": "app/db.py",
        "line": 42,
        "code": "cursor.execute(f\"SELECT * FROM users WHERE id = {user_id}\")"
      },
      "call_chain": [
        "routes.get_user()",
        "db.fetch_user(user_id)"
      ],
      "variable_path": ["user_id", "id_param", "query"]
    }
  ]
}
```

## Architecture

Tainter is built with separation of concerns:

- **Parser**: AST-based Python parsing
- **Graph Builder**: Call graph and data flow graph construction
- **Models**: Extensible source/sink/sanitizer definitions
- **Analyzer**: Taint propagation with path sensitivity
- **Reporter**: Multiple output formats

## Configuration

Create a `tainter.yaml` in your project root:

```yaml
sources:
  - module: "myapp.utils"
    function: "get_user_input"
    returns: tainted

sinks:
  - module: "myapp.db"
    function: "raw_query"
    parameters: [0]
    vulnerability: sqli

sanitizers:
  - module: "myapp.security"
    function: "escape_sql"
    clears: sqli
```

## License

MIT License
