"""Integration tests for Go taint flow analysis."""

from tainter.core.types import Language, VulnerabilityClass
from tainter.engine import EngineConfig, TainterEngine


def _scan_go(tmp_path, go_source: str, filename: str = "handler.go"):
    project = tmp_path / "go_project"
    project.mkdir()
    (project / filename).write_text(go_source)
    engine = TainterEngine(
        EngineConfig(include_tests=True, languages=frozenset({Language.GO}))
    )
    result = engine.analyze(project)
    return engine, result


def test_net_http_query_to_sql_sink(tmp_path):
    go = """
package handler

import (
    "database/sql"
    "net/http"
)

func GetUser(w http.ResponseWriter, r *http.Request) {
    id := r.FormValue("id")
    db.Query(id)
}
"""
    _engine, result = _scan_go(tmp_path, go)
    sqli = [f for f in result.flows if f.vulnerability_class == VulnerabilityClass.SQLI]
    assert len(sqli) >= 1


def test_net_http_query_to_rce_sink(tmp_path):
    go = """
package handler

import (
    "os/exec"
    "net/http"
)

func RunCmd(w http.ResponseWriter, r *http.Request) {
    cmd := r.FormValue("cmd")
    exec.Command(cmd)
}
"""
    _engine, result = _scan_go(tmp_path, go)
    rce = [f for f in result.flows if f.vulnerability_class == VulnerabilityClass.RCE]
    assert len(rce) >= 1


def test_net_http_query_to_path_traversal(tmp_path):
    go = """
package handler

import (
    "os"
    "net/http"
)

func ReadFile(w http.ResponseWriter, r *http.Request) {
    filename := r.FormValue("file")
    os.Open(filename)
}
"""
    _engine, result = _scan_go(tmp_path, go)
    path = [
        f for f in result.flows
        if f.vulnerability_class == VulnerabilityClass.PATH_TRAVERSAL
    ]
    assert len(path) >= 1


def test_go_language_is_active_analyzer(tmp_path):
    go = """
package main

import "net/http"

func main() {}
"""
    engine, result = _scan_go(tmp_path, go)
    assert "go" in result.active_analyzers
    assert result.files_analyzed >= 1
