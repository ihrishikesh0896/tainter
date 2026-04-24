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
    db.query(sqlQuery);
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
    exec(cmd);
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
