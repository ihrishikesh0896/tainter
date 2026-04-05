"""Tests for Java taint flow analysis."""

from tainter.core.types import Language, VulnerabilityClass
from tainter.engine import EngineConfig, TainterEngine


def _scan_java(tmp_path, java_source: str):
    project = tmp_path / "java_project"
    project.mkdir()
    (project / "Vuln.java").write_text(java_source)
    engine = TainterEngine(EngineConfig(include_tests=True, languages=frozenset({Language.JAVA})))
    result = engine.analyze(project)
    return engine, result


def test_java_parameter_to_sql_sink(tmp_path):
    java = """
package com.example;
import java.sql.Statement;

public class Vuln {
    public void run(String userId) throws Exception {
        Statement stmt = null;
        String query = "SELECT * FROM users WHERE id = " + userId;
        stmt.executeQuery(query);
    }
}
"""
    _engine, result = _scan_java(tmp_path, java)
    sqli = [f for f in result.flows if f.vulnerability_class == VulnerabilityClass.SQLI]
    assert len(sqli) == 1


def test_java_request_source_to_rce_sink(tmp_path):
    java = """
package com.example;
import javax.servlet.http.HttpServletRequest;

public class Vuln {
    public void run(HttpServletRequest request) throws Exception {
        String cmd = request.getParameter("cmd");
        Runtime.getRuntime().exec(cmd);
    }
}
"""
    _engine, result = _scan_java(tmp_path, java)
    rce = [f for f in result.flows if f.vulnerability_class == VulnerabilityClass.RCE]
    assert len(rce) == 1


def test_java_language_is_active_analyzer(tmp_path):
    java = """
package com.example;
public class Vuln {
    public void run(String x) { }
}
"""
    engine, result = _scan_java(tmp_path, java)
    assert result.active_analyzers == ["java"]
    assert result.files_analyzed == 1
    assert all(module.language == Language.JAVA for module in engine.modules)


def test_mixed_python_java_runs_both_analyzers(tmp_path):
    project = tmp_path / "mixed_project"
    project.mkdir()

    (project / "app.py").write_text(
        "from flask import request\nimport os\n\n"
        "def run():\n"
        "    cmd = request.args.get('cmd')\n"
        "    return os.system(cmd)\n"
    )
    (project / "Vuln.java").write_text(
        "package com.example;\n"
        "import java.sql.Statement;\n"
        "public class Vuln {\n"
        "  public void run(String userId) throws Exception {\n"
        "    Statement stmt = null;\n"
        "    String query = \"SELECT * FROM users WHERE id = \" + userId;\n"
        "    stmt.executeQuery(query);\n"
        "  }\n"
        "}\n"
    )

    engine = TainterEngine(EngineConfig(include_tests=True))
    result = engine.analyze(project)

    classes = {flow.vulnerability_class for flow in result.flows}
    assert VulnerabilityClass.RCE in classes
    assert VulnerabilityClass.SQLI in classes
    assert result.active_analyzers == ["java", "python"]
