"""Regression tests for taint analysis correctness fixes."""

from textwrap import dedent

from tainter.core.types import VulnerabilityClass
from tainter.engine import EngineConfig, TainterEngine


def _scan_code(tmp_path, code: str):
    project = tmp_path / "project"
    project.mkdir()
    (project / "app.py").write_text(dedent(code))

    engine = TainterEngine(EngineConfig(include_tests=True))
    return engine.analyze(project)


def test_builtin_open_is_path_traversal_sink(tmp_path):
    result = _scan_code(
        tmp_path,
        """
        from flask import request

        def read_file():
            filename = request.args.get("filename")
            with open(filename, "r") as handle:
                return handle.read()
        """,
    )

    vuln_classes = {flow.vulnerability_class for flow in result.flows}
    assert VulnerabilityClass.PATH_TRAVERSAL in vuln_classes
    assert VulnerabilityClass.DESERIALIZE not in vuln_classes


def test_keyword_argument_sink_is_detected(tmp_path):
    result = _scan_code(
        tmp_path,
        """
        import requests
        from flask import request

        def fetch():
            url = request.args.get("url")
            return requests.get(url=url)
        """,
    )

    assert any(flow.vulnerability_class == VulnerabilityClass.SSRF for flow in result.flows)


def test_safe_helper_call_does_not_taint_parameters_by_default(tmp_path):
    result = _scan_code(
        tmp_path,
        """
        import os

        def run(cmd):
            return os.system(cmd)

        def safe():
            return run("ls")
        """,
    )

    assert result.flows == []


def test_tainted_argument_propagates_into_helper_function(tmp_path):
    result = _scan_code(
        tmp_path,
        """
        import os
        from flask import request

        def run(cmd):
            return os.system(cmd)

        def handler():
            cmd = request.args.get("cmd")
            return run(cmd)
        """,
    )

    rce_flows = [flow for flow in result.flows if flow.vulnerability_class == VulnerabilityClass.RCE]
    assert len(rce_flows) == 1
    assert rce_flows[0].call_chain == ("app.handler", "app.run")


def test_unsanitized_branch_is_preserved_across_if_merge(tmp_path):
    result = _scan_code(
        tmp_path,
        """
        import os
        from flask import request

        def branch(flag):
            cmd = request.args.get("cmd")
            if flag:
                pass
            else:
                cmd = int(cmd)
            return os.system(cmd)
        """,
    )

    assert any(flow.vulnerability_class == VulnerabilityClass.RCE for flow in result.flows)
