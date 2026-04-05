"""Tests for the parser module."""

import pytest
from pathlib import Path

from tainter.core.types import Language
from tainter.parser.file_finder import find_python_files, find_source_files, should_ignore_dir
from tainter.parser.ast_parser import parse_file, infer_module_name
from tainter.parser.java_parser import parse_java_file


class TestFileFinder:
    """Tests for file discovery."""
    
    def test_should_ignore_venv(self):
        assert should_ignore_dir(".venv", frozenset({".venv"}))
        assert should_ignore_dir("venv", frozenset({"venv"}))
    
    def test_should_ignore_pycache(self):
        assert should_ignore_dir("__pycache__", frozenset({"__pycache__"}))
    
    def test_should_not_ignore_src(self):
        assert not should_ignore_dir("src", frozenset({".venv", "__pycache__"}))
    
    def test_should_ignore_egg_info(self):
        assert should_ignore_dir("my_package.egg-info", frozenset({"*.egg-info"}))

    def test_find_source_files_includes_java(self, tmp_path):
        py_file = tmp_path / "app.py"
        java_file = tmp_path / "App.java"
        py_file.write_text("print('x')")
        java_file.write_text("class App {}")

        files = find_source_files(tmp_path)
        discovered = {path.name for path in files.files}
        assert "app.py" in discovered
        assert "App.java" in discovered


class TestASTParser:
    """Tests for AST parsing."""
    
    def test_infer_module_name_simple(self):
        path = Path("/project/mymodule.py")
        assert infer_module_name(path) == "mymodule"
    
    def test_infer_module_name_with_root(self):
        path = Path("/project/src/package/module.py")
        root = Path("/project/src")
        assert infer_module_name(path, root) == "package.module"
    
    def test_infer_module_name_init(self):
        path = Path("/project/package/__init__.py")
        root = Path("/project")
        assert infer_module_name(path, root) == "package"


class TestParseFile:
    """Tests for file parsing."""
    
    def test_parse_vuln_app(self, tmp_path):
        """Test parsing a Python file."""
        code = '''
def hello(name):
    """Say hello."""
    return f"Hello, {name}"

class Greeter:
    def greet(self, name):
        return hello(name)
'''
        test_file = tmp_path / "test.py"
        test_file.write_text(code)
        
        module = parse_file(test_file)
        
        assert module.module_name == "test"
        assert len(module.functions) == 1
        assert module.functions[0].name == "hello"
        assert len(module.classes) == 1
        assert module.classes[0].name == "Greeter"
        assert len(module.classes[0].methods) == 1

    def test_parse_java_file(self, tmp_path):
        code = """
package com.example;

import java.sql.Statement;

public class UserService {
    public String readUser(String userId) {
        String query = "SELECT * FROM users WHERE id = " + userId;
        stmt.executeQuery(query);
        return query;
    }
}
"""
        test_file = tmp_path / "UserService.java"
        test_file.write_text(code)

        module = parse_java_file(test_file, tmp_path)

        assert module.language == Language.JAVA
        assert module.module_name == "com.example.UserService"
        assert len(module.imports) == 1
        assert len(module.classes) == 1
        assert module.classes[0].name == "UserService"
        assert len(module.classes[0].methods) == 1
        assert module.classes[0].methods[0].name == "readUser"
        assert len(module.all_calls) > 0
