"""Tests for the parser module."""

import pytest
from pathlib import Path

from tainter.parser.file_finder import find_python_files, should_ignore_dir
from tainter.parser.ast_parser import parse_file, infer_module_name


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
