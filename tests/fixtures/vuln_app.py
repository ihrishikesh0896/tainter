"""
Vulnerable Flask application for testing Tainter.

This file contains intentional vulnerabilities to verify detection.
"""

from flask import Flask, request, render_template_string
import sqlite3
import os
import subprocess
import pickle
import yaml


app = Flask(__name__)


# =============================================================================
# SQL INJECTION VULNERABILITIES
# =============================================================================

@app.route("/user")
def get_user():
    """SQLi: Direct string interpolation in SQL query."""
    user_id = request.args.get("id")
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    # VULNERABLE: Tainted data directly in SQL
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
    return str(cursor.fetchall())


@app.route("/search")
def search_users():
    """SQLi: String concatenation in SQL query."""
    query = request.args.get("q")
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    # VULNERABLE: Tainted data concatenated to SQL
    sql = "SELECT * FROM users WHERE name LIKE '%" + query + "%'"
    cursor.execute(sql)
    return str(cursor.fetchall())


# =============================================================================
# REMOTE CODE EXECUTION VULNERABILITIES
# =============================================================================

@app.route("/calc")
def calculator():
    """RCE: eval() with user input."""
    expression = request.args.get("expr")
    # VULNERABLE: Direct eval of user input
    result = eval(expression)
    return str(result)


@app.route("/run")
def run_command():
    """RCE: os.system() with user input."""
    cmd = request.args.get("cmd")
    # VULNERABLE: Direct command execution
    os.system(cmd)
    return "Command executed"


@app.route("/exec")
def execute():
    """RCE: subprocess with shell=True."""
    command = request.args.get("command")
    # VULNERABLE: Shell command injection
    output = subprocess.check_output(command, shell=True)
    return output


# =============================================================================
# SERVER-SIDE TEMPLATE INJECTION
# =============================================================================

@app.route("/greet")
def greet():
    """SSTI: render_template_string with user input."""
    name = request.args.get("name")
    # VULNERABLE: User input directly in template
    template = f"<h1>Hello, {name}!</h1>"
    return render_template_string(template)


@app.route("/template")
def custom_template():
    """SSTI: User controls entire template."""
    template = request.args.get("template")
    # VULNERABLE: User-controlled template
    return render_template_string(template)


# =============================================================================
# DESERIALIZATION VULNERABILITIES
# =============================================================================

@app.route("/load", methods=["POST"])
def load_data():
    """Deserialization: pickle.loads with user data."""
    data = request.data
    # VULNERABLE: Deserializing untrusted pickle data
    obj = pickle.loads(data)
    return str(obj)


@app.route("/config", methods=["POST"])
def load_config():
    """Deserialization: yaml.load with user data."""
    yaml_data = request.data.decode()
    # VULNERABLE: Unsafe YAML loading
    config = yaml.load(yaml_data)
    return str(config)


# =============================================================================
# SSRF VULNERABILITIES
# =============================================================================

@app.route("/fetch")
def fetch_url():
    """SSRF: requests.get with user-controlled URL."""
    import requests
    url = request.args.get("url")
    # VULNERABLE: Fetching user-controlled URL
    response = requests.get(url)
    return response.text


# =============================================================================
# PATH TRAVERSAL VULNERABILITIES
# =============================================================================

@app.route("/file")
def read_file():
    """Path Traversal: open() with user-controlled path."""
    filename = request.args.get("filename")
    # VULNERABLE: Reading user-controlled file path
    with open(filename, "r") as f:
        return f.read()


@app.route("/download")
def download():
    """Path Traversal: Path concatenation."""
    name = request.args.get("name")
    # VULNERABLE: Path concatenation without validation
    path = "/var/www/files/" + name
    with open(path, "rb") as f:
        return f.read()


# =============================================================================
# SAFE EXAMPLES (Should NOT be flagged)
# =============================================================================

@app.route("/safe/user")
def get_user_safe():
    """SAFE: Parameterized query."""
    user_id = request.args.get("id")
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    # SAFE: Parameterized query
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    return str(cursor.fetchall())


@app.route("/safe/calc")
def calculator_safe():
    """SAFE: Input validation before eval."""
    expression = request.args.get("expr")
    # SAFE: Convert to int (sanitizer)
    value = int(expression)
    return str(value * 2)


@app.route("/safe/file")
def read_file_safe():
    """SAFE: basename sanitizes path."""
    filename = request.args.get("filename")
    # SAFE: basename removes directory traversal
    safe_name = os.path.basename(filename)
    path = os.path.join("/var/www/files/", safe_name)
    with open(path, "r") as f:
        return f.read()


if __name__ == "__main__":
    app.run(debug=True)
