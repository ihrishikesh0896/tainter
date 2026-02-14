#!/usr/bin/env python3
"""
VulnReach Robust Demo Application
----------------------------------
A comprehensive Flask application with multiple intentional vulnerabilities
designed to demonstrate VulnReach's static analysis and reachability detection.

This application contains:
- 10+ vulnerability categories
- Multiple attack vectors per category
- Realistic code patterns and service architecture
- Complex call chains for reachability testing

WARNING: This code is INTENTIONALLY VULNERABLE. 
         Do NOT deploy this in any production or public environment.
"""

from flask import Flask, request, jsonify, render_template_string, send_file
from functools import wraps
import os
import sys

# Add current directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from vuln_module import (
    unsafe_load, unsafe_full_load,
    run_command, run_command_popen, execute_system_cmd,
    # parse_xml_unsafe,
    deserialize_object, deserialize_with_dill, load_saved_model,
    read_file, write_file, serve_static_file,
    render_template, render_greeting,
    query_user, login_user, search_products,
    hash_password_md5, encrypt_data_des, verify_signature_timing_vulnerable,
    render_markdown,
    generate_session_token, generate_reset_code
)
from services.user_service import UserService, AdminService
from services.file_service import FileService
from services.data_service import DataService, DataExporter
from config import (
    DATABASE_CONFIG, API_KEYS, JWT_SECRET,
    UPLOAD_FOLDER, DEBUG_MODE, SESSION_CONFIG
)

app = Flask(__name__)
app.secret_key = SESSION_CONFIG["secret_key"]  # Weak secret
app.debug = DEBUG_MODE  # Debug mode enabled

# Initialize services
user_service = UserService()
admin_service = AdminService()
file_service = FileService()
data_service = DataService()
data_exporter = DataExporter()


# ============================================================
# DIRECT SOURCE-TO-SINK VULNERABILITIES (For Tainter Testing)
# ============================================================
# These patterns have taint flow within the same function for 
# intra-procedural analysis detection.

@app.route("/api/direct/sqli")
def direct_sqli():
    """
    Direct SQL Injection: request.args → cursor.execute
    
    This is a direct source-to-sink flow within the same function.
    """
    import sqlite3
    user_id = request.args.get("id")
    conn = sqlite3.connect(":memory:")
    cursor = conn.cursor()
    # VULNERABLE: Direct taint flow from request to SQL
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
    return jsonify({"result": cursor.fetchall()})


@app.route("/api/direct/rce")
def direct_rce():
    """
    Direct RCE: request.args → eval()
    
    Tainted data flows directly to eval().
    """
    expression = request.args.get("expr")
    # VULNERABLE: Direct eval of user input
    result = eval(expression)
    return jsonify({"result": str(result)})


@app.route("/api/direct/command")
def direct_command_injection():
    """
    Direct Command Injection: request.args → os.system()
    """
    cmd = request.args.get("cmd")
    # VULNERABLE: Direct command execution
    exit_code = os.system(cmd)
    return jsonify({"exit_code": exit_code})


@app.route("/api/direct/ssti")
def direct_ssti():
    """
    Direct SSTI: request.args → render_template_string()
    """
    template = request.args.get("template")
    # VULNERABLE: Direct template injection
    result = render_template_string(template)
    return jsonify({"result": result})


@app.route("/api/direct/pickle", methods=["POST"])
def direct_pickle():
    """
    Direct Deserialization: request.data → pickle.loads()
    """
    import pickle
    data = request.data
    # VULNERABLE: Direct pickle deserialization
    obj = pickle.loads(data)
    return jsonify({"object": str(obj)})


@app.route("/api/direct/yaml", methods=["POST"])
def direct_yaml():
    """
    Direct YAML Deserialization: request.data → yaml.load()
    """
    import yaml
    raw = request.get_data(as_text=True)
    # VULNERABLE: Direct unsafe YAML load
    parsed = yaml.load(raw)
    return jsonify({"parsed": str(parsed)})


@app.route("/api/direct/path")
def direct_path_traversal():
    """
    Direct Path Traversal: request.args → open()
    """
    filename = request.args.get("file")
    # VULNERABLE: Direct file read with user-controlled path
    with open(filename, "r") as f:
        content = f.read()
    return jsonify({"content": content})


@app.route("/api/direct/ssrf")
def direct_ssrf():
    """
    Direct SSRF: request.args → requests.get()
    """
    import requests as req
    url = request.args.get("url")
    # VULNERABLE: Direct SSRF
    response = req.get(url)
    return jsonify({"content": response.text[:500]})


# ============================================================
# YAML Deserialization Endpoints (CVE-2020-1747)
# ============================================================

@app.route("/api/yaml/load", methods=["POST"])
def yaml_load():
    """
    Endpoint that deserializes YAML using unsafe yaml.load.
    
    Call chain: route → unsafe_load → yaml.load
    Vulnerability: Arbitrary code execution
    """
    raw = request.get_data(as_text=True)
    parsed = unsafe_load(raw)
    return jsonify({"parsed": str(parsed)})


@app.route("/api/yaml/full-load", methods=["POST"])
def yaml_full_load():
    """
    Endpoint using yaml.full_load.
    
    Call chain: route → unsafe_full_load → yaml.full_load
    """
    raw = request.get_data(as_text=True)
    parsed = unsafe_full_load(raw)
    return jsonify({"parsed": str(parsed)})


@app.route("/api/config/import", methods=["POST"])
def import_config():
    """
    Imports YAML configuration via DataService.
    
    Call chain: route → data_service.import_yaml_data → unsafe_load → yaml.load
    """
    yaml_data = request.get_data(as_text=True)
    config = data_service.import_yaml_data(yaml_data)
    return jsonify({"config": str(config)})


# ============================================================
# Command Injection Endpoints
# ============================================================

@app.route("/api/exec/run", methods=["GET", "POST"])
def run():
    """
    Executes shell commands (shell=True).
    
    Call chain: route → run_command → subprocess.check_output(shell=True)
    """
    cmd = request.args.get("cmd") or request.json.get("cmd", "")
    output = run_command(cmd)
    return jsonify({"output": output.decode(errors="ignore")})


@app.route("/api/exec/popen")
def run_popen():
    """
    Executes commands via Popen.
    
    Call chain: route → run_command_popen → subprocess.Popen(shell=True)
    """
    cmd = request.args.get("cmd", "")
    output = run_command_popen(cmd)
    return jsonify({"output": output})


@app.route("/api/exec/system")
def run_system():
    """
    Executes commands via os.system.
    
    Call chain: route → execute_system_cmd → os.system
    """
    cmd = request.args.get("cmd", "")
    exit_code = execute_system_cmd(cmd)
    return jsonify({"exit_code": exit_code})


@app.route("/api/admin/maintenance")
def admin_maintenance():
    """
    Admin maintenance command execution.
    
    Call chain: route → admin_service.execute_maintenance_command → run_command
    """
    command = request.args.get("command", "")
    output = admin_service.execute_maintenance_command(command)
    return jsonify({"output": output.decode(errors="ignore") if isinstance(output, bytes) else output})


# ============================================================
# XML External Entity (XXE) Endpoints
# ============================================================

# @app.route("/api/xml/parse", methods=["POST"])
# def parse_xml():
#     """
#     Parses XML with external entity processing enabled.
    
#     Call chain: route → parse_xml_unsafe → etree.fromstring(resolve_entities=True)
#     Vulnerability: XXE - read local files, SSRF
#     """
#     xml_data = request.get_data(as_text=True)
#     root = parse_xml_unsafe(xml_data)
#     return jsonify({
#         "tag": root.tag,
#         "text": root.text,
#         "children": [child.tag for child in root]
#     })


# @app.route("/api/xml/upload", methods=["POST"])
# def upload_xml():
#     """
#     Processes uploaded XML via FileService.
    
#     Call chain: route → file_service.process_xml_upload → parse_xml_unsafe
#     """
#     xml_content = request.get_data(as_text=True)
#     result = file_service.process_xml_upload(xml_content)
#     return jsonify(result)


# ============================================================
# Pickle Deserialization Endpoints (RCE)
# ============================================================

@app.route("/api/pickle/load", methods=["POST"])
def pickle_load():
    """
    Deserializes pickle data.
    
    Call chain: route → deserialize_object → pickle.loads
    Vulnerability: Arbitrary code execution
    """
    import base64
    pickle_b64 = request.get_data(as_text=True)
    pickle_bytes = base64.b64decode(pickle_b64)
    obj = deserialize_object(pickle_bytes)
    return jsonify({"object": str(obj)})


@app.route("/api/dill/load", methods=["POST"])
def dill_load():
    """
    Deserializes dill data.
    
    Call chain: route → deserialize_with_dill → dill.loads
    """
    import base64
    dill_b64 = request.get_data(as_text=True)
    dill_bytes = base64.b64decode(dill_b64)
    obj = deserialize_with_dill(dill_bytes)
    return jsonify({"object": str(obj)})


@app.route("/api/model/load")
def model_load():
    """
    Loads a "ML model" from disk (common vulnerable pattern).
    
    Call chain: route → load_saved_model → pickle.load
    """
    filepath = request.args.get("path", "")
    model = load_saved_model(filepath)
    return jsonify({"model_type": str(type(model))})


@app.route("/api/data/import", methods=["POST"])
def import_pickle_data():
    """
    Imports pickle data via DataService.
    
    Call chain: route → data_service.import_pickle_data → deserialize_object → pickle.loads
    """
    pickle_b64 = request.get_data(as_text=True)
    obj = data_service.import_pickle_data(pickle_b64)
    return jsonify({"object": str(obj)})


# ============================================================
# Path Traversal Endpoints
# ============================================================

@app.route("/api/files/read")
def files_read():
    """
    Reads a file with path traversal vulnerability.
    
    Call chain: route → read_file → open(path)
    Vulnerability: Read arbitrary files like /etc/passwd
    """
    base = request.args.get("base", "/tmp")
    filename = request.args.get("file", "")
    content = read_file(base, filename)
    return jsonify({"content": content})


@app.route("/api/files/download")
def files_download():
    """
    Downloads a file via FileService.
    
    Call chain: route → file_service.download_file → open(path)
    """
    filename = request.args.get("file", "")
    content = file_service.download_file(filename)
    return content, 200, {"Content-Type": "application/octet-stream"}


@app.route("/api/files/upload", methods=["POST"])
def files_upload():
    """
    Uploads a file with path traversal.
    
    Call chain: route → file_service.upload_file → open(path, 'wb')
    """
    filename = request.args.get("filename", "upload.bin")
    content = request.get_data()
    filepath = file_service.upload_file(filename, content)
    return jsonify({"path": filepath})


@app.route("/api/files/list")
def files_list():
    """
    Lists directory contents.
    
    Call chain: route → file_service.list_directory → os.listdir
    """
    path = request.args.get("path", "")
    files = file_service.list_directory(path)
    return jsonify({"files": files})


@app.route("/api/static/<path:filename>")
def static_serve(filename):
    """
    Serves static files with path traversal.
    
    Call chain: route → serve_static_file → open(path)
    """
    content = serve_static_file(filename)
    return content


# ============================================================
# Server-Side Template Injection (SSTI) Endpoints
# ============================================================

@app.route("/api/template/render", methods=["POST"])
def template_render():
    """
    Renders a user-provided template.
    
    Call chain: route → render_template → Template(user_input).render()
    Vulnerability: Execute arbitrary Python code
    """
    template_str = request.json.get("template", "")
    context = request.json.get("context", {})
    result = render_template(template_str, context)
    return jsonify({"rendered": result})


@app.route("/api/greeting")
def greeting():
    """
    Renders a greeting with user name.
    
    Call chain: route → render_greeting → Template(name).render()
    """
    name = request.args.get("name", "World")
    result = render_greeting(name)
    return jsonify({"greeting": result})


@app.route("/api/email/preview", methods=["POST"])
def email_preview():
    """
    Previews an email template via DataService.
    
    Call chain: route → data_service.generate_email_content → render_template
    """
    template = request.json.get("template", "")
    user_data = request.json.get("user", {})
    content = data_service.generate_email_content(template, user_data)
    return jsonify({"preview": content})


# ============================================================
# SQL Injection Endpoints
# ============================================================

@app.route("/api/users/search")
def users_search():
    """
    Searches for a user with SQL injection.
    
    Call chain: route → query_user → cursor.execute(f-string)
    """
    db_path = request.args.get("db", ":memory:")
    username = request.args.get("username", "")
    result = query_user(db_path, username)
    return jsonify({"user": result})


@app.route("/api/products/search")
def products_search():
    """
    Searches products with SQL injection.
    
    Call chain: route → search_products → cursor.execute(concatenated SQL)
    """
    db_path = request.args.get("db", ":memory:")
    search_term = request.args.get("q", "")
    results = search_products(db_path, search_term)
    return jsonify({"products": results})


@app.route("/api/auth/login", methods=["POST"])
def auth_login():
    """
    Login endpoint with SQL injection.
    
    Call chain: route → login_user → cursor.execute(f-string SQL)
    """
    db_path = request.json.get("db", ":memory:")
    username = request.json.get("username", "")
    password = request.json.get("password", "")
    success = login_user(db_path, username, password)
    return jsonify({"authenticated": success})


# ============================================================
# Authentication Endpoints (Multiple Vulnerabilities)
# ============================================================

@app.route("/api/auth/register", methods=["POST"])
def auth_register():
    """
    User registration with SQL injection and weak hashing.
    
    Call chain: route → user_service.register_user → hash_password_md5 + SQL injection
    """
    data = request.json
    user_id = user_service.register_user(
        data.get("username"),
        data.get("password"),
        data.get("email")
    )
    return jsonify({"user_id": user_id})


@app.route("/api/auth/authenticate", methods=["POST"])
def auth_authenticate():
    """
    Authentication with SQL injection.
    
    Call chain: route → user_service.authenticate → SQL injection + weak hash
    """
    data = request.json
    user = user_service.authenticate(
        data.get("username"),
        data.get("password")
    )
    if user:
        token = user_service.create_jwt_token(user)
        return jsonify({"token": token, "user": user})
    return jsonify({"error": "Invalid credentials"}), 401


@app.route("/api/auth/reset-password", methods=["POST"])
def auth_reset_password():
    """
    Password reset with predictable code.
    
    Call chain: route → user_service.request_password_reset → generate_reset_code (predictable)
    """
    email = request.json.get("email")
    code = user_service.request_password_reset(email)
    if code:
        # In real app, this would be sent via email
        # Intentionally exposing for demo
        return jsonify({"message": "Reset code sent", "code": code})
    return jsonify({"error": "Email not found"}), 404


# ============================================================
# SSRF Endpoints
# ============================================================

@app.route("/api/fetch")
def fetch_url():
    """
    Fetches external URL (SSRF).
    
    Call chain: route → data_service.fetch_external_resource → requests.get(user_url)
    Vulnerability: Access internal services, cloud metadata
    """
    url = request.args.get("url", "")
    content = data_service.fetch_external_resource(url)
    return jsonify({"content": content})


@app.route("/api/proxy", methods=["POST"])
def proxy():
    """
    Full HTTP proxy (SSRF).
    
    Call chain: route → data_service.proxy_request → requests.request(method, url, data)
    """
    data = request.json
    result = data_service.proxy_request(
        data.get("method", "GET"),
        data.get("url", ""),
        data.get("data")
    )
    return jsonify(result)


@app.route("/api/webhook/register", methods=["POST"])
def webhook_register():
    """
    Registers a webhook URL (stored SSRF).
    
    Call chain: route → data_service.register_webhook → store URL
    """
    data = request.json
    data_service.register_webhook(data.get("name"), data.get("url"))
    return jsonify({"status": "registered"})


@app.route("/api/webhook/trigger")
def webhook_trigger():
    """
    Triggers a stored webhook (SSRF).
    
    Call chain: route → data_service.trigger_webhook → requests.post(stored_url)
    """
    name = request.args.get("name", "")
    payload = request.args.get("payload", "{}")
    import json
    result = data_service.trigger_webhook(name, json.loads(payload))
    return jsonify({"result": result})


# ============================================================
# Markdown Processing (CVE-2022-34749)
# ============================================================

@app.route("/api/markdown/render", methods=["POST"])
def markdown_render():
    """
    Renders markdown content.
    
    Call chain: route → render_markdown → mistune.markdown
    Vulnerability: XSS, potential code execution in old versions
    """
    content = request.get_data(as_text=True)
    html = render_markdown(content)
    return html, 200, {"Content-Type": "text/html"}


@app.route("/api/document/process", methods=["POST"])
def document_process():
    """
    Processes a markdown document via FileService.
    
    Call chain: route → file_service.process_markdown_document → render_markdown
    """
    content = request.get_data(as_text=True)
    html = file_service.process_markdown_document(content)
    return html, 200, {"Content-Type": "text/html"}


# ============================================================
# Archive Extraction (Zip Slip)
# ============================================================

@app.route("/api/archive/extract", methods=["POST"])
def archive_extract():
    """
    Extracts uploaded archive.
    
    Call chain: route → file_service.extract_archive → tarfile.extract
    Vulnerability: Zip slip - write files outside intended directory
    """
    archive_path = request.args.get("path", "")
    extracted = file_service.extract_archive(archive_path)
    return jsonify({"extracted": extracted})


@app.route("/api/archive/extract-zip", methods=["POST"])
def archive_extract_zip():
    """
    Extracts a zip file.
    
    Call chain: route → file_service.extract_zip → zipfile.extract
    """
    zip_path = request.args.get("path", "")
    extracted = file_service.extract_zip(zip_path)
    return jsonify({"extracted": extracted})


# ============================================================
# Weak Cryptography Endpoints
# ============================================================

@app.route("/api/crypto/hash")
def crypto_hash():
    """
    Hashes data with MD5.
    
    Call chain: route → hash_password_md5 → hashlib.md5
    Vulnerability: MD5 is cryptographically broken
    """
    data = request.args.get("data", "")
    hashed = hash_password_md5(data)
    return jsonify({"hash": hashed})


@app.route("/api/crypto/encrypt", methods=["POST"])
def crypto_encrypt():
    """
    Encrypts data with DES.
    
    Call chain: route → encrypt_data_des → DES.new(ECB mode)
    Vulnerability: DES is obsolete, ECB mode is insecure
    """
    data = request.json.get("data", "")
    key = request.json.get("key", "12345678").encode()
    encrypted = encrypt_data_des(key, data)
    import base64
    return jsonify({"encrypted": base64.b64encode(encrypted).decode()})


@app.route("/api/crypto/verify")
def crypto_verify():
    """
    Verifies a signature with timing-vulnerable comparison.
    
    Call chain: route → verify_signature_timing_vulnerable → string comparison
    Vulnerability: Timing attack reveals secret character by character
    """
    provided = request.args.get("signature", "")
    expected = request.args.get("expected", "secret123")
    valid = verify_signature_timing_vulnerable(provided, expected)
    return jsonify({"valid": valid})


# ============================================================
# Admin Endpoints (Multiple Vulnerabilities)
# ============================================================

@app.route("/api/admin/users")
def admin_users():
    """
    Lists all users (no auth required - broken access control).
    
    Call chain: route → admin_service.get_all_users
    Vulnerability: Missing authentication
    """
    users = admin_service.get_all_users()
    return jsonify({"users": users})


@app.route("/api/admin/delete-user", methods=["DELETE"])
def admin_delete_user():
    """
    Deletes a user (SQL injection + no auth).
    
    Call chain: route → admin_service.delete_user → SQL injection
    """
    username = request.args.get("username", "")
    deleted = admin_service.delete_user(username)
    return jsonify({"deleted": deleted})


# ============================================================
# Debug / Information Disclosure Endpoints
# ============================================================

@app.route("/api/debug/config")
def debug_config():
    """
    Exposes configuration including secrets.
    
    Vulnerability: Information disclosure
    """
    return jsonify({
        "database": DATABASE_CONFIG,
        "api_keys": API_KEYS,
        "jwt_secret": JWT_SECRET,
        "debug": DEBUG_MODE
    })


@app.route("/api/debug/env")
def debug_env():
    """
    Exposes environment variables.
    
    Vulnerability: Information disclosure
    """
    return jsonify(dict(os.environ))


@app.route("/api/debug/error")
def debug_error():
    """
    Endpoint that triggers an error with stack trace.
    
    Vulnerability: Information disclosure via error messages
    """
    # Intentional error
    undefined_var  # noqa: F821


# ============================================================
# Error Handlers
# ============================================================

@app.errorhandler(Exception)
def handle_error(e):
    """
    Global error handler that exposes stack traces.
    
    Vulnerability: Information disclosure
    """
    import traceback
    return jsonify({
        "error": str(e),
        "type": type(e).__name__,
        "traceback": traceback.format_exc()  # VULNERABLE: Stack trace exposure
    }), 500


# ============================================================
# Main Entry Point
# ============================================================

if __name__ == "__main__":
    print("=" * 60)
    print("WARNING: This application is INTENTIONALLY VULNERABLE!")
    print("Do NOT deploy in production or expose to the internet!")
    print("=" * 60)
    print()
    print("VulnReach Demo Server starting...")
    print("Endpoints available at http://127.0.0.1:5000/api/...")
    print()
    
    # Running on localhost with debug mode
    app.run(host="127.0.0.1", port=5000, debug=DEBUG_MODE)