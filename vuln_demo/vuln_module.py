#!/usr/bin/env python3
"""
Vulnerable Utility Module
-------------------------
Contains various insecure patterns for VulnReach demonstration:

1. **Unsafe YAML deserialization** – CVE-2020-1747
2. **Command injection** – Direct shell execution
3. **XML External Entity (XXE)** – Unsafe XML parsing
4. **Pickle deserialization** – RCE via dill/pickle
5. **Path traversal** – Unrestricted file access
6. **Unsafe template rendering** – SSTI vulnerability
7. **Weak cryptography** – Insecure encryption
8. **SQL Injection** – Raw query execution
"""

import os
import subprocess
import sqlite3
import hashlib
import pickle
from typing import Any, Optional

import yaml
import dill
from jinja2 import Template
from Crypto.Cipher import DES  # Weak cipher
import mistune

# ============================================================
# YAML Deserialization (CVE-2020-1747)
# ============================================================

def unsafe_load(data: str) -> Any:
    """
    Deserialises YAML using the unsafe `yaml.load` API.
    This function is deliberately vulnerable; an attacker can craft a payload
    that executes arbitrary Python code.
    
    Vulnerable call: yaml.load without Loader parameter
    """
    # NOTE: `Loader=yaml.SafeLoader` would be safe – we *omit* it on purpose.
    return yaml.load(data)  # <-- VulnReach should flag this as a reachable sink.


def unsafe_full_load(data: str) -> Any:
    """
    Uses yaml.full_load which is still vulnerable in older versions.
    """
    return yaml.full_load(data)


# ============================================================
# Command Injection
# ============================================================

def run_command(cmd: str) -> bytes:
    """
    Executes a shell command without any validation.
    The function is a textbook command-injection vector.
    """
    return subprocess.check_output(cmd, shell=True)  # shell=True is dangerous


def run_command_popen(cmd: str) -> str:
    """
    Alternative command execution using Popen.
    Equally dangerous with shell=True.
    """
    proc = subprocess.Popen(
        cmd,
        shell=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    stdout, stderr = proc.communicate()
    return stdout.decode() + stderr.decode()


def execute_system_cmd(cmd: str) -> int:
    """
    Uses os.system which is always shell-based.
    """
    return os.system(cmd)  # Vulnerable to command injection


# ============================================================
# XML External Entity (XXE)
# ============================================================

# def parse_xml_unsafe(xml_data: str) -> etree._Element:
#     """
#     Parses XML without disabling external entity processing.
#     Vulnerable to XXE attacks that can read local files or perform SSRF.
#     """
#     parser = etree.XMLParser(resolve_entities=True, load_dtd=True)
#     return etree.fromstring(xml_data.encode(), parser=parser)


# def parse_xml_from_file(filepath: str) -> etree._Element:
#     """
#     Parses XML from a file, vulnerable to XXE.
#     """
#     with open(filepath, 'rb') as f:
#         return etree.parse(f)  # Default parser is vulnerable


# ============================================================
# Pickle Deserialization (RCE)
# ============================================================

def deserialize_object(data: bytes) -> Any:
    """
    Deserializes arbitrary pickle data.
    An attacker can craft malicious pickle data to execute arbitrary code.
    """
    return pickle.loads(data)  # <-- RCE vulnerability


def deserialize_with_dill(data: bytes) -> Any:
    """
    Uses dill library which extends pickle.
    Equally dangerous for deserialization attacks.
    """
    return dill.loads(data)  # <-- RCE vulnerability


def load_saved_model(filepath: str) -> Any:
    """
    Loads a "model" from disk using pickle.
    Common pattern in ML applications, vulnerable to RCE.
    """
    with open(filepath, 'rb') as f:
        return pickle.load(f)


# ============================================================
# Path Traversal
# ============================================================

def read_file(base_dir: str, filename: str) -> str:
    """
    Reads a file from a directory without sanitizing the filename.
    Vulnerable to path traversal (e.g., ../../etc/passwd).
    """
    filepath = os.path.join(base_dir, filename)
    with open(filepath, 'r') as f:
        return f.read()


def write_file(base_dir: str, filename: str, content: str) -> None:
    """
    Writes to a file without path sanitization.
    Can write to arbitrary locations on the filesystem.
    """
    filepath = os.path.join(base_dir, filename)
    with open(filepath, 'w') as f:
        f.write(content)


def serve_static_file(filename: str) -> bytes:
    """
    Serves a static file from /var/www without validation.
    """
    filepath = f"/var/www/static/{filename}"
    with open(filepath, 'rb') as f:
        return f.read()


# ============================================================
# Server-Side Template Injection (SSTI)
# ============================================================

def render_template(template_str: str, context: dict) -> str:
    """
    Renders a user-provided template string.
    Vulnerable to SSTI attacks that can execute arbitrary Python code.
    """
    template = Template(template_str)
    return template.render(**context)


def render_greeting(name: str) -> str:
    """
    Simple greeting that uses template rendering.
    If 'name' comes from user input, this is vulnerable.
    """
    template = Template(f"Hello, {name}!")  # Vulnerable: user input in template
    return template.render()


# ============================================================
# SQL Injection
# ============================================================

def query_user(db_path: str, username: str) -> Optional[tuple]:
    """
    Queries a user by username using string formatting.
    Classic SQL injection vulnerability.
    """
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    # DANGEROUS: String concatenation in SQL
    query = f"SELECT * FROM users WHERE username = '{username}'"
    cursor.execute(query)
    result = cursor.fetchone()
    conn.close()
    return result


def login_user(db_path: str, username: str, password: str) -> bool:
    """
    Authenticates a user with SQL injection vulnerability.
    """
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    # DANGEROUS: f-string SQL injection
    query = f"SELECT id FROM users WHERE username = '{username}' AND password = '{password}'"
    cursor.execute(query)
    result = cursor.fetchone()
    conn.close()
    return result is not None


def search_products(db_path: str, search_term: str) -> list:
    """
    Searches products with LIKE clause.
    Vulnerable to SQL injection.
    """
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    # DANGEROUS: Direct string interpolation
    query = "SELECT * FROM products WHERE name LIKE '%" + search_term + "%'"
    cursor.execute(query)
    results = cursor.fetchall()
    conn.close()
    return results


# ============================================================
# Weak Cryptography
# ============================================================

def hash_password_md5(password: str) -> str:
    """
    Hashes a password using MD5.
    MD5 is cryptographically broken and unsuitable for password hashing.
    """
    return hashlib.md5(password.encode()).hexdigest()


def hash_password_sha1(password: str) -> str:
    """
    Hashes a password using SHA1.
    SHA1 is deprecated for security purposes.
    """
    return hashlib.sha1(password.encode()).hexdigest()


def encrypt_data_des(key: bytes, data: str) -> bytes:
    """
    Encrypts data using DES.
    DES is obsolete and easily broken (56-bit key).
    """
    # DES requires 8-byte key
    key = key[:8].ljust(8, b'\0')
    cipher = DES.new(key, DES.MODE_ECB)  # ECB mode is insecure
    # Pad data to 8-byte blocks
    padded_data = data.encode().ljust((len(data) // 8 + 1) * 8, b'\0')
    return cipher.encrypt(padded_data)


def verify_signature_timing_vulnerable(provided: str, expected: str) -> bool:
    """
    Compares two strings in a timing-attack vulnerable way.
    Attackers can determine the secret character by character.
    """
    if len(provided) != len(expected):
        return False
    for a, b in zip(provided, expected):
        if a != b:
            return False  # Early return reveals information
    return True


# ============================================================
# Markdown Processing (CVE-2022-34749)
# ============================================================

def render_markdown(content: str) -> str:
    """
    Renders Markdown using vulnerable mistune version.
    Can lead to XSS or arbitrary code execution.
    """
    return mistune.markdown(content)


def render_markdown_with_plugin(content: str) -> str:
    """
    Another markdown rendering path.
    """
    md = mistune.Markdown()
    return md(content)


# ============================================================
# Insecure Random
# ============================================================

import random  # noqa: E402

def generate_session_token() -> str:
    """
    Generates a session token using the insecure random module.
    The random module uses a predictable PRNG not suitable for security.
    """
    chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    return "".join(random.choice(chars) for _ in range(32))


def generate_reset_code() -> str:
    """
    Generates a password reset code.
    Using random.randint is predictable.
    """
    return str(random.randint(100000, 999999))