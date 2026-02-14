#!/usr/bin/env python3
"""
File Service
------------
Handles file operations with intentional security vulnerabilities.
Demonstrates path traversal, arbitrary file read/write, and XXE attacks.
"""

import os
import hashlib
from typing import Optional, List, Tuple
from werkzeug.utils import secure_filename

from vuln_module import (
    read_file,
    write_file,
    # parse_xml_unsafe,
    parse_xml_from_file,
    render_markdown,
    unsafe_load
)
from config import UPLOAD_FOLDER, ALLOWED_EXTENSIONS


class FileService:
    """
    File management service with multiple file-handling vulnerabilities.
    """
    
    def __init__(self, base_path: str = UPLOAD_FOLDER):
        self.base_path = base_path
        os.makedirs(base_path, exist_ok=True)
    
    # ============================================================
    # File Upload (Path Traversal Vulnerabilities)
    # ============================================================
    
    def upload_file(self, filename: str, content: bytes) -> str:
        """
        Uploads a file without proper sanitization.
        
        Vulnerability: Path traversal via filename (e.g., ../../etc/cron.d/evil)
        """
        # VULNERABLE: No sanitization of filename
        filepath = os.path.join(self.base_path, filename)
        
        with open(filepath, 'wb') as f:
            f.write(content)
        
        return filepath
    
    def upload_file_weak_sanitization(self, filename: str, content: bytes) -> str:
        """
        Uploads a file with weak sanitization.
        
        Vulnerability: Only removes leading slashes, still allows ../../ 
        """
        # Weak sanitization: only strips leading slash
        sanitized = filename.lstrip('/')
        filepath = os.path.join(self.base_path, sanitized)
        
        with open(filepath, 'wb') as f:
            f.write(content)
        
        return filepath
    
    def upload_file_with_extension_check(self, filename: str, content: bytes) -> str:
        """
        Uploads a file with extension check (bypassable).
        
        Vulnerability: Extension check doesn't prevent path traversal
        """
        # Extension check can be bypassed with double extensions
        ext = filename.rsplit('.', 1)[-1].lower()
        if ext not in ALLOWED_EXTENSIONS:
            raise ValueError(f"Extension .{ext} not allowed")
        
        # Still vulnerable to path traversal
        filepath = os.path.join(self.base_path, filename)
        
        with open(filepath, 'wb') as f:
            f.write(content)
        
        return filepath
    
    # ============================================================
    # File Download (Arbitrary File Read)
    # ============================================================
    
    def download_file(self, filename: str) -> bytes:
        """
        Downloads a file by name.
        
        Vulnerability: Path traversal to read any file (e.g., ../../../etc/passwd)
        """
        # VULNERABLE: Direct path join without sanitization
        filepath = os.path.join(self.base_path, filename)
        
        with open(filepath, 'rb') as f:
            return f.read()
    
    def get_file_content(self, filename: str) -> str:
        """
        Gets file content as string.
        
        Vulnerability: Passes to another vulnerable function
        """
        # VULNERABLE: Calls vulnerable vuln_module.read_file
        return read_file(self.base_path, filename)
    
    def read_config_file(self, config_name: str) -> str:
        """
        Reads a configuration file.
        
        Vulnerability: User controls the path completely
        """
        # VULNERABLE: No validation of config_name
        filepath = f"/etc/{config_name}"
        with open(filepath, 'r') as f:
            return f.read()
    
    # ============================================================
    # File Listing (Information Disclosure)
    # ============================================================
    
    def list_directory(self, path: str = "") -> List[str]:
        """
        Lists files in a directory.
        
        Vulnerability: Directory traversal
        """
        full_path = os.path.join(self.base_path, path)
        # VULNERABLE: Can list any directory
        return os.listdir(full_path)
    
    def get_file_info(self, filename: str) -> dict:
        """
        Gets file metadata.
        
        Vulnerability: Path traversal + information disclosure
        """
        filepath = os.path.join(self.base_path, filename)
        stat = os.stat(filepath)  # VULNERABLE: Can stat any file
        
        return {
            "name": filename,
            "size": stat.st_size,
            "modified": stat.st_mtime,
            "created": stat.st_ctime,
            "mode": oct(stat.st_mode)
        }
    
    # ============================================================
    # XML Processing (XXE)
    # ============================================================
    
    # def process_xml_upload(self, xml_content: str) -> dict:
        """
        Processes an uploaded XML file.
        
        Vulnerability: XXE via unsafe XML parsing
        """
        # VULNERABLE: Uses unsafe XML parser
        # root = parse_xml_unsafe(xml_content)
        
        # return {
        #     "tag": root.tag,
        #     "attribs": dict(root.attrib),
        #     "text": root.text,
        #     "children": len(root)
        # }
    
    # def import_data_from_xml(self, filepath: str) -> list:
        """
        Imports data from an XML file.
        
        Vulnerability: XXE + Path traversal combination
        """
        # VULNERABLE: Path traversal to read any XML file
        # tree = parse_xml_from_file(os.path.join(self.base_path, filepath))
        # root = tree.getroot()
        
        # data = []
        # for item in root.iter('item'):
        #     data.append({
        #         "name": item.findtext('name'),
        #         "value": item.findtext('value')
        #     })
        # return data
    
    # ============================================================
    # Document Processing
    # ============================================================
    
    def process_yaml_config(self, yaml_content: str) -> dict:
        """
        Processes a YAML configuration.
        
        Vulnerability: Unsafe YAML deserialization (CVE-2020-1747)
        """
        # VULNERABLE: Uses unsafe yaml.load
        return unsafe_load(yaml_content)
    
    def process_markdown_document(self, markdown_content: str) -> str:
        """
        Converts markdown to HTML.
        
        Vulnerability: Uses vulnerable mistune version (CVE-2022-34749)
        """
        # VULNERABLE: Mistune XSS/code execution
        return render_markdown(markdown_content)
    
    def render_document_template(self, filename: str, variables: dict) -> str:
        """
        Renders a document with template variables.
        
        Vulnerability: User-controlled template + path traversal
        """
        from jinja2 import Template
        
        # VULNERABLE: Path traversal
        filepath = os.path.join(self.base_path, filename)
        with open(filepath, 'r') as f:
            template_content = f.read()
        
        # VULNERABLE: SSTI if template content is user-controlled
        template = Template(template_content)
        return template.render(**variables)
    
    # ============================================================
    # Archive Processing
    # ============================================================
    
    def extract_archive(self, archive_path: str) -> List[str]:
        """
        Extracts a tar archive.
        
        Vulnerability: Zip slip / path traversal in archive extraction
        """
        import tarfile
        
        full_path = os.path.join(self.base_path, archive_path)
        extracted_files = []
        
        with tarfile.open(full_path, 'r:*') as tar:
            for member in tar.getmembers():
                # VULNERABLE: No path validation - zip slip attack
                tar.extract(member, self.base_path)
                extracted_files.append(member.name)
        
        return extracted_files
    
    def extract_zip(self, zip_path: str) -> List[str]:
        """
        Extracts a zip archive.
        
        Vulnerability: Zip slip
        """
        import zipfile
        
        full_path = os.path.join(self.base_path, zip_path)
        extracted_files = []
        
        with zipfile.ZipFile(full_path, 'r') as zip_ref:
            for name in zip_ref.namelist():
                # VULNERABLE: No path validation
                zip_ref.extract(name, self.base_path)
                extracted_files.append(name)
        
        return extracted_files
    
    # ============================================================
    # File Hash (Using Weak Algorithms)
    # ============================================================
    
    def compute_file_hash(self, filename: str, algorithm: str = "md5") -> str:
        """
        Computes hash of a file.
        
        Vulnerability: Uses weak hash algorithms (MD5/SHA1)
        """
        filepath = os.path.join(self.base_path, filename)
        
        # VULNERABLE: MD5 and SHA1 are cryptographically weak
        if algorithm == "md5":
            hasher = hashlib.md5()
        elif algorithm == "sha1":
            hasher = hashlib.sha1()
        else:
            hasher = hashlib.sha256()
        
        with open(filepath, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hasher.update(chunk)
        
        return hasher.hexdigest()
