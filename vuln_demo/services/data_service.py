#!/usr/bin/env python3
"""
Data Service
------------
Handles data processing and external integrations.
Contains vulnerabilities related to data handling, SSRF, and serialization.
"""

import json
import base64
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin
import requests

from vuln_module import (
    unsafe_load,
    unsafe_full_load,
    deserialize_object,
    deserialize_with_dill,
    render_template,
    run_command
)
from config import API_KEYS


class DataService:
    """
    Data processing service with serialization and SSRF vulnerabilities.
    """
    
    def __init__(self, base_url: str = "http://localhost:8080"):
        self.base_url = base_url
        self.cache = {}
    
    # ============================================================
    # Data Import/Export (Deserialization Vulnerabilities)
    # ============================================================
    
    def import_yaml_data(self, yaml_string: str) -> Dict:
        """
        Imports data from YAML string.
        
        Vulnerability: Unsafe YAML deserialization (CVE-2020-1747)
        """
        # VULNERABLE: Uses yaml.load without safe loader
        return unsafe_load(yaml_string)
    
    def import_yaml_config(self, yaml_string: str) -> Dict:
        """
        Imports configuration from YAML.
        
        Vulnerability: Uses yaml.full_load which is unsafe in old versions
        """
        # VULNERABLE: yaml.full_load is unsafe in pyyaml < 5.4
        return unsafe_full_load(yaml_string)
    
    def import_pickle_data(self, pickle_b64: str) -> Any:
        """
        Imports pickle-serialized data from base64.
        
        Vulnerability: Pickle deserialization RCE
        """
        # VULNERABLE: Arbitrary code execution via pickle
        pickle_bytes = base64.b64decode(pickle_b64)
        return deserialize_object(pickle_bytes)
    
    def import_dill_data(self, dill_b64: str) -> Any:
        """
        Imports dill-serialized data.
        
        Vulnerability: Dill deserialization RCE (dill extends pickle)
        """
        # VULNERABLE: RCE via dill
        dill_bytes = base64.b64decode(dill_b64)
        return deserialize_with_dill(dill_bytes)
    
    def load_cached_object(self, key: str) -> Optional[Any]:
        """
        Loads a cached object.
        
        Vulnerability: If cache contains pickled data from untrusted source
        """
        if key in self.cache:
            cached = self.cache[key]
            if isinstance(cached, bytes):
                # VULNERABLE: Deserializes potentially untrusted data
                return deserialize_object(cached)
            return cached
        return None
    
    # ============================================================
    # External Data Fetching (SSRF Vulnerabilities)
    # ============================================================
    
    def fetch_external_resource(self, url: str) -> str:
        """
        Fetches content from an external URL.
        
        Vulnerability: SSRF - user controls the URL completely
        """
        # VULNERABLE: No URL validation - can access internal services
        response = requests.get(url, timeout=10)
        return response.text
    
    def fetch_api_endpoint(self, endpoint: str) -> Dict:
        """
        Fetches data from an API endpoint.
        
        Vulnerability: SSRF via endpoint parameter
        """
        # VULNERABLE: Partial SSRF - can manipulate the path
        url = urljoin(self.base_url, endpoint)
        response = requests.get(url, timeout=10)
        return response.json()
    
    def fetch_with_redirect(self, url: str) -> str:
        """
        Fetches URL following redirects.
        
        Vulnerability: SSRF with redirect following
        """
        # VULNERABLE: Follows redirects that may lead to internal services
        response = requests.get(url, allow_redirects=True, timeout=10)
        return response.text
    
    def proxy_request(self, method: str, url: str, data: Optional[Dict] = None) -> Dict:
        """
        Proxies an HTTP request.
        
        Vulnerability: Full SSRF - user controls method, URL, and data
        """
        # VULNERABLE: Complete SSRF vulnerability
        response = requests.request(
            method=method,
            url=url,
            json=data,
            timeout=10
        )
        return {
            "status": response.status_code,
            "headers": dict(response.headers),
            "body": response.text
        }
    
    def check_url_status(self, url: str) -> bool:
        """
        Checks if a URL is reachable.
        
        Vulnerability: Blind SSRF
        """
        try:
            # VULNERABLE: Blind SSRF - can probe internal network
            response = requests.head(url, timeout=5)
            return response.status_code < 500
        except Exception:
            return False
    
    # ============================================================
    # Webhook Processing (SSRF + Deserialization)
    # ============================================================
    
    def process_webhook(self, callback_url: str, payload: Dict) -> str:
        """
        Sends data to a webhook.
        
        Vulnerability: SSRF via callback URL
        """
        # VULNERABLE: User controls the callback URL
        response = requests.post(callback_url, json=payload, timeout=10)
        return response.text
    
    def register_webhook(self, name: str, url: str) -> bool:
        """
        Registers a webhook URL.
        
        Vulnerability: Stored SSRF - URL saved for later use
        """
        # VULNERABLE: Storing untrusted URLs
        self.cache[f"webhook_{name}"] = url
        return True
    
    def trigger_webhook(self, name: str, data: Dict) -> Optional[str]:
        """
        Triggers a stored webhook.
        
        Vulnerability: SSRF using stored URL
        """
        url = self.cache.get(f"webhook_{name}")
        if url:
            # VULNERABLE: Uses previously stored (potentially malicious) URL
            response = requests.post(url, json=data, timeout=10)
            return response.text
        return None
    
    # ============================================================
    # Template Processing (SSTI)
    # ============================================================
    
    def render_dynamic_content(self, template: str, context: Dict) -> str:
        """
        Renders dynamic content from template.
        
        Vulnerability: SSTI - user controls the template string
        """
        # VULNERABLE: User-controlled template string
        return render_template(template, context)
    
    def generate_email_content(self, template: str, user_data: Dict) -> str:
        """
        Generates email content from template.
        
        Vulnerability: SSTI in email generation
        """
        # VULNERABLE: Template injection
        return render_template(template, {"user": user_data})
    
    def format_notification(self, message_template: str, **kwargs) -> str:
        """
        Formats a notification message.
        
        Vulnerability: Format string injection (less severe but still a vuln)
        """
        # VULNERABLE: Format string injection
        return message_template.format(**kwargs)
    
    # ============================================================
    # Command Execution (OS Command Injection)
    # ============================================================
    
    def process_data_file(self, filename: str) -> str:
        """
        Processes a data file using an external tool.
        
        Vulnerability: Command injection via filename
        """
        # VULNERABLE: Filename injected into command
        return run_command(f"cat {filename} | wc -l")
    
    def convert_format(self, input_file: str, output_format: str) -> str:
        """
        Converts file to different format.
        
        Vulnerability: Command injection in both parameters
        """
        # VULNERABLE: Both parameters can be exploited
        return run_command(f"convert {input_file} {output_format}")
    
    def run_data_pipeline(self, pipeline_name: str) -> str:
        """
        Runs a named data pipeline.
        
        Vulnerability: Command injection via pipeline name
        """
        # VULNERABLE: Pipeline name injected into command
        return run_command(f"/opt/pipelines/{pipeline_name}.sh")
    
    # ============================================================
    # API Integration (Credential Exposure)
    # ============================================================
    
    def call_external_api(self, service: str, endpoint: str) -> Dict:
        """
        Calls an external API using stored credentials.
        
        Vulnerability: Hardcoded API keys from config
        """
        api_key = API_KEYS.get(service)
        if not api_key:
            raise ValueError(f"No API key for service: {service}")
        
        # Uses hardcoded credentials
        headers = {"Authorization": f"Bearer {api_key}"}
        response = requests.get(endpoint, headers=headers, timeout=10)
        return response.json()
    
    def log_api_call(self, service: str, endpoint: str, response: Dict) -> None:
        """
        Logs an API call.
        
        Vulnerability: Logs may contain sensitive data
        """
        api_key = API_KEYS.get(service, "unknown")
        # VULNERABLE: Logging sensitive API key
        log_entry = {
            "service": service,
            "endpoint": endpoint,
            "api_key": api_key,  # Sensitive data in logs
            "response": response
        }
        print(f"API Call: {json.dumps(log_entry)}")


class DataExporter:
    """
    Exports data to various formats.
    """
    
    def __init__(self):
        self.export_path = "/tmp/exports"
    
    def export_to_csv(self, filename: str, data: List[Dict]) -> str:
        """
        Exports data to CSV.
        
        Vulnerability: Path traversal
        """
        import csv
        
        # VULNERABLE: No filename sanitization
        filepath = f"{self.export_path}/{filename}"
        
        with open(filepath, 'w', newline='') as f:
            if data:
                writer = csv.DictWriter(f, fieldnames=data[0].keys())
                writer.writeheader()
                writer.writerows(data)
        
        return filepath
    
    def export_to_json(self, filename: str, data: Any) -> str:
        """
        Exports data to JSON.
        
        Vulnerability: Path traversal + potential DoS via large data
        """
        # VULNERABLE: No filename sanitization
        filepath = f"{self.export_path}/{filename}"
        
        with open(filepath, 'w') as f:
            json.dump(data, f)
        
        return filepath
