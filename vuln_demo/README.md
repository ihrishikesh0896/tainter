# VulnReach Robust Demo Application

A comprehensive, intentionally vulnerable Flask application designed to demonstrate **VulnReach's** static analysis and reachability detection capabilities.

> ⚠️ **WARNING**: This application is **INTENTIONALLY VULNERABLE**. Do **NOT** deploy it on any production system, public server, or network accessible to untrusted users.

---

## 📋 Overview

This demo application contains:

| Category | Count | Description |
|----------|-------|-------------|
| **Vulnerability Types** | 15+ | Different classes of security vulnerabilities |
| **API Endpoints** | 35+ | Flask routes demonstrating various attack vectors |
| **Vulnerable Dependencies** | 12+ | Known CVEs in pinned package versions |
| **Service Layers** | 3 | Realistic service architecture for call-chain testing |

---

## 🔐 Vulnerability Categories

### 1. Deserialization Vulnerabilities

| Vulnerability | CVE | Location | Endpoint |
|--------------|-----|----------|----------|
| Unsafe YAML | CVE-2020-1747 | `vuln_module.unsafe_load` | `/api/yaml/load` |
| Pickle RCE | - | `vuln_module.deserialize_object` | `/api/pickle/load` |
| Dill RCE | - | `vuln_module.deserialize_with_dill` | `/api/dill/load` |

### 2. Injection Vulnerabilities

| Vulnerability | Location | Endpoint |
|--------------|----------|----------|
| Command Injection (shell=True) | `vuln_module.run_command` | `/api/exec/run` |
| Command Injection (Popen) | `vuln_module.run_command_popen` | `/api/exec/popen` |
| Command Injection (os.system) | `vuln_module.execute_system_cmd` | `/api/exec/system` |
| SQL Injection | `vuln_module.query_user` | `/api/users/search` |
| SSTI (Jinja2) | `vuln_module.render_template` | `/api/template/render` |
| LDAP Injection | `services/user_service.py` | - |

### 3. XML External Entity (XXE)

| Vulnerability | Location | Endpoint |
|--------------|----------|----------|
| XXE (resolve_entities=True) | `vuln_module.parse_xml_unsafe` | `/api/xml/parse` |
| XXE (default parser) | `vuln_module.parse_xml_from_file` | `/api/xml/upload` |

### 4. Path Traversal

| Vulnerability | Location | Endpoint |
|--------------|----------|----------|
| Arbitrary File Read | `vuln_module.read_file` | `/api/files/read` |
| Arbitrary File Write | `services/file_service.py` | `/api/files/upload` |
| Directory Listing | `services/file_service.py` | `/api/files/list` |
| Zip Slip | `services/file_service.py` | `/api/archive/extract` |

### 5. Server-Side Request Forgery (SSRF)

| Vulnerability | Location | Endpoint |
|--------------|----------|----------|
| Full SSRF | `services/data_service.py` | `/api/fetch` |
| Proxy SSRF | `services/data_service.py` | `/api/proxy` |
| Webhook SSRF | `services/data_service.py` | `/api/webhook/*` |

### 6. Cryptographic Weaknesses

| Vulnerability | Location | Endpoint |
|--------------|----------|----------|
| MD5 Password Hashing | `vuln_module.hash_password_md5` | `/api/crypto/hash` |
| DES Encryption (ECB mode) | `vuln_module.encrypt_data_des` | `/api/crypto/encrypt` |
| Timing-Vulnerable Comparison | `vuln_module.verify_signature_timing_vulnerable` | `/api/crypto/verify` |
| Predictable Session Token | `vuln_module.generate_session_token` | Auth endpoints |

### 7. Authentication & Authorization

| Vulnerability | Location |
|--------------|----------|
| SQL Injection in Login | `services/user_service.py` |
| Weak JWT Secret | `config.py` |
| Predictable Password Reset | `services/user_service.py` |
| Missing Access Control | Admin endpoints |
| Information Disclosure | Login error messages |

### 8. Configuration & Secrets

| Vulnerability | Location |
|--------------|----------|
| Hardcoded Database Credentials | `config.py` |
| Hardcoded API Keys | `config.py` |
| Debug Mode Enabled | `config.py` |
| Weak Session Secret | `config.py` |

---

## 📦 Vulnerable Dependencies

The `requirements.txt` pins specific vulnerable versions:

```
pyyaml==5.3.1          # CVE-2020-1747: Arbitrary code execution
py==1.11.0             # CVE-2022-42969: ReDoS
urllib3==1.26.4        # CVE-2021-33503: ReDoS
Pillow==9.0.0          # CVE-2022-24303: Path traversal
celery==5.0.5          # CVE-2021-23727: Command injection
nltk==3.4.4            # CVE-2019-14751: Path traversal
mistune==0.8.4         # CVE-2022-34749: XSS/Code execution
Jinja2==2.11.2         # CVE-2020-28493: ReDoS
ldap3==2.9             # CVE-2022-29155: SQL injection
lxml==4.6.2            # XXE vulnerable defaults
dill==0.3.5            # Unsafe deserialization
pycryptodome==3.9.9    # Weak cipher support
```

---

## 🏗️ Project Structure

```
labs/vuln_demo/
├── app.py                  # Main Flask application (35+ endpoints)
├── vuln_module.py          # Core vulnerable functions
├── config.py               # Configuration with hardcoded secrets
├── requirements.txt        # Vulnerable dependencies
├── README.md               # This file
└── services/
    ├── __init__.py
    ├── user_service.py     # User auth with SQL injection
    ├── file_service.py     # File ops with path traversal
    └── data_service.py     # Data handling with SSRF
```

---

## 🚀 Usage

### Installation

```bash
cd labs/vuln_demo
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### Running the Server

```bash
python app.py
```

Server starts at `http://127.0.0.1:5000`

### Example Vulnerable Requests

```bash
# YAML Deserialization (CVE-2020-1747)
curl -X POST http://127.0.0.1:5000/api/yaml/load \
  -d 'key: value'

# Command Injection
curl "http://127.0.0.1:5000/api/exec/run?cmd=whoami"

# Path Traversal
curl "http://127.0.0.1:5000/api/files/read?base=/&file=etc/passwd"

# SQL Injection
curl "http://127.0.0.1:5000/api/users/search?username=admin' OR '1'='1"

# SSTI
curl -X POST http://127.0.0.1:5000/api/template/render \
  -H "Content-Type: application/json" \
  -d '{"template": "{{ config }}", "context": {}}'

# SSRF
curl "http://127.0.0.1:5000/api/fetch?url=http://169.254.169.254/latest/meta-data/"
```

---

## 🔍 VulnReach Testing

Run VulnReach against this demo to:

1. **Detect vulnerable dependencies** from `requirements.txt`
2. **Build call graphs** showing Flask routes → vulnerable sinks
3. **Analyze reachability** of CVE-affected code paths
4. **Generate reports** with Mermaid visualizations

```bash
# From project root
vulnreach labs/vuln_demo --run-reachability --run-exploitability
```

### Expected Call Chains

VulnReach should discover chains like:

```
Flask Route (/api/yaml/load)
    → unsafe_load()
        → yaml.load() [CVE-2020-1747]

Flask Route (/api/exec/run)
    → run_command()
        → subprocess.check_output(shell=True)

Flask Route (/api/auth/authenticate)
    → user_service.authenticate()
        → hash_password_md5()
            → hashlib.md5()
        → cursor.execute(f-string) [SQL Injection]
```

---

## 📊 Endpoint Summary

| Category | Endpoints | Example |
|----------|-----------|---------|
| YAML | 3 | `/api/yaml/load` |
| Command Exec | 4 | `/api/exec/run` |
| XXE | 2 | `/api/xml/parse` |
| Pickle | 4 | `/api/pickle/load` |
| Path Traversal | 5 | `/api/files/read` |
| SSTI | 3 | `/api/template/render` |
| SQL Injection | 3 | `/api/users/search` |
| Auth | 4 | `/api/auth/login` |
| SSRF | 4 | `/api/fetch` |
| Crypto | 3 | `/api/crypto/hash` |
| Archive | 2 | `/api/archive/extract` |
| Markdown | 2 | `/api/markdown/render` |
| Admin | 3 | `/api/admin/users` |
| Debug | 3 | `/api/debug/config` |

---

## 📝 License

This code is provided for **educational and security research purposes only**. Use responsibly.

---

**Created for VulnReach demonstration. Happy hunting! 🔍**
