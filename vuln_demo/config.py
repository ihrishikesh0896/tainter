#!/usr/bin/env python3
"""
Application Configuration
-------------------------
Contains configuration settings, some with security anti-patterns.
"""

import os

# Database configuration (hardcoded credentials - vulnerability!)
DATABASE_CONFIG = {
    "host": "localhost",
    "port": 5432,
    "database": "vuln_demo_db",
    "username": "admin",          # Hardcoded credential
    "password": "super_secret123"  # Hardcoded credential
}

# API Keys (exposed secrets - vulnerability!)
API_KEYS = {
    "github": "ghp_xxxxxxxxxxxxxxxxxxxx",
    "aws_access_key": "AKIA1234567890EXAMPLE",
    "aws_secret_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
}

# JWT configuration (weak secret - vulnerability!)
JWT_SECRET = "changeme"
JWT_ALGORITHM = "HS256"

# File upload settings
UPLOAD_FOLDER = "/tmp/uploads"
ALLOWED_EXTENSIONS = {"txt", "pdf", "png", "jpg", "jpeg", "gif", "xml", "yaml"}
MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB

# Debug mode (should be False in production!)
DEBUG_MODE = True

# Session configuration (insecure settings)
SESSION_CONFIG = {
    "secret_key": "dev",  # Weak secret
    "cookie_secure": False,  # Should be True for HTTPS
    "cookie_httponly": False,  # Should be True
    "cookie_samesite": None,  # Should be 'Strict' or 'Lax'
}


def get_database_url():
    """
    Constructs database URL from config.
    Uses hardcoded credentials if environment variables are not set.
    """
    host = os.environ.get("DB_HOST", DATABASE_CONFIG["host"])
    port = os.environ.get("DB_PORT", DATABASE_CONFIG["port"])
    database = os.environ.get("DB_NAME", DATABASE_CONFIG["database"])
    username = os.environ.get("DB_USER", DATABASE_CONFIG["username"])
    password = os.environ.get("DB_PASS", DATABASE_CONFIG["password"])
    
    return f"postgresql://{username}:{password}@{host}:{port}/{database}"
