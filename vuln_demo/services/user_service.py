#!/usr/bin/env python3
"""
User Service
------------
Handles user authentication and management.
Contains multiple vulnerability patterns in realistic service code.
"""

import sqlite3
import os
from typing import Optional, Dict, Any
from datetime import datetime, timedelta
import jwt

from vuln_module import (
    hash_password_md5,
    hash_password_sha1,
    generate_session_token,
    generate_reset_code,
    deserialize_object
)
from config import JWT_SECRET, JWT_ALGORITHM, DATABASE_CONFIG


class UserService:
    """
    User management service with intentional vulnerabilities.
    Demonstrates how vulnerabilities propagate through service layers.
    """
    
    def __init__(self, db_path: str = ":memory:"):
        self.db_path = db_path
        self._init_db()
    
    def _init_db(self):
        """Initialize the SQLite database with a users table."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                email TEXT,
                role TEXT DEFAULT 'user',
                session_token TEXT,
                reset_code TEXT,
                preferences BLOB,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        conn.commit()
        conn.close()
    
    # ============================================================
    # Authentication (Multiple Vulnerabilities)
    # ============================================================
    
    def register_user(self, username: str, password: str, email: str) -> int:
        """
        Registers a new user.
        
        Vulnerabilities:
        - SQL Injection: username is not sanitized
        - Weak hashing: uses MD5 for password storage
        """
        # VULNERABLE: MD5 is insecure for password hashing
        password_hash = hash_password_md5(password)
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # VULNERABLE: SQL Injection via string formatting
        query = f"""
            INSERT INTO users (username, password_hash, email) 
            VALUES ('{username}', '{password_hash}', '{email}')
        """
        cursor.execute(query)
        user_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        return user_id
    
    def authenticate(self, username: str, password: str) -> Optional[Dict[str, Any]]:
        """
        Authenticates a user by username and password.
        
        Vulnerabilities:
        - SQL Injection
        - Weak password hashing
        - Information disclosure (different error for user not found vs wrong password)
        """
        password_hash = hash_password_md5(password)
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # VULNERABLE: SQL Injection
        query = f"""
            SELECT id, username, email, role 
            FROM users 
            WHERE username = '{username}' AND password_hash = '{password_hash}'
        """
        cursor.execute(query)
        row = cursor.fetchone()
        conn.close()
        
        if row:
            return {
                "id": row[0],
                "username": row[1],
                "email": row[2],
                "role": row[3]
            }
        return None
    
    def create_session(self, user_id: int) -> str:
        """
        Creates a session token for the user.
        
        Vulnerability: Uses insecure random for token generation
        """
        # VULNERABLE: Predictable session token
        token = generate_session_token()
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE users SET session_token = ? WHERE id = ?",
            (token, user_id)
        )
        conn.commit()
        conn.close()
        
        return token
    
    def create_jwt_token(self, user_data: Dict[str, Any]) -> str:
        """
        Creates a JWT token for the user.
        
        Vulnerability: Weak secret key from config
        """
        payload = {
            "user_id": user_data["id"],
            "username": user_data["username"],
            "role": user_data["role"],
            "exp": datetime.utcnow() + timedelta(hours=24)
        }
        # VULNERABLE: Weak JWT_SECRET ("changeme")
        return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
    
    def verify_jwt_token(self, token: str) -> Optional[Dict[str, Any]]:
        """
        Verifies a JWT token.
        
        Vulnerability: Algorithm confusion if not properly validated
        """
        try:
            # Could be vulnerable to algorithm confusion attacks
            payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
            return payload
        except jwt.ExpiredSignatureError:
            return None
        except jwt.InvalidTokenError:
            return None
    
    # ============================================================
    # Password Reset (Insecure Implementation)
    # ============================================================
    
    def request_password_reset(self, email: str) -> Optional[str]:
        """
        Generates a password reset code.
        
        Vulnerabilities:
        - Predictable reset code (6 digits)
        - Information disclosure (tells if email exists)
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Check if email exists (information disclosure)
        cursor.execute("SELECT id FROM users WHERE email = ?", (email,))
        row = cursor.fetchone()
        
        if not row:
            return None  # Information disclosure
        
        # VULNERABLE: Predictable reset code
        reset_code = generate_reset_code()
        
        cursor.execute(
            "UPDATE users SET reset_code = ? WHERE id = ?",
            (reset_code, row[0])
        )
        conn.commit()
        conn.close()
        
        return reset_code
    
    def reset_password(self, email: str, reset_code: str, new_password: str) -> bool:
        """
        Resets the user's password using a reset code.
        
        Vulnerability: Still uses weak MD5 hashing
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute(
            "SELECT id FROM users WHERE email = ? AND reset_code = ?",
            (email, reset_code)
        )
        row = cursor.fetchone()
        
        if not row:
            return False
        
        # VULNERABLE: Weak hashing
        new_hash = hash_password_md5(new_password)
        
        cursor.execute(
            "UPDATE users SET password_hash = ?, reset_code = NULL WHERE id = ?",
            (new_hash, row[0])
        )
        conn.commit()
        conn.close()
        
        return True
    
    # ============================================================
    # User Preferences (Deserialization Vulnerability)
    # ============================================================
    
    def save_user_preferences(self, user_id: int, preferences: Dict) -> None:
        """
        Saves user preferences as pickled blob.
        
        Note: The vulnerability is in loading, not saving.
        """
        import pickle
        pref_blob = pickle.dumps(preferences)
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE users SET preferences = ? WHERE id = ?",
            (pref_blob, user_id)
        )
        conn.commit()
        conn.close()
    
    def load_user_preferences(self, user_id: int) -> Optional[Dict]:
        """
        Loads user preferences from pickled blob.
        
        Vulnerability: Deserializes untrusted pickle data
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute(
            "SELECT preferences FROM users WHERE id = ?",
            (user_id,)
        )
        row = cursor.fetchone()
        conn.close()
        
        if row and row[0]:
            # VULNERABLE: Pickle deserialization of untrusted data
            return deserialize_object(row[0])
        return None
    
    # ============================================================
    # LDAP Lookup (Injection Vulnerability)
    # ============================================================
    
    def lookup_user_ldap(self, username: str) -> str:
        """
        Constructs an LDAP query string.
        
        Vulnerability: LDAP Injection
        """
        # VULNERABLE: No escaping of user input
        ldap_filter = f"(uid={username})"
        return ldap_filter


class AdminService(UserService):
    """
    Admin service extending UserService with elevated privileges.
    Shows how vulnerabilities can be inherited.
    """
    
    def __init__(self, db_path: str = ":memory:"):
        super().__init__(db_path)
    
    def get_all_users(self) -> list:
        """Returns all users. Only admins should access this."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT id, username, email, role FROM users")
        users = cursor.fetchall()
        conn.close()
        return users
    
    def delete_user(self, username: str) -> bool:
        """
        Deletes a user.
        
        Vulnerability: SQL Injection
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        # VULNERABLE: SQL Injection
        query = f"DELETE FROM users WHERE username = '{username}'"
        cursor.execute(query)
        affected = cursor.rowcount
        conn.commit()
        conn.close()
        return affected > 0
    
    def execute_maintenance_command(self, command: str) -> str:
        """
        Executes a maintenance command.
        
        Vulnerability: Command Injection
        """
        from vuln_module import run_command
        # VULNERABLE: Direct command execution
        return run_command(command)
