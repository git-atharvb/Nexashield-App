import sqlite3
import hashlib
import datetime

class DatabaseManager:
    def __init__(self, db_name="nexashield.db"):
        self.conn = sqlite3.connect(db_name)
        self.cursor = self.conn.cursor()
        self.init_db()

    def init_db(self):
        """Initialize the users table."""
        self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                password TEXT,
                phone TEXT,
                address TEXT
            )
        """)
        
        # Antivirus Tables
        self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS scan_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_type TEXT,
                files_scanned INTEGER,
                threats_found INTEGER,
                timestamp TEXT
            )
        """)
        self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS signatures (
                hash TEXT PRIMARY KEY,
                name TEXT,
                type TEXT,
                severity TEXT
            )
        """)
        
        # Centralized SIEM Event Auditing Table
        self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS siem_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                source TEXT,
                description TEXT,
                severity TEXT
            )
        """)
        
        # Seed EICAR Test Signature (Standard Anti-Malware Test File)
        eicar_hash = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
        self.cursor.execute("INSERT OR IGNORE INTO signatures VALUES (?, ?, ?, ?)", 
                            (eicar_hash, "EICAR-Test-File", "Virus", "High"))

        # AI Settings Table
        self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS api_keys (
                service TEXT PRIMARY KEY,
                api_key TEXT
            )
        """)

        # AI Chat Sessions
        self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS ai_chat_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT,
                created_at TEXT
            )
        """)
        
        # AI Chat Messages
        self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS ai_chat_messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id INTEGER,
                role TEXT,
                content TEXT,
                timestamp TEXT,
                FOREIGN KEY(session_id) REFERENCES ai_chat_sessions(id) ON DELETE CASCADE
            )
        """)

        # Migration: Add columns if they don't exist (for existing databases)
        try:
            self.cursor.execute("ALTER TABLE users ADD COLUMN phone TEXT")
            self.cursor.execute("ALTER TABLE users ADD COLUMN address TEXT")
        except sqlite3.OperationalError:
            pass  # Columns likely already exist
        self.conn.commit()

    def register_user(self, username, password, phone, address):
        """Register a new user with a hashed password."""
        try:
            hashed_pw = hashlib.sha256(password.encode()).hexdigest()
            self.cursor.execute("INSERT INTO users (username, password, phone, address) VALUES (?, ?, ?, ?)", 
                                (username, hashed_pw, phone, address))
            self.conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False

    def verify_user(self, username, password):
        """Verify user credentials."""
        hashed_pw = hashlib.sha256(password.encode()).hexdigest()
        self.cursor.execute("SELECT * FROM users WHERE username=? AND password=?", (username, hashed_pw))
        return self.cursor.fetchone() is not None

    def get_user_phone(self, username):
        """Retrieve phone number for a user."""
        self.cursor.execute("SELECT phone FROM users WHERE username=?", (username,))
        result = self.cursor.fetchone()
        return result[0] if result else None

    def update_password(self, username, new_password):
        """Update user password."""
        hashed_pw = hashlib.sha256(new_password.encode()).hexdigest()
        self.cursor.execute("UPDATE users SET password=? WHERE username=?", (hashed_pw, username))
        self.conn.commit()
        return True

    def add_scan_history(self, scan_type, files_scanned, threats_found):
        """Log a completed scan."""
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.cursor.execute("INSERT INTO scan_history (scan_type, files_scanned, threats_found, timestamp) VALUES (?, ?, ?, ?)",
                            (scan_type, files_scanned, threats_found, timestamp))
        self.conn.commit()

    def get_scan_history(self):
        self.cursor.execute("SELECT * FROM scan_history ORDER BY id DESC")
        return self.cursor.fetchall()

    def check_signature(self, file_hash):
        """Check if a file hash exists in the signature database."""
        self.cursor.execute("SELECT name, type, severity FROM signatures WHERE hash=?", (file_hash,))
        return self.cursor.fetchone()

    def clear_scan_history(self):
        """Clear all scan history."""
        self.cursor.execute("DELETE FROM scan_history")
        self.conn.commit()

    def log_siem_event(self, source, description, severity):
        """Log a generic event for the SIEM Dashboard."""
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.cursor.execute("INSERT INTO siem_events (timestamp, source, description, severity) VALUES (?, ?, ?, ?)",
                            (timestamp, source, description, severity))
        self.conn.commit()

    def get_api_key(self, service="openrouter"):
        """Get API key for a service."""
        self.cursor.execute("SELECT api_key FROM api_keys WHERE service=?", (service,))
        result = self.cursor.fetchone()
        return result[0] if result else None
        
    def set_api_key(self, service, api_key):
        """Set or update API key for a service."""
        self.cursor.execute("INSERT OR REPLACE INTO api_keys (service, api_key) VALUES (?, ?)", (service, api_key))
        self.conn.commit()

    # --- AI Chat History Methods ---
    def create_chat_session(self, title="New Chat"):
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.cursor.execute("INSERT INTO ai_chat_sessions (title, created_at) VALUES (?, ?)", (title, timestamp))
        self.conn.commit()
        return self.cursor.lastrowid

    def get_chat_sessions(self):
        self.cursor.execute("SELECT id, title, created_at FROM ai_chat_sessions ORDER BY id DESC")
        return self.cursor.fetchall()

    def get_chat_messages(self, session_id):
        self.cursor.execute("SELECT role, content FROM ai_chat_messages WHERE session_id=? ORDER BY id ASC", (session_id,))
        return self.cursor.fetchall()

    def add_chat_message(self, session_id, role, content):
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.cursor.execute("INSERT INTO ai_chat_messages (session_id, role, content, timestamp) VALUES (?, ?, ?, ?)", 
                            (session_id, role, content, timestamp))
        self.conn.commit()
        
    def update_chat_title(self, session_id, title):
        self.cursor.execute("UPDATE ai_chat_sessions SET title=? WHERE id=?", (title, session_id))
        self.conn.commit()

    def delete_chat_session(self, session_id):
        self.cursor.execute("DELETE FROM ai_chat_messages WHERE session_id=?", (session_id,))
        self.cursor.execute("DELETE FROM ai_chat_sessions WHERE id=?", (session_id,))
        self.conn.commit()