import os
import sqlite3
from file_manager import FileManager

class SessionManager:
    """
    Manages user-specific workspace context. 
    Ensures Data Isolation between different users on the same OS.
    """
    def __init__(self, email_or_id, auth_type="local", auth_token=None):
        self.user_id = email_or_id
        self.auth_type = auth_type
        self.auth_token = auth_token
        # Define isolated workspace path: C:\Users\<OS_User>\AppData\Local\NexaShield\workspaces\<user_id>
        self.app_data_dir = os.path.join(os.path.expanduser("~"), "AppData", "Local", "NexaShield")
        self.workspace_dir = os.path.join(self.app_data_dir, "workspaces", self.user_id)
        
        # Ensure the tenant's workspace exists
        os.makedirs(self.workspace_dir, exist_ok=True)
        
        # Initialize User Database
        self._init_user_database()
        
        # Initialize File Manager (Vault)
        self.file_manager = FileManager(self)
        
    def _init_user_database(self):
        """Initializes the SQLite database structure for the isolated user."""
        db_path = self.get_db_path()
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # SIEM Tables
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS siem_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                source TEXT,
                description TEXT,
                severity TEXT
            )
        """)
        
        # Antivirus Tables
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scan_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_type TEXT,
                files_scanned INTEGER,
                threats_found INTEGER,
                timestamp TEXT
            )
        """)
        
        # Firewall Tables (if any needed historically)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS firewall_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                action TEXT,
                protocol TEXT,
                ip TEXT,
                port TEXT,
                timestamp TEXT
            )
        """)
        
        # FMS Vault Table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS file_registry (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                filename TEXT,
                filepath TEXT,
                module_source TEXT,
                file_type TEXT,
                tags TEXT,
                timestamp TEXT,
                file_size INTEGER,
                file_hash TEXT
            )
        """)
        
        conn.commit()
        conn.close()
        
    def get_db_path(self):
        """Returns the path to the isolated SQLite database for this user."""
        return os.path.join(self.workspace_dir, "user_data.db")
        
    def get_log_dir(self):
        """Returns the isolated log directory for this user."""
        log_dir = os.path.join(self.workspace_dir, "logs")
        os.makedirs(log_dir, exist_ok=True)
        return log_dir
        
    def get_cloud_token_path(self):
        """Returns the path where OAuth tokens are securely stored for this user."""
        return os.path.join(self.workspace_dir, "cloud_token.json")

    def reset_session(self):
        """Clear memory cache for smooth logout without deleting files."""
        self.user_id = None
        self.workspace_dir = None
