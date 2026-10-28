import os
import sqlite3
from file_manager import FileManager

class SessionManager:
    """
    Manages user-specific workspace context. 
    Ensures Data Isolation between different users on the same OS.
    """
    def __init__(self, email_or_id, auth_type="local", auth_token=None):
        import re
        self.user_id = str(email_or_id).strip()
        self.auth_type = auth_type
        self.auth_token = auth_token
        # Sanitize folder name for Windows filesystem compatibility (strip invalid chars < > : " / \ | ? *)
        safe_folder = re.sub(r'[<>:"/\\|?*]', '_', self.user_id)
        # Define isolated workspace path: C:\Users\<OS_User>\AppData\Local\NexaShield\workspaces\<user_id>
        self.app_data_dir = os.path.join(os.path.expanduser("~"), "AppData", "Local", "NexaShield")
        self.workspace_dir = os.path.join(self.app_data_dir, "workspaces", safe_folder)
        
        # Ensure the tenant's workspace exists with graceful workspace directory fallback
        try:
            os.makedirs(self.workspace_dir, exist_ok=True)
        except Exception:
            self.app_data_dir = os.path.join(os.getcwd(), ".nexashield_data")
            self.workspace_dir = os.path.join(self.app_data_dir, "workspaces", safe_folder)
            os.makedirs(self.workspace_dir, exist_ok=True)
        
        # Initialize User Database
        self._init_user_database()
        
        # Initialize File Manager (Vault)
        self.file_manager = FileManager(self)
        
    def _init_user_database(self):
        """Initializes the SQLite database structure for the isolated user."""
        db_path = self.get_db_path()
        conn = sqlite3.connect(db_path, check_same_thread=False, timeout=30.0)
        cursor = conn.cursor()
        try:
            cursor.execute("PRAGMA journal_mode=WAL;")
            cursor.execute("PRAGMA synchronous=NORMAL;")
        except sqlite3.OperationalError:
            pass
        
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

        # Permanent Phishing Intelligence Tables
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS phishing_scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT NOT NULL,
                normalized_url TEXT,
                final_url TEXT,
                threat_level TEXT NOT NULL,
                score REAL NOT NULL,
                heuristic_score REAL,
                ml_score REAL,
                method TEXT,
                timestamp TEXT NOT NULL,
                scan_duration REAL DEFAULT 0.0,
                domain TEXT,
                resolved_ip TEXT
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS phishing_scan_details (
                scan_id INTEGER PRIMARY KEY,
                url_anatomy TEXT,
                heuristic_results TEXT,
                ml_results TEXT,
                redirect_chain TEXT,
                domain_intel TEXT,
                ssl_analysis TEXT,
                http_analysis TEXT,
                content_analysis TEXT,
                raw_reasons TEXT,
                FOREIGN KEY (scan_id) REFERENCES phishing_scans(id) ON DELETE CASCADE
            )
        """)

        # Permanent NIDS & IPS Tables
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS nids_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                src_ip TEXT,
                dst_ip TEXT,
                protocol TEXT,
                length INTEGER,
                risk_level TEXT,
                info TEXT,
                rule_id TEXT,
                mitre_attack TEXT,
                details_json TEXT
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS nids_blocked_ips (
                ip TEXT PRIMARY KEY,
                reason TEXT,
                timestamp TEXT,
                blocked_by TEXT DEFAULT 'IPS',
                status TEXT DEFAULT 'Blocked'
            )
        """)

        # Cloud Security (CASB & CSPM) Tables
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS cloud_scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                total_files INTEGER DEFAULT 0,
                exposed_count INTEGER DEFAULT 0,
                dlp_count INTEGER DEFAULT 0,
                malware_count INTEGER DEFAULT 0,
                security_score REAL DEFAULT 100.0
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS cloud_assets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                file_id TEXT UNIQUE,
                name TEXT NOT NULL,
                mime_type TEXT,
                size TEXT,
                is_public INTEGER DEFAULT 0,
                status TEXT,
                score INTEGER DEFAULT 0,
                findings_summary TEXT,
                raw_findings_json TEXT,
                timestamp TEXT
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS cloud_vaulted_assets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                file_name TEXT NOT NULL,
                file_id TEXT,
                vault_path TEXT,
                timestamp TEXT,
                reason TEXT
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
