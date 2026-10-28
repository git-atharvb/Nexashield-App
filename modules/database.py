import sqlite3
import hashlib
import datetime
import json

class DatabaseManager:
    def __init__(self, db_name="nexashield.db"):
        self.conn = sqlite3.connect(db_name, check_same_thread=False, timeout=30.0)
        self.cursor = self.conn.cursor()
        try:
            self.cursor.execute("PRAGMA journal_mode=WAL;")
            self.cursor.execute("PRAGMA synchronous=NORMAL;")
        except sqlite3.OperationalError:
            pass
        self.init_db()

    def init_db(self):
        """Initialize all required system and security tables."""
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

        # Permanent Phishing History & Deep Forensics Tables
        self.cursor.execute("""
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
        self.cursor.execute("""
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
        
        # NIDS Intrusion Events & Blocked IPs
        self.cursor.execute("""
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
        self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS nids_blocked_ips (
                ip TEXT PRIMARY KEY,
                reason TEXT,
                timestamp TEXT,
                blocked_by TEXT DEFAULT 'IPS',
                status TEXT DEFAULT 'Blocked'
            )
        """)
        
        # Cloud Security (CASB & CSPM) Tables
        self.cursor.execute("""
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
        self.cursor.execute("""
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
        self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS cloud_vaulted_assets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                file_name TEXT NOT NULL,
                file_id TEXT,
                vault_path TEXT,
                timestamp TEXT,
                reason TEXT
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
            if not username or not password:
                return False
            username = str(username).strip()
            phone = str(phone).strip() if phone else ""
            address = str(address).strip() if address else ""
            hashed_pw = hashlib.sha256(password.encode()).hexdigest()
            self.cursor.execute("INSERT INTO users (username, password, phone, address) VALUES (?, ?, ?, ?)", 
                                (username, hashed_pw, phone, address))
            self.conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False

    def verify_user(self, username, password):
        """Verify user credentials."""
        if not username or not password:
            return False
        username = str(username).strip()
        hashed_pw = hashlib.sha256(password.encode()).hexdigest()
        self.cursor.execute("SELECT * FROM users WHERE username=? AND password=?", (username, hashed_pw))
        return self.cursor.fetchone() is not None

    def get_user_phone(self, username):
        """Retrieve phone number for a user."""
        if not username:
            return None
        username = str(username).strip()
        self.cursor.execute("SELECT phone FROM users WHERE username=?", (username,))
        result = self.cursor.fetchone()
        return result[0] if result else None

    def update_password(self, username, new_password):
        """Update user password."""
        if not username or not new_password:
            return False
        username = str(username).strip()
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

    def get_siem_events(self, limit: int = 500, severity: str = None, search: str = "") -> list[dict]:
        """Retrieves ordered list of SIEM events with optional filtering."""
        query = "SELECT id, timestamp, source, description, severity FROM siem_events WHERE 1=1"
        params = []
        if severity and severity != "All Severities":
            query += " AND severity = ?"
            params.append(severity)
        if search:
            query += " AND (source LIKE ? OR description LIKE ?)"
            term = f"%{search}%"
            params.extend([term, term])
        query += " ORDER BY id DESC LIMIT ?"
        params.append(limit)

        self.cursor.execute(query, tuple(params))
        rows = self.cursor.fetchall()
        cols = ["id", "timestamp", "source", "description", "severity"]
        return [dict(zip(cols, r)) for r in rows]

    def clear_siem_events(self):
        """Clears all logged SIEM events."""
        self.cursor.execute("DELETE FROM siem_events")
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

    # --- Permanent Phishing Intelligence Storage Methods ---
    def add_phishing_scan(self, scan_data: dict) -> int:
        """Saves a top-level scan record into permanent database storage."""
        url = scan_data.get("url", "")
        normalized_url = scan_data.get("normalized_url", url)
        final_url = scan_data.get("final_url", url)
        threat_level = scan_data.get("threat_level", "Unknown")
        score = float(scan_data.get("score", 0.0))
        heuristic_score = float(scan_data.get("heuristic_score", 0.0))
        ml_score = float(scan_data.get("ml_score", 0.0))
        method = scan_data.get("method", "Heuristics")
        timestamp = scan_data.get("timestamp") or datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        scan_duration = float(scan_data.get("scan_duration", 0.0))
        domain = scan_data.get("domain", "-")
        resolved_ip = scan_data.get("resolved_ip", "-")

        self.cursor.execute("""
            INSERT INTO phishing_scans 
            (url, normalized_url, final_url, threat_level, score, heuristic_score, ml_score, method, timestamp, scan_duration, domain, resolved_ip)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (url, normalized_url, final_url, threat_level, score, heuristic_score, ml_score, method, timestamp, scan_duration, domain, resolved_ip))
        self.conn.commit()
        scan_id = self.cursor.lastrowid

        # Also save details if provided
        if "details" in scan_data:
            self.add_phishing_scan_details(scan_id, scan_data["details"], scan_data.get("reasons", []))

        return scan_id

    def add_phishing_scan_details(self, scan_id: int, details: dict, raw_reasons: list = None):
        """Saves comprehensive structured forensic payload for a scan ID."""
        if not details:
            details = {}

        def to_json(val):
            if isinstance(val, str):
                return val
            try:
                return json.dumps(val)
            except Exception:
                return "{}"

        anatomy_json = to_json(details.get("anatomy", {}))
        heuristic_json = to_json(details.get("rules_triggered", []))
        ml_json = to_json(details.get("ml_results", {}))
        redirect_json = to_json(details.get("redirect_chain", []))
        domain_json = to_json(details.get("domain_intel", {}))
        ssl_json = to_json(details.get("ssl_analysis", {}))
        http_json = to_json(details.get("http_analysis", {}))
        content_json = to_json(details.get("content_analysis", {}))
        reasons_json = to_json(raw_reasons if raw_reasons is not None else details.get("reasons", []))

        self.cursor.execute("""
            INSERT OR REPLACE INTO phishing_scan_details
            (scan_id, url_anatomy, heuristic_results, ml_results, redirect_chain, domain_intel, ssl_analysis, http_analysis, content_analysis, raw_reasons)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (scan_id, anatomy_json, heuristic_json, ml_json, redirect_json, domain_json, ssl_json, http_json, content_json, reasons_json))
        self.conn.commit()

    def get_phishing_history(self, limit: int = 500) -> list[dict]:
        """Returns ordered list of all historical phishing scan summaries."""
        self.cursor.execute("""
            SELECT id, url, normalized_url, final_url, threat_level, score, heuristic_score, ml_score, method, timestamp, scan_duration, domain, resolved_ip
            FROM phishing_scans ORDER BY id DESC LIMIT ?
        """, (limit,))
        rows = self.cursor.fetchall()
        cols = ["id", "url", "normalized_url", "final_url", "threat_level", "score", "heuristic_score", "ml_score", "method", "timestamp", "scan_duration", "domain", "resolved_ip"]
        return [dict(zip(cols, r)) for r in rows]

    def get_phishing_scan_detail(self, scan_id: int) -> dict:
        """Retrieves full deep forensic dossier for a specific historical scan."""
        self.cursor.execute("""
            SELECT id, url, normalized_url, final_url, threat_level, score, heuristic_score, ml_score, method, timestamp, scan_duration, domain, resolved_ip
            FROM phishing_scans WHERE id=?
        """, (scan_id,))
        main_row = self.cursor.fetchone()
        if not main_row:
            return {}

        cols = ["id", "url", "normalized_url", "final_url", "threat_level", "score", "heuristic_score", "ml_score", "method", "timestamp", "scan_duration", "domain", "resolved_ip"]
        data = dict(zip(cols, main_row))

        self.cursor.execute("""
            SELECT url_anatomy, heuristic_results, ml_results, redirect_chain, domain_intel, ssl_analysis, http_analysis, content_analysis, raw_reasons
            FROM phishing_scan_details WHERE scan_id=?
        """, (scan_id,))
        det_row = self.cursor.fetchone()

        details = {}
        reasons = []
        if det_row:
            def safe_load(val, default):
                if not val:
                    return default
                try:
                    return json.loads(val)
                except Exception:
                    return default

            details["anatomy"] = safe_load(det_row[0], {})
            details["rules_triggered"] = safe_load(det_row[1], [])
            details["ml_results"] = safe_load(det_row[2], {})
            details["redirect_chain"] = safe_load(det_row[3], [])
            details["domain_intel"] = safe_load(det_row[4], {})
            details["ssl_analysis"] = safe_load(det_row[5], {})
            details["http_analysis"] = safe_load(det_row[6], {})
            details["content_analysis"] = safe_load(det_row[7], {})
            reasons = safe_load(det_row[8], [])

        data["details"] = details
        data["reasons"] = reasons
        return data

    def delete_phishing_scans(self, scan_ids: list[int]):
        """Deletes selected scans by ID safely with parameterized query."""
        if not scan_ids:
            return
        placeholders = ",".join("?" for _ in scan_ids)
        self.cursor.execute(f"DELETE FROM phishing_scan_details WHERE scan_id IN ({placeholders})", scan_ids)
        self.cursor.execute(f"DELETE FROM phishing_scans WHERE id IN ({placeholders})", scan_ids)
        self.conn.commit()

    def clear_phishing_history(self):
        """Purges all phishing scans and related details."""
        self.cursor.execute("DELETE FROM phishing_scan_details")
        self.cursor.execute("DELETE FROM phishing_scans")
        self.conn.commit()

    def get_phishing_stats(self) -> dict:
        """Calculates threat distribution, total scans, and average threat score."""
        stats = {"Safe": 0, "Low Risk": 0, "Medium Risk": 0, "High Risk": 0, "Total": 0, "AvgScore": 0.0}
        self.cursor.execute("SELECT threat_level, COUNT(*), AVG(score) FROM phishing_scans GROUP BY threat_level")
        rows = self.cursor.fetchall()
        total = 0
        total_score_sum = 0.0

        for level, count, avg_s in rows:
            if level in stats:
                stats[level] = count
            elif "High" in str(level):
                stats["High Risk"] += count
            elif "Medium" in str(level):
                stats["Medium Risk"] += count
            elif "Low" in str(level):
                stats["Low Risk"] += count
            else:
                stats["Safe"] += count
            total += count
            total_score_sum += (avg_s or 0.0) * count

        stats["Total"] = total
        stats["AvgScore"] = round(total_score_sum / total, 1) if total > 0 else 0.0
        return stats

    def search_phishing_history(self, query: str = "", threat_filter: str = None) -> list[dict]:
        """Searches scan records by URL/Domain and optional threat level."""
        sql = "SELECT id, url, normalized_url, final_url, threat_level, score, heuristic_score, ml_score, method, timestamp, scan_duration, domain, resolved_ip FROM phishing_scans WHERE 1=1"
        params = []

        if query:
            sql += " AND (url LIKE ? OR domain LIKE ?)"
            pattern = f"%{query.strip()}%"
            params.extend([pattern, pattern])

        if threat_filter and threat_filter != "All Threat Levels":
            sql += " AND threat_level = ?"
            params.append(threat_filter)

        sql += " ORDER BY id DESC LIMIT 500"
        self.cursor.execute(sql, params)
        rows = self.cursor.fetchall()
        cols = ["id", "url", "normalized_url", "final_url", "threat_level", "score", "heuristic_score", "ml_score", "method", "timestamp", "scan_duration", "domain", "resolved_ip"]
        return [dict(zip(cols, r)) for r in rows]

    # ==========================================================
    # NIDS & IPS Database Operations
    # ==========================================================
    def add_nids_event(self, event: dict) -> int:
        """Stores a captured packet or intrusion event in the database."""
        import json
        details_str = json.dumps(event.get("details", {}))
        self.cursor.execute("""
            INSERT INTO nids_events (timestamp, src_ip, dst_ip, protocol, length, risk_level, info, rule_id, mitre_attack, details_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            event.get("timestamp", ""),
            event.get("src_ip", "Unknown"),
            event.get("dst_ip", "Unknown"),
            event.get("protocol", "Other"),
            int(event.get("length", 0)),
            event.get("risk_level", "Safe"),
            event.get("info", ""),
            event.get("rule_id", ""),
            event.get("mitre_attack", ""),
            details_str
        ))
        self.conn.commit()
        return self.cursor.lastrowid

    def get_nids_events(self, limit: int = 500, protocol: str = None, risk_level: str = None, search: str = "") -> list[dict]:
        """Fetches stored NIDS events with optional filtering."""
        import json
        sql = "SELECT id, timestamp, src_ip, dst_ip, protocol, length, risk_level, info, rule_id, mitre_attack, details_json FROM nids_events WHERE 1=1"
        params = []
        if protocol and protocol not in ("All Protocols", "All"):
            sql += " AND protocol = ?"
            params.append(protocol)
        if risk_level and risk_level not in ("All Risk Levels", "All"):
            sql += " AND risk_level = ?"
            params.append(risk_level)
        if search:
            sql += " AND (src_ip LIKE ? OR dst_ip LIKE ? OR info LIKE ?)"
            pat = f"%{search.strip()}%"
            params.extend([pat, pat, pat])

        sql += f" ORDER BY id DESC LIMIT {int(limit)}"
        self.cursor.execute(sql, params)
        rows = self.cursor.fetchall()
        results = []
        for r in rows:
            details = {}
            try:
                if r[10]:
                    details = json.loads(r[10])
            except Exception:
                pass
            results.append({
                "id": r[0],
                "timestamp": r[1],
                "src_ip": r[2],
                "dst_ip": r[3],
                "protocol": r[4],
                "length": r[5],
                "risk_level": r[6],
                "info": r[7],
                "rule_id": r[8],
                "mitre_attack": r[9],
                "details": details
            })
        return results

    def clear_nids_events(self):
        """Clears all packet logs from the database."""
        self.cursor.execute("DELETE FROM nids_events")
        self.conn.commit()

    def delete_nids_events(self, event_ids: list[int]):
        """Deletes selected packet events by ID."""
        if not event_ids:
            return
        placeholders = ",".join("?" for _ in event_ids)
        self.cursor.execute(f"DELETE FROM nids_events WHERE id IN ({placeholders})", event_ids)
        self.conn.commit()

    def add_nids_blocked_ip(self, ip: str, reason: str, timestamp: str = None, blocked_by: str = "IPS"):
        """Records an OS firewall blocked IP in the database."""
        import datetime
        ts = timestamp or datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.cursor.execute("""
            INSERT OR REPLACE INTO nids_blocked_ips (ip, reason, timestamp, blocked_by, status)
            VALUES (?, ?, ?, ?, 'Blocked')
        """, (ip, reason, ts, blocked_by))
        self.conn.commit()

    def remove_nids_blocked_ip(self, ip: str):
        """Removes a blocked IP record upon unblocking."""
        self.cursor.execute("DELETE FROM nids_blocked_ips WHERE ip = ?", (ip,))
        self.conn.commit()

    def get_nids_blocked_ips(self) -> list[dict]:
        """Returns all currently registered blocked IPs."""
        self.cursor.execute("SELECT ip, reason, timestamp, blocked_by, status FROM nids_blocked_ips ORDER BY timestamp DESC")
        rows = self.cursor.fetchall()
        cols = ["ip", "reason", "timestamp", "blocked_by", "status"]
        return [dict(zip(cols, r)) for r in rows]

    def is_ip_blocked(self, ip: str) -> bool:
        """Checks if an IP is in the blocked database."""
        self.cursor.execute("SELECT 1 FROM nids_blocked_ips WHERE ip = ?", (ip,))
        return self.cursor.fetchone() is not None

    # ==========================================================
    # Cloud Security (CASB & CSPM) Database Operations
    # ==========================================================
    def save_cloud_scan(self, total: int, exposed: int, dlp: int, malware: int, score: float) -> int:
        """Records an overall Cloud CASB scan summary."""
        import datetime
        ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.cursor.execute("""
            INSERT INTO cloud_scans (timestamp, total_files, exposed_count, dlp_count, malware_count, security_score)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (ts, total, exposed, dlp, malware, score))
        self.conn.commit()
        return self.cursor.lastrowid

    def save_cloud_assets(self, assets: list[dict]):
        """Persists or updates scanned cloud assets."""
        import json
        import datetime
        ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        for a in assets:
            raw_json = json.dumps(a.get("raw_findings", []))
            is_pub = 1 if "Public" in str(a.get("findings", "")) else 0
            self.cursor.execute("""
                INSERT OR REPLACE INTO cloud_assets (file_id, name, mime_type, size, is_public, status, score, findings_summary, raw_findings_json, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                a.get("id", ""),
                a.get("name", "Unknown"),
                a.get("mimeType", ""),
                str(a.get("size", "N/A")),
                is_pub,
                a.get("status", "clean"),
                a.get("score", 0),
                a.get("findings", ""),
                raw_json,
                ts
            ))
        self.conn.commit()

    def get_cloud_assets(self, search: str = "", status: str = "All", limit: int = 200) -> list[dict]:
        """Retrieves cached cloud asset findings from database."""
        import json
        sql = "SELECT id, file_id, name, mime_type, size, is_public, status, score, findings_summary, raw_findings_json, timestamp FROM cloud_assets WHERE 1=1"
        params = []
        if search:
            sql += " AND (name LIKE ? OR findings_summary LIKE ?)"
            pat = f"%{search.strip()}%"
            params.extend([pat, pat])
        if status and status != "All":
            sql += " AND status = ?"
            params.append(status.lower())

        sql += f" ORDER BY score DESC, id DESC LIMIT {int(limit)}"
        self.cursor.execute(sql, params)
        rows = self.cursor.fetchall()
        results = []
        for r in rows:
            raw = []
            try:
                if r[9]:
                    raw = json.loads(r[9])
            except Exception:
                pass
            results.append({
                "id": r[1],
                "name": r[2],
                "mimeType": r[3],
                "size": r[4],
                "is_public": bool(r[5]),
                "status": r[6],
                "score": r[7],
                "findings": r[8],
                "raw_findings": raw,
                "timestamp": r[10]
            })
        return results

    def save_cloud_vaulted_asset(self, file_name: str, file_id: str, vault_path: str, reason: str = "Quarantined Threat"):
        """Records a quarantined cloud file saved in local vault."""
        import datetime
        ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.cursor.execute("""
            INSERT INTO cloud_vaulted_assets (file_name, file_id, vault_path, timestamp, reason)
            VALUES (?, ?, ?, ?, ?)
        """, (file_name, file_id, vault_path, ts, reason))
        self.conn.commit()

    def get_cloud_vaulted_assets(self) -> list[dict]:
        """Returns all quarantined and vaulted cloud assets."""
        self.cursor.execute("SELECT id, file_name, file_id, vault_path, timestamp, reason FROM cloud_vaulted_assets ORDER BY id DESC")
        rows = self.cursor.fetchall()
        cols = ["id", "file_name", "file_id", "vault_path", "timestamp", "reason"]
        return [dict(zip(cols, r)) for r in rows]

    def clear_cloud_data(self):
        """Clears cached cloud assets and scans."""
        self.cursor.execute("DELETE FROM cloud_assets")
        self.cursor.execute("DELETE FROM cloud_scans")
        self.conn.commit()


