import os
import hashlib
import datetime
import time
import shutil
from PyQt6.QtCore import QThread, pyqtSignal, QMutex, QWaitCondition

import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from database import DatabaseManager

# Try importing watchdog for real-time protection
try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
    WATCHDOG_AVAILABLE = True
except ImportError:
    WATCHDOG_AVAILABLE = False
    Observer = None

class ScanWorker(QThread):
    """Background thread for scanning files to prevent UI freezing."""
    progress_updated = pyqtSignal(int, str, str) # progress %, current file, time_left
    threat_found = pyqtSignal(dict)         # threat details
    scan_finished = pyqtSignal(int, int)    # total files, threats found

    def __init__(self, paths, scan_type, db_path="nexashield.db"):
        super().__init__()
        self.paths = paths
        self.scan_type = scan_type
        self.db_path = db_path
        self.is_running = True
        self.is_paused = False
        self.mutex = QMutex()
        self.condition = QWaitCondition()
        self.total_files = 0
        self.scanned_count = 0
        self.total_bytes = 0
        self.scanned_bytes = 0
        self.start_time = 0
        self.threats = 0
        self.last_emit_time = 0.0

    def pause(self):
        self.mutex.lock()
        self.is_paused = True
        self.mutex.unlock()

    def resume(self):
        self.mutex.lock()
        self.is_paused = False
        self.condition.wakeAll()
        self.mutex.unlock()

    def run(self):
        # Create a thread-local database connection to avoid SQLite threading errors
        self.db = DatabaseManager(self.db_path)
        self.start_time = time.time()
        
        if self.scan_type == "Full":
            # Use disk usage for estimation to allow immediate start (Fast)
            self.progress_updated.emit(0, "Calculating drive usage...", "Calculating...")
            for path in self.paths:
                try:
                    usage = shutil.disk_usage(path)
                    self.total_bytes += usage.used
                except:
                    pass
            
            # Stream processing
            for path in self.paths:
                if not self.is_running: break
                if os.path.isfile(path):
                    self.process_file(path)
                elif os.path.isdir(path):
                    for root, _, files in os.walk(path):
                        if not self.is_running: break
                        for file in files:
                            if not self.is_running: break
                            self.process_file(os.path.join(root, file))
        else:
            # First pass: count files for progress bar (Quick/Custom/File)
            file_list = []
            for path in self.paths:
                if os.path.isfile(path):
                    file_list.append(path)
                elif os.path.isdir(path):
                    for root, _, files in os.walk(path):
                        for file in files:
                            file_list.append(os.path.join(root, file))
            
            self.total_files = len(file_list)
            
            for file_path in file_list:
                if not self.is_running:
                    break
                self.process_file(file_path)

        self.scan_finished.emit(self.scanned_count, self.threats)

    def process_file(self, file_path):
        self.mutex.lock()
        if self.is_paused:
            self.condition.wait(self.mutex)
        self.mutex.unlock()
        
        if not self.is_running:
            return

        self.scanned_count += 1
        file_size = 0
        try:
            file_size = os.path.getsize(file_path)
        except:
            pass
        self.scanned_bytes += file_size
        
        # Calculate Progress and ETA
        elapsed = time.time() - self.start_time
        if elapsed == 0:
            elapsed = 0.001 # Prevent division by zero
        progress = 0
        eta_str = "Calculating..."

        if self.total_bytes > 0:
            # Byte-based progress (Full Scan)
            progress = int((self.scanned_bytes / self.total_bytes) * 100)
            if self.scanned_bytes > 0:
                rate = self.scanned_bytes / elapsed # bytes per second
                remaining_bytes = self.total_bytes - self.scanned_bytes
                eta_seconds = remaining_bytes / rate if rate > 0 else 0
                eta_str = str(datetime.timedelta(seconds=int(eta_seconds)))
        elif self.total_files > 0:
            # File-count based progress (Quick/Custom)
            progress = int((self.scanned_count / self.total_files) * 100)
            if self.scanned_count > 0:
                rate = self.scanned_count / elapsed # files per second
                remaining_files = self.total_files - self.scanned_count
                eta_seconds = remaining_files / rate if rate > 0 else 0
                eta_str = str(datetime.timedelta(seconds=int(eta_seconds)))
            
        # Cap progress at 99% until actually finished
        if progress >= 100: progress = 99
            
        current_time = time.time()
        # Throttle UI updates to roughly 10 times a second to prevent event loop flooding and UI lag
        if current_time - self.last_emit_time > 0.1:
            self.progress_updated.emit(progress, file_path, eta_str)
            self.last_emit_time = current_time
        
        threat = self.scan_file(file_path)
        if threat:
            self.threats += 1
            self.threat_found.emit(threat)

    def scan_file(self, file_path):
        """Hybrid detection engine."""
        try:
            # 1. Signature Check (SHA-256)
            sha256_hash = hashlib.sha256()
            with open(file_path, "rb") as f:
                # Read in chunks to handle large files
                for byte_block in iter(lambda: f.read(65536), b""): # 64KB chunks for speed
                    sha256_hash.update(byte_block)
            file_hash = sha256_hash.hexdigest()

            sig_match = self.db.check_signature(file_hash)
            if sig_match:
                return {
                    "path": file_path,
                    "name": sig_match[0],
                    "type": sig_match[1],
                    "severity": sig_match[2],
                    "method": "Signature",
                    "time": datetime.datetime.now().strftime("%H:%M:%S")
                }

            # 2. Heuristic Analysis (Basic)
            filename = os.path.basename(file_path).lower()
            
            # Double extension check
            if filename.count('.') > 1 and filename.endswith(('.exe', '.bat', '.vbs')):
                return {
                    "path": file_path,
                    "name": "Suspicious Double Extension",
                    "type": "Suspicious",
                    "severity": "Medium",
                    "method": "Heuristic",
                    "time": datetime.datetime.now().strftime("%H:%M:%S")
                }
            
        except (PermissionError, OSError):
            pass # Skip locked/system files
        
        return None

    def stop(self):
        self.is_running = False
        self.mutex.lock()
        if self.is_paused:
            self.is_paused = False
            self.condition.wakeAll()
        self.mutex.unlock()

class UpdateDefinitionsWorker(QThread):
    """Background thread for updating virus definitions."""
    finished = pyqtSignal(bool, str)

    def __init__(self, db_path="nexashield.db"):
        super().__init__()
        self.db_path = db_path

    def run(self):
        try:
            # Simulating network delay and update
            time.sleep(2)
            
            # Mock new signatures
            new_sigs = [
                ("44d88612fea8a8f36de82e1278abb02f", "EICAR-Test-File-MD5", "Virus", "High"),
                ("5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8", "WannaCry", "Ransomware", "Critical"),
                ("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "Empty-Test", "Suspicious", "Low")
            ]
            
            db = DatabaseManager(self.db_path)
            added = 0
            for sig in new_sigs:
                # Check if hash exists
                db.cursor.execute("SELECT hash FROM signatures WHERE hash=?", (sig[0],))
                if not db.cursor.fetchone():
                    db.cursor.execute("INSERT INTO signatures (hash, name, type, severity) VALUES (?, ?, ?, ?)", sig)
                    added += 1
            
            db.conn.commit()
            self.finished.emit(True, f"Virus definitions updated successfully.\nAdded {added} new signatures.")
            
        except Exception as e:
            self.finished.emit(False, f"Update failed: {str(e)}")

if WATCHDOG_AVAILABLE:
    class RealTimeHandler(FileSystemEventHandler):
        def __init__(self, callback):
            self.callback = callback

        def on_created(self, event):
            if not event.is_directory:
                self.callback(event.src_path)

        def on_modified(self, event):
            if not event.is_directory:
                self.callback(event.src_path)
else:
    RealTimeHandler = None