import sys
import os
import hashlib
import datetime
import time
import shutil
import json
import string
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLabel, 
    QProgressBar, QTableWidget, QTableWidgetItem, QHeaderView,
    QFileDialog, QMessageBox, QTabWidget, QFrame, QAbstractItemView,
    QTimeEdit, QCheckBox, QComboBox, QGroupBox, QLineEdit, QDialog,
    QFormLayout
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QObject, QTimer, QTime
from PyQt6.QtGui import QColor, QBrush, QDragEnterEvent, QDropEvent, QTextDocument

import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from database import DatabaseManager
from .antivirus_logic import ScanWorker, UpdateDefinitionsWorker, RealTimeHandler, WATCHDOG_AVAILABLE, Observer

try:
    from PyQt6.QtPrintSupport import QPrinter
    PDF_SUPPORT = True
except ImportError:
    PDF_SUPPORT = False

class FileDetailsDialog(QDialog):
    def __init__(self, parent, data):
        super().__init__(parent)
        self.setWindowTitle("Threat Details")
        self.setMinimumWidth(500)
        
        layout = QVBoxLayout(self)
        
        title = QLabel("File Information")
        title.setObjectName("DialogTitle")
        layout.addWidget(title)
        
        form_layout = QFormLayout()
        form_layout.setLabelAlignment(Qt.AlignmentFlag.AlignRight)
        
        for key, value in data.items():
            lbl_key = QLabel(key + ":")
            lbl_key.setObjectName("DialogKey")
            
            lbl_val = QLabel(str(value))
            lbl_val.setWordWrap(True)
            lbl_val.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            
            if key == "Severity":
                lbl_val.setProperty("severity", value)
                lbl_val.style().unpolish(lbl_val)
                lbl_val.style().polish(lbl_val)
            
            form_layout.addRow(lbl_key, lbl_val)
            
        layout.addLayout(form_layout)
        layout.addStretch()
        
        close_btn = QPushButton("Close")
        close_btn.clicked.connect(self.accept)
        layout.addWidget(close_btn)

class AntivirusWidget(QWidget):
    def __init__(self, session_manager=None):
        super().__init__()
        self.session = session_manager
        db_path = self.session.get_db_path() if self.session else "nexashield.db"
        self.db = DatabaseManager(db_path)
        
        workspace = self.session.workspace_dir if self.session else "."
        self.quarantine_log_file = os.path.join(workspace, "quarantine_log.json")
        self.schedule_file = os.path.join(workspace, "scan_schedule.json")
        self.setAcceptDrops(True) # Enable Drag & Drop
        self.setup_ui()
        self.observer = None
        self.scan_thread = None
        self.update_worker = None
        self.manual_stop = False
        
        # Scheduler Timer
        self.scheduler_timer = QTimer(self)
        self.scheduler_timer.timeout.connect(self.check_schedule)
        self.scheduler_timer.start(60000) # Check every minute

    def setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)

        # --- Header ---
        header_layout = QHBoxLayout()
        title = QLabel("🛡️ Smart Antivirus Engine")
        title.setObjectName("HeaderTitle")
        header_layout.addWidget(title)
        header_layout.addStretch()
        
        self.rt_status = QLabel("⚡ Real-Time: OFF")
        self.rt_status.setObjectName("StatusRed")
        header_layout.addWidget(self.rt_status)

        self.rt_btn = QPushButton("✅ Enable Real-Time")
        self.rt_btn.setObjectName("BtnPrimary")
        self.rt_btn.clicked.connect(self.toggle_realtime)
        if not WATCHDOG_AVAILABLE:
            self.rt_btn.setEnabled(False)
            self.rt_btn.setToolTip("Install 'watchdog' library to enable")
        header_layout.addWidget(self.rt_btn)
        
        layout.addLayout(header_layout)

        # --- Tabs ---
        self.tabs = QTabWidget()
        self.scanner_tab = QWidget()
        self.quarantine_tab = QWidget()
        self.scheduler_tab = QWidget()
        self.history_tab = QWidget()
        
        self.setup_scanner_tab()
        self.setup_quarantine_tab()
        self.setup_scheduler_tab()
        self.setup_history_tab()
        
        self.tabs.addTab(self.scanner_tab, "🔍 Scanner")
        self.tabs.addTab(self.quarantine_tab, "☣️ Quarantine")
        self.tabs.addTab(self.scheduler_tab, "📅 Scheduler")
        self.tabs.addTab(self.history_tab, "📜 Scan History")
        layout.addWidget(self.tabs)

    def setup_scanner_tab(self):
        layout = QVBoxLayout(self.scanner_tab)
        
        # --- Top Section (Split 2:1) ---
        top_layout = QHBoxLayout()
        
        # Left: System Scan Controls (Folder/Directory)
        scan_group = QGroupBox("💻 System & Directory Scan")
        scan_layout = QVBoxLayout(scan_group)
        
        btn_row1 = QHBoxLayout()
        btn_quick = QPushButton("⚡ Quick Scan")
        btn_quick.setObjectName("BtnPrimary")
        btn_quick.clicked.connect(lambda: self.start_scan("Quick"))
        
        btn_full = QPushButton("🔍 Full Scan")
        btn_full.setObjectName("BtnSecondary")
        btn_full.clicked.connect(lambda: self.start_scan("Full"))
        btn_row1.addWidget(btn_quick)
        btn_row1.addWidget(btn_full)
        
        btn_row2 = QHBoxLayout()
        btn_custom = QPushButton("📂 Custom Scan")
        btn_custom.setObjectName("BtnSuccess")
        btn_custom.clicked.connect(self.select_custom_scan)
        
        btn_file = QPushButton("📄 Scan File")
        btn_file.setObjectName("BtnPurple")
        btn_file.clicked.connect(self.select_file_scan)
        
        btn_update = QPushButton("🔄 Update DB")
        btn_update.setObjectName("BtnInfo")
        btn_update.clicked.connect(self.update_definitions)
        btn_row2.addWidget(btn_custom)
        btn_row2.addWidget(btn_file)
        btn_row2.addWidget(btn_update)
        
        scan_layout.addLayout(btn_row1)
        scan_layout.addLayout(btn_row2)
        
        # Right: Manual Hash Scan (Files)
        hash_group = QGroupBox("🔢 Manual File Hash Scan")
        hash_layout = QVBoxLayout(hash_group)
        
        self.hash_input = QLineEdit()
        self.hash_input.setPlaceholderText("🔢 Enter SHA-256 Hash...")
        
        btn_hash = QPushButton("🔎 Check Hash")
        btn_hash.setObjectName("BtnIndigo")
        btn_hash.clicked.connect(self.check_manual_hash)
        
        hash_layout.addWidget(self.hash_input)
        hash_layout.addWidget(btn_hash)
        hash_layout.addStretch()
        
        # Add to top layout with 2:1 ratio
        top_layout.addWidget(scan_group, 2)
        top_layout.addWidget(hash_group, 1)
        
        layout.addLayout(top_layout)

        # Status Area
        self.status_label = QLabel("ℹ️ Status: Idle - Drag & Drop files here to scan")
        self.status_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self.status_label)

        progress_layout = QHBoxLayout()
        self.progress_bar = QProgressBar()
        self.progress_bar.setTextVisible(True)
        self.progress_bar.setObjectName("AntivirusProgress")
        progress_layout.addWidget(self.progress_bar)
        
        self.pause_btn = QPushButton("⏸️ Pause")
        self.pause_btn.setFixedWidth(80)
        self.pause_btn.setEnabled(False)
        self.pause_btn.clicked.connect(self.toggle_pause)
        progress_layout.addWidget(self.pause_btn)
        
        self.stop_btn = QPushButton("⏹️ Stop")
        self.stop_btn.setFixedWidth(80)
        self.stop_btn.setEnabled(False)
        self.stop_btn.clicked.connect(self.stop_scan)
        progress_layout.addWidget(self.stop_btn)
        
        layout.addLayout(progress_layout)

        # Results Table
        self.results_table = QTableWidget()
        self.results_table.setColumnCount(6)
        self.results_table.setHorizontalHeaderLabels(["📂 File Path", "🦠 Threat", "🏷️ Type", "⚠️ Severity", "⚙️ Method", "🕒 Time"])
        self.results_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.results_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.results_table.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self.results_table.cellDoubleClicked.connect(self.show_file_details)
        layout.addWidget(self.results_table)

        # Action Buttons
        actions = QHBoxLayout()
        btn_select_all = QPushButton("✅ Select All")
        btn_select_all.setObjectName("BtnInfo")
        btn_select_all.clicked.connect(self.select_all_threats)

        btn_export = QPushButton("📄 Export Report (PDF)")
        btn_export.setObjectName("BtnWarning")
        btn_export.clicked.connect(lambda: self.export_table_to_pdf(self.results_table, "Scan Results", "ScanReport.pdf"))

        btn_del = QPushButton("🗑️ Delete Selected")
        btn_del.setObjectName("BtnDanger")
        btn_del.clicked.connect(self.delete_threat)
        
        btn_quarantine = QPushButton("☣️ Quarantine Selected")
        btn_quarantine.setObjectName("BtnQuarantine")
        btn_quarantine.clicked.connect(self.quarantine_threat)
        
        btn_ignore = QPushButton("👁️ Ignore")
        btn_ignore.clicked.connect(self.ignore_threat)
        
        actions.addWidget(btn_select_all)
        actions.addWidget(btn_export)
        actions.addWidget(btn_del)
        actions.addWidget(btn_quarantine)
        actions.addWidget(btn_ignore)
        actions.addStretch()
        layout.addLayout(actions)

    def setup_quarantine_tab(self):
        layout = QVBoxLayout(self.quarantine_tab)
        
        self.quarantine_table = QTableWidget()
        self.quarantine_table.setColumnCount(3)
        self.quarantine_table.setHorizontalHeaderLabels(["📂 Original Path", "📅 Quarantined Date", "ℹ️ Status"])
        self.quarantine_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.quarantine_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.quarantine_table.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        layout.addWidget(self.quarantine_table)

        btns = QHBoxLayout()
        select_all_btn = QPushButton("✅ Select All")
        select_all_btn.setObjectName("BtnInfo")
        select_all_btn.clicked.connect(self.quarantine_table.selectAll)

        restore_btn = QPushButton("♻️ Restore Selected")
        restore_btn.setObjectName("BtnSuccess")
        restore_btn.clicked.connect(self.restore_selected)
        
        export_btn = QPushButton("📄 Export Report (PDF)")
        export_btn.setObjectName("BtnWarning")
        export_btn.clicked.connect(lambda: self.export_table_to_pdf(self.quarantine_table, "Quarantine History", "QuarantineReport.pdf"))
        
        del_btn = QPushButton("🗑️ Delete Permanently")
        del_btn.setObjectName("BtnDanger")
        del_btn.clicked.connect(self.delete_quarantined_selected)
        
        btns.addWidget(select_all_btn)
        btns.addWidget(restore_btn)
        btns.addWidget(export_btn)
        btns.addWidget(del_btn)
        layout.addLayout(btns)
        
        self.load_quarantine_items()

    def setup_scheduler_tab(self):
        layout = QVBoxLayout(self.scheduler_tab)
        layout.setSpacing(20)
        layout.setContentsMargins(30, 30, 30, 30)

        # Title
        title = QLabel("📅 Scheduled Scanning")
        title.setObjectName("SchedTitle")
        layout.addWidget(title)

        # Description
        desc = QLabel("Configure NexaShield to automatically scan your system at a specific time daily.")
        desc.setObjectName("SchedDesc")
        desc.setWordWrap(True)
        layout.addWidget(desc)

        # Settings Container
        container = QFrame()
        container.setObjectName("ConfigCard")
        form_layout = QFormLayout(container)
        form_layout.setContentsMargins(20, 20, 20, 20)
        form_layout.setSpacing(15)

        self.sched_enable = QCheckBox("✅ Enable Daily Scan")
        form_layout.addRow("Status:", self.sched_enable)

        self.sched_type = QComboBox()
        self.sched_type.addItems(["Quick", "Full"])
        form_layout.addRow("Scan Type:", self.sched_type)

        self.sched_time = QTimeEdit()
        self.sched_time.setDisplayFormat("HH:mm")
        form_layout.addRow("Time:", self.sched_time)

        layout.addWidget(container)

        # Save Button
        save_btn = QPushButton("💾 Save Configuration")
        save_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        save_btn.setObjectName("BtnPrimary")
        save_btn.clicked.connect(self.save_schedule)
        layout.addWidget(save_btn, alignment=Qt.AlignmentFlag.AlignRight)

        layout.addStretch()
        
        self.load_schedule()

    def setup_history_tab(self):
        layout = QVBoxLayout(self.history_tab)
        
        self.history_table = QTableWidget()
        self.history_table.setColumnCount(4)
        self.history_table.setHorizontalHeaderLabels(["🔍 Scan Type", "📂 Files Scanned", "🦠 Threats Found", "🕒 Timestamp"])
        self.history_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        layout.addWidget(self.history_table)
        
        refresh_btn = QPushButton("🔄 Refresh History")
        refresh_btn.clicked.connect(self.load_history)
        
        export_btn = QPushButton("📄 Export Report (PDF)")
        export_btn.setObjectName("BtnWarning")
        export_btn.clicked.connect(lambda: self.export_table_to_pdf(self.history_table, "Scan History", "ScanHistoryReport.pdf"))
        
        clear_btn = QPushButton("🗑️ Clear History")
        clear_btn.setObjectName("BtnDanger")
        clear_btn.clicked.connect(self.clear_history)
        
        h_layout = QHBoxLayout()
        h_layout.addWidget(refresh_btn)
        h_layout.addWidget(export_btn)
        h_layout.addWidget(clear_btn)
        layout.addLayout(h_layout)

    # --- Logic ---

    def reset_ui(self):
        """Clears inputs and resets the scanner state."""
        self.hash_input.clear()
        self.results_table.setRowCount(0)
        self.status_label.setText("ℹ️ Status: Idle - Drag & Drop files here to scan")
        self.progress_bar.setValue(0)
        self.progress_bar.setRange(0, 100)
        
        if self.scan_thread and self.scan_thread.isRunning():
            self.stop_scan()

    def check_manual_hash(self):
        text = self.hash_input.text().strip()
        if not text:
            QMessageBox.warning(self, "Input Error", "Please enter a file hash.")
            return
            
        # Check DB
        sig_match = self.db.check_signature(text)
        if sig_match:
            # Add to table
            row = self.results_table.rowCount()
            self.results_table.insertRow(row)
            self.results_table.setItem(row, 0, QTableWidgetItem(f"Manual Hash: {text}"))
            self.results_table.setItem(row, 1, QTableWidgetItem(sig_match[0])) # Name
            self.results_table.setItem(row, 2, QTableWidgetItem(sig_match[1])) # Type
            
            sev_item = QTableWidgetItem(sig_match[2]) # Severity
            if sig_match[2] in ["High", "Critical"]:
                sev_item.setForeground(QBrush(QColor("#dc3545")))
            self.results_table.setItem(row, 3, sev_item)
            
            self.results_table.setItem(row, 4, QTableWidgetItem("Manual Check"))
            self.results_table.setItem(row, 5, QTableWidgetItem(datetime.datetime.now().strftime("%H:%M:%S")))
            
            QMessageBox.warning(self, "Threat Detected", f"Hash found in database!\nThreat: {sig_match[0]}\nType: {sig_match[1]}")
        else:
            QMessageBox.information(self, "Clean", "Hash not found in signature database.")

    def export_table_to_pdf(self, table, title, default_filename):
        import tempfile
        import os
        if not PDF_SUPPORT:
            QMessageBox.warning(self, "Error", "PDF Export not supported (QtPrintSupport missing).")
            return
            
        temp_fd, temp_path = tempfile.mkstemp(suffix=".pdf")
        os.close(temp_fd)
            
        printer = QPrinter(QPrinter.PrinterMode.HighResolution)
        printer.setOutputFormat(QPrinter.OutputFormat.PdfFormat)
        printer.setOutputFileName(temp_path)
        
        doc = QTextDocument()
        
        # Build HTML
        html = """
        <html>
        <head>
            <style>
                table { border-collapse: collapse; width: 100%; }
                th, td { border: 1px solid black; padding: 8px; text-align: left; }
                th { background-color: #f2f2f2; }
                h1 { color: #0078d7; }
            </style>
        </head>
        <body>
            <h1>{title}</h1>
            <p>Generated on: """ + datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + """</p>
            <table>
                <thead>
                    <tr>
        """
        
        for col in range(table.columnCount()):
            item = table.horizontalHeaderItem(col)
            header = item.text() if item else f"Col {col}"
            html += f"<th>{header}</th>"
            
        html += "</tr></thead><tbody>"
        
        for row in range(table.rowCount()):
            html += "<tr>"
            for col in range(table.columnCount()):
                item = table.item(row, col)
                text = item.text() if item else ""
                html += f"<td>{text}</td>"
            html += "</tr>"
            
        html += """
                </tbody>
            </table>
        </body>
        </html>
        """
        
        doc.setHtml(html)
        doc.print(printer)
        
        with open(temp_path, "rb") as f:
            pdf_bytes = f.read()
        os.remove(temp_path)
        
        if self.session and hasattr(self.session, 'file_manager'):
            self.session.file_manager.export_file(
                filename=default_filename,
                content=pdf_bytes,
                module_source="Antivirus",
                file_type="PDF",
                tags="Critical" if "Quarantine" in title else "Routine"
            )
            QMessageBox.information(self, "Vaulted", "Antivirus report securely vaulted in FMS.")
        else:
            QMessageBox.warning(self, "Warning", "FMS not available, file not saved.")

    def show_file_details(self, row, column):
        file_path = self.results_table.item(row, 0).text()
        threat = self.results_table.item(row, 1).text()
        t_type = self.results_table.item(row, 2).text()
        severity = self.results_table.item(row, 3).text()
        method = self.results_table.item(row, 4).text()
        time_str = self.results_table.item(row, 5).text()
        
        details = {
            "File Path": file_path,
            "Threat Name": threat,
            "Threat Type": t_type,
            "Severity": severity,
            "Detection Method": method,
            "Detection Time": time_str
        }
        
        if os.path.exists(file_path):
            try:
                stat = os.stat(file_path)
                details["File Size"] = f"{stat.st_size:,} bytes"
                
                # Calculate Hashes
                sha256 = hashlib.sha256()
                md5 = hashlib.md5()
                with open(file_path, "rb") as f:
                    for chunk in iter(lambda: f.read(4096), b""):
                        sha256.update(chunk)
                        md5.update(chunk)
                
                details["MD5"] = md5.hexdigest()
                details["SHA-256"] = sha256.hexdigest()
                
            except Exception as e:
                details["Error reading file"] = str(e)
        else:
            details["Status"] = "File not found (Deleted or Moved)"
            
        dlg = FileDetailsDialog(self, details)
        dlg.exec()

    def update_definitions(self):
        self.status_label.setText("Status: Updating Virus Definitions...")
        db_path = self.session.get_db_path() if self.session else "nexashield.db"
        self.update_worker = UpdateDefinitionsWorker(db_path)
        self.update_worker.finished.connect(self.on_update_finished)
        self.update_worker.start()

    def on_update_finished(self, success, message):
        if success:
            QMessageBox.information(self, "Update Complete", message)
            self.status_label.setText("Status: Idle - Definitions Updated")
        else:
            QMessageBox.warning(self, "Update Failed", message)
            self.status_label.setText("Status: Idle")

    def load_schedule(self):
        if os.path.exists(self.schedule_file):
            try:
                with open(self.schedule_file, 'r') as f:
                    data = json.load(f)
                    self.sched_enable.setChecked(data.get('enabled', False))
                    self.sched_type.setCurrentText(data.get('type', 'Quick'))
                    time_str = data.get('time', '12:00')
                    self.sched_time.setTime(QTime.fromString(time_str, "HH:mm"))
            except Exception as e:
                print(f"Error loading schedule: {e}")

    def save_schedule(self):
        data = {
            'enabled': self.sched_enable.isChecked(),
            'type': self.sched_type.currentText(),
            'time': self.sched_time.time().toString("HH:mm"),
            'last_run': '' 
        }
        # Preserve last_run if exists
        if os.path.exists(self.schedule_file):
            try:
                with open(self.schedule_file, 'r') as f:
                    old_data = json.load(f)
                    data['last_run'] = old_data.get('last_run', '')
            except:
                pass
                
        try:
            with open(self.schedule_file, 'w') as f:
                json.dump(data, f, indent=4)
            QMessageBox.information(self, "Schedule", "Schedule saved successfully.")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to save schedule: {e}")

    def check_schedule(self):
        if not os.path.exists(self.schedule_file):
            return
            
        try:
            with open(self.schedule_file, 'r') as f:
                data = json.load(f)
            
            if not data.get('enabled', False):
                return
                
            sched_time = QTime.fromString(data.get('time', '00:00'), "HH:mm")
            now = datetime.datetime.now()
            current_time = now.time()
            
            # Check if current time matches (within the minute)
            if current_time.hour() == sched_time.hour() and current_time.minute() == sched_time.minute():
                last_run_str = data.get('last_run', '')
                today_str = now.strftime("%Y-%m-%d")
                
                if last_run_str != today_str:
                    # Check if scan is already running
                    if self.scan_thread and self.scan_thread.isRunning():
                        print("Scheduled scan skipped: Scan already in progress.")
                        return

                    # Run scan
                    scan_type = data.get('type', 'Quick')
                    self.start_scan(scan_type)
                    
                    # Update last run
                    data['last_run'] = today_str
                    with open(self.schedule_file, 'w') as f:
                        json.dump(data, f, indent=4)
        except Exception as e:
            print(f"Scheduler error: {e}")

    def start_scan(self, scan_type, custom_path=None):
        if self.scan_thread and self.scan_thread.isRunning():
            QMessageBox.warning(self, "Scan in Progress", "Please wait for the current scan to finish.")
            return

        paths = []
        if scan_type == "Quick":
            # Scan User Documents and Downloads
            home = os.path.expanduser("~")
            paths = [os.path.join(home, "Documents"), os.path.join(home, "Downloads")]
        elif scan_type == "Full":
            # Scan all available drives
            paths = []
            if os.name == 'nt':
                paths = [f"{d}:\\" for d in string.ascii_uppercase if os.path.exists(f"{d}:\\")]
            else:
                paths = ["/"]
        elif scan_type == "Custom" and custom_path:
            paths = [custom_path]
        elif scan_type == "File" and custom_path:
            paths = [custom_path]

        self.results_table.setRowCount(0)
        self.status_label.setText(f"Status: Scanning ({scan_type})...")
        self.progress_bar.setValue(0)
        self.pause_btn.setEnabled(True)
        self.pause_btn.setText("Pause")
        self.stop_btn.setEnabled(True)
        self.manual_stop = False
        
        db_path = self.session.get_db_path() if self.session else "nexashield.db"
        self.scan_thread = ScanWorker(paths, scan_type, db_path)
        self.scan_thread.progress_updated.connect(self.update_progress)
        self.scan_thread.threat_found.connect(self.add_threat_row)
        self.scan_thread.scan_finished.connect(self.scan_finished)
        self.scan_thread.start()

    def toggle_pause(self):
        if not self.scan_thread:
            return
            
        if "Pause" in self.pause_btn.text():
            self.scan_thread.pause()
            self.pause_btn.setText("▶️ Resume")
            self.status_label.setText(self.status_label.text() + " (Paused)")
            # Stop indeterminate animation if active by setting a fixed range
            if self.progress_bar.maximum() == 0:
                self.progress_bar.setRange(0, 100)
                self.progress_bar.setValue(0) 
        else:
            self.scan_thread.resume()
            self.pause_btn.setText("⏸️ Pause")
            text = self.status_label.text().replace(" (Paused)", "")
            self.status_label.setText(text)
            # Resume indeterminate animation if it was a full scan
            if self.scan_thread.scan_type == "Full":
                 self.progress_bar.setRange(0, 0)

    def stop_scan(self):
        if self.scan_thread and self.scan_thread.isRunning():
            self.manual_stop = True
            self.scan_thread.stop()
            # We don't wait() here to avoid freezing UI, we let the finished signal handle cleanup
            self.status_label.setText("Status: Stopping scan...")
            self.pause_btn.setEnabled(False)
            self.stop_btn.setEnabled(False)
            self.pause_btn.setText("⏸️ Pause")
            # Reset progress bar
            self.progress_bar.setRange(0, 100)
            self.progress_bar.setValue(0)

    def select_custom_scan(self):
        path = QFileDialog.getExistingDirectory(self, "Select Folder to Scan")
        if path:
            self.start_scan("Custom", path)

    def select_file_scan(self):
        path, _ = QFileDialog.getOpenFileName(self, "Select File to Scan")
        if path:
            self.start_scan("File", path)

    def update_progress(self, value, current_file, time_left):
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(value)
            
        # Truncate file path for display
        display_path = (current_file[:50] + '...') if len(current_file) > 50 else current_file
        self.status_label.setText(f"Scanning: {display_path} | Time Left: {time_left}")

    def add_threat_row(self, threat):
        row = self.results_table.rowCount()
        self.results_table.insertRow(row)
        self.results_table.setItem(row, 0, QTableWidgetItem(threat['path']))
        self.results_table.setItem(row, 1, QTableWidgetItem(threat['name']))
        self.results_table.setItem(row, 2, QTableWidgetItem(threat['type']))
        
        sev_item = QTableWidgetItem(threat['severity'])
        if threat['severity'] == "High" or threat['severity'] == "Critical":
            sev_item.setForeground(QBrush(QColor("#dc3545")))
        self.results_table.setItem(row, 3, sev_item)
        
        self.results_table.setItem(row, 4, QTableWidgetItem(threat['method']))
        self.results_table.setItem(row, 5, QTableWidgetItem(threat['time']))

    def scan_finished(self, total, threats):
        if self.manual_stop:
            self.status_label.setText("Status: Scan Stopped.")
            QMessageBox.information(self, "Scan Stopped", "The scan was stopped by the user.")
        else:
            self.status_label.setText(f"Scan Completed. Scanned {total} files. Found {threats} threats.")
            if threats > 0:
                QMessageBox.warning(self, "Threats Detected", f"Scan found {threats} threats! Please review results.")
            else:
                QMessageBox.information(self, "Clean", "No threats found.")

        self.progress_bar.setValue(100)
        self.progress_bar.setRange(0, 100)
        self.pause_btn.setEnabled(False)
        self.stop_btn.setEnabled(False)
        self.db.add_scan_history(self.scan_thread.scan_type, total, threats)
        self.load_history()

    def load_history(self):
        history = self.db.get_scan_history()
        self.history_table.setRowCount(len(history))
        for i, row in enumerate(history):
            # row: id, type, files, threats, time
            self.history_table.setItem(i, 0, QTableWidgetItem(row[1]))
            self.history_table.setItem(i, 1, QTableWidgetItem(str(row[2])))
            self.history_table.setItem(i, 2, QTableWidgetItem(str(row[3])))
            self.history_table.setItem(i, 3, QTableWidgetItem(row[4]))

    def clear_history(self):
        confirm = QMessageBox.question(self, "Confirm Clear", "Are you sure you want to clear the entire scan history?",
                                     QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        
        if confirm == QMessageBox.StandardButton.Yes:
            self.db.clear_scan_history()
            self.load_history()
            QMessageBox.information(self, "Success", "Scan history cleared.")

    def load_quarantine_items(self):
        self.quarantine_table.setRowCount(0)
        if not os.path.exists(self.quarantine_log_file):
            return
        
        try:
            with open(self.quarantine_log_file, 'r') as f:
                data = json.load(f)
                
            self.quarantine_table.setRowCount(len(data))
            for i, entry in enumerate(data):
                self.quarantine_table.setItem(i, 0, QTableWidgetItem(entry.get('original_path', 'Unknown')))
                self.quarantine_table.setItem(i, 1, QTableWidgetItem(entry.get('timestamp', '')))
                
                q_path = entry.get('quarantine_path')
                status = "Secured" if os.path.exists(q_path) else "Missing"
                self.quarantine_table.setItem(i, 2, QTableWidgetItem(status))
                
                # Store entry data for retrieval
                self.quarantine_table.item(i, 0).setData(Qt.ItemDataRole.UserRole, entry)
        except Exception as e:
            print(f"Error loading quarantine log: {e}")

    def select_all_threats(self):
        self.results_table.selectAll()

    def delete_threat(self):
        selected = self.results_table.selectedItems()
        if not selected:
            return
        
        rows = sorted(list(set(item.row() for item in selected)), reverse=True)
        
        confirm = QMessageBox.question(self, "Confirm Delete", f"Permanently delete {len(rows)} selected file(s)?",
                                     QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        
        if confirm == QMessageBox.StandardButton.Yes:
            deleted_count = 0
            for row in rows:
                file_path = self.results_table.item(row, 0).text()
                try:
                    if os.path.exists(file_path):
                        os.remove(file_path)
                    self.results_table.removeRow(row)
                    deleted_count += 1
                except Exception as e:
                    print(f"Error deleting {file_path}: {e}")
            
            if deleted_count > 0:
                QMessageBox.information(self, "Success", f"Deleted {deleted_count} files.")

    def quarantine_threat(self):
        selected = self.results_table.selectedItems()
        if not selected:
            return
        
        rows = sorted(list(set(item.row() for item in selected)), reverse=True)
        
        confirm = QMessageBox.question(self, "Confirm Quarantine", f"Quarantine {len(rows)} selected file(s)?",
                                     QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        
        if confirm == QMessageBox.StandardButton.Yes:
            quarantined_count = 0
            quarantine_dir = "quarantine"
            if not os.path.exists(quarantine_dir):
                os.makedirs(quarantine_dir)

            log_entries = []
            if os.path.exists(self.quarantine_log_file):
                try:
                    with open(self.quarantine_log_file, 'r') as f:
                        log_entries = json.load(f)
                except:
                    log_entries = []

            for row in rows:
                file_path = self.results_table.item(row, 0).text()
                try:
                    if os.path.exists(file_path):
                        filename = os.path.basename(file_path)
                        timestamp = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
                        dest_path = os.path.join(quarantine_dir, f"{timestamp}_{filename}.quarantined")
                        
                        shutil.move(file_path, dest_path)
                        
                        log_entries.append({
                            "original_path": file_path,
                            "quarantine_path": dest_path,
                            "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                        })
                        
                        self.results_table.removeRow(row)
                        quarantined_count += 1
                except Exception as e:
                    print(f"Error quarantining {file_path}: {e}")
            
            with open(self.quarantine_log_file, 'w') as f:
                json.dump(log_entries, f, indent=4)
            
            self.load_quarantine_items()
            
            if quarantined_count > 0:
                QMessageBox.information(self, "Success", f"Quarantined {quarantined_count} files.")

    def restore_selected(self):
        selected = self.quarantine_table.selectedItems()
        if not selected:
            return
        
        rows = sorted(list(set(item.row() for item in selected)), reverse=True)
        
        if not os.path.exists(self.quarantine_log_file):
            return
            
        with open(self.quarantine_log_file, 'r') as f:
            log_entries = json.load(f)
            
        restored_paths = set()
        
        for row in rows:
            item = self.quarantine_table.item(row, 0)
            entry = item.data(Qt.ItemDataRole.UserRole)
            if not entry: continue
            
            q_path = entry['quarantine_path']
            orig_path = entry['original_path']
            
            if os.path.exists(q_path):
                try:
                    os.makedirs(os.path.dirname(orig_path), exist_ok=True)
                    shutil.move(q_path, orig_path)
                    restored_paths.add(q_path)
                except Exception as e:
                    QMessageBox.warning(self, "Error", f"Failed to restore {orig_path}:\n{e}")
            else:
                restored_paths.add(q_path) 

        # Update log
        new_log = [e for e in log_entries if e['quarantine_path'] not in restored_paths]
        with open(self.quarantine_log_file, 'w') as f:
            json.dump(new_log, f, indent=4)
            
        self.load_quarantine_items()
        QMessageBox.information(self, "Success", "Selected files restored.")

    def delete_quarantined_selected(self):
        selected = self.quarantine_table.selectedItems()
        if not selected: return
        
        rows = sorted(list(set(item.row() for item in selected)), reverse=True)
        confirm = QMessageBox.question(self, "Confirm", "Permanently delete selected quarantined files?", QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if confirm != QMessageBox.StandardButton.Yes: return

        if not os.path.exists(self.quarantine_log_file): return
        with open(self.quarantine_log_file, 'r') as f: log_entries = json.load(f)
        
        deleted_paths = set()
        for row in rows:
            item = self.quarantine_table.item(row, 0)
            entry = item.data(Qt.ItemDataRole.UserRole)
            if not entry: continue
            
            q_path = entry['quarantine_path']
            if os.path.exists(q_path):
                try:
                    os.remove(q_path)
                except: pass
            deleted_paths.add(q_path)
            
        new_log = [e for e in log_entries if e['quarantine_path'] not in deleted_paths]
        with open(self.quarantine_log_file, 'w') as f: json.dump(new_log, f, indent=4)
        
        self.load_quarantine_items()

    def ignore_threat(self):
        selected = self.results_table.selectedItems()
        if not selected:
            return
            
        rows = sorted(list(set(item.row() for item in selected)), reverse=True)
        for row in rows:
            self.results_table.removeRow(row)

    # --- Drag & Drop ---
    def dragEnterEvent(self, event: QDragEnterEvent):
        if event.mimeData().hasUrls():
            event.accept()
        else:
            event.ignore()

    def dropEvent(self, event: QDropEvent):
        files = [u.toLocalFile() for u in event.mimeData().urls()]
        if files:
            # If directory, scan it. If file, scan it.
            path = files[0] # Just take the first one for simplicity in this demo
            if os.path.isdir(path):
                self.start_scan("Custom", path)
            else:
                self.start_scan("Custom", os.path.dirname(path))

    # --- Real-Time Protection ---
    def toggle_realtime(self):
        if "OFF" in self.rt_status.text():
            # Start
            path_to_watch = os.path.expanduser("~") # Watch user home
            self.event_handler = RealTimeHandler(self.on_realtime_event)
            self.observer = Observer()
            self.observer.schedule(self.event_handler, path_to_watch, recursive=False)
            self.observer.start()
            
            self.rt_status.setText("⚡ Real-Time: ON")
            self.rt_status.setObjectName("StatusGreen")
            self.rt_status.style().unpolish(self.rt_status); self.rt_status.style().polish(self.rt_status)
            self.rt_btn.setText("❌ Disable Real-Time")
        else:
            # Stop
            if self.observer:
                self.observer.stop()
                self.observer.join()
            
            self.rt_status.setText("⚡ Real-Time: OFF")
            self.rt_status.setObjectName("StatusRed")
            self.rt_status.style().unpolish(self.rt_status); self.rt_status.style().polish(self.rt_status)
            self.rt_btn.setText("✅ Enable Real-Time")

    def on_realtime_event(self, file_path):
        # In a real app, queue this. For now, just print or log.
        print(f"Real-time detection: File modified/created: {file_path}")
        # Trigger a background scan of this specific file if needed