import sys
import os
import json
import webbrowser
import requests
from http.server import HTTPServer
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QTableWidget, QTableWidgetItem,
    QHeaderView, QAbstractItemView, QMessageBox, QFrame, QProgressBar, QDialog, QTextEdit, QMenu
)
from PyQt6.QtGui import QAction

class DLPReportDialog(QDialog):
    def __init__(self, filename, raw_findings, parent=None):
        super().__init__(parent)
        self.setWindowTitle(f"Advanced Analysis Report: {filename}")
        self.resize(600, 450)
        self.setStyleSheet("background-color: #1e1e1e; color: white;")
        
        layout = QVBoxLayout(self)
        
        title = QLabel(f"DLP Expert Analysis\nFile: {filename}")
        title.setStyleSheet("font-size: 18px; font-weight: bold; color: #0078d7;")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(title)
        
        self.text_area = QTextEdit()
        self.text_area.setReadOnly(True)
        self.text_area.setStyleSheet("background-color: #2b2b2b; border: 1px solid #444; padding: 10px; font-size: 14px;")
        
        html_report = "<h3>Identified Sensitive Data</h3><ul>"
        if not raw_findings:
            html_report += "<li>No sensitive data detected.</li>"
        else:
            for finding in raw_findings:
                color = "#dc3545" if finding['severity'] == "Critical" else "#fd7e14" if finding['severity'] == "High" else "#ffc107"
                html_report += f"<li style='margin-bottom: 15px;'>"
                html_report += f"<b style='color: {color};'>[{finding['severity']}] {finding['label']}</b> (Found {finding['count']} times)<br>"
                html_report += f"<i>Sample: {finding.get('sample', 'N/A')}</i><br>"
                html_report += f"<span style='color: #ccc;'><b>Risk:</b> {finding['desc']}</span>"
                html_report += f"</li>"
        html_report += "</ul>"
        
        self.text_area.setHtml(html_report)
        layout.addWidget(self.text_area)
        
        btn_close = QPushButton("Close Report")
        btn_close.setObjectName("BtnSecondary")
        btn_close.setMinimumHeight(35)
        btn_close.clicked.connect(self.accept)
        layout.addWidget(btn_close)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QColor, QBrush

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from google_auth import OAuthCallbackHandler
from cloud_logic import CloudStorageScanner

class GoogleDriveAuthWorker(QThread):
    auth_success = pyqtSignal(str) # access_token
    auth_error = pyqtSignal(str)

    def __init__(self, client_id, client_secret):
        super().__init__()
        self.client_id = client_id
        self.client_secret = client_secret
        self.redirect_port = 0
        self.redirect_uri = ""

    def run(self):
        try:
            server = HTTPServer(('127.0.0.1', 0), OAuthCallbackHandler)
            self.redirect_port = server.server_port
            self.redirect_uri = f"http://127.0.0.1:{self.redirect_port}/callback"
            server.auth_code = None
            server.auth_error = None

            auth_url = (
                f"https://accounts.google.com/o/oauth2/auth?"
                f"response_type=code&client_id={self.client_id}&"
                f"redirect_uri={self.redirect_uri}&"
                f"scope=https://www.googleapis.com/auth/drive.readonly"
            )

            webbrowser.open(auth_url)

            server.timeout = 1.0  # 1 second timeout
            timeout_counter = 0
            max_timeout = 90  # Wait up to 90 seconds

            while not server.auth_code and not server.auth_error and timeout_counter < max_timeout:
                server.handle_request()
                timeout_counter += 1

            if not server.auth_code and not server.auth_error:
                self.auth_error.emit("Authentication timed out or was cancelled by closing the browser.")
                server.server_close()
                return

            if server.auth_error:
                self.auth_error.emit(f"Authentication Error: {server.auth_error}")
                server.server_close()
                return

            token_data = {
                'code': server.auth_code,
                'client_id': self.client_id,
                'client_secret': self.client_secret,
                'redirect_uri': self.redirect_uri,
                'grant_type': 'authorization_code'
            }
            
            response = requests.post("https://oauth2.googleapis.com/token", data=token_data)
            tokens = response.json()

            if 'access_token' in tokens:
                self.auth_success.emit(tokens['access_token'])
            else:
                self.auth_error.emit(f"Failed to retrieve access token: {tokens.get('error', 'Unknown error')}")

            server.server_close()

        except Exception as e:
            self.auth_error.emit(f"Authentication Error: {str(e)}")


class CloudStorageScannerWorker(QThread):
    progress_update = pyqtSignal(int, int, str) # current, total, filename
    scan_complete = pyqtSignal(list) # list of result dicts
    scan_error = pyqtSignal(str)

    def __init__(self, access_token):
        super().__init__()
        self.scanner = CloudStorageScanner(access_token)
        
    def run(self):
        files = self.scanner.list_files(limit=30)
        
        if isinstance(files, str): # Error message
            self.scan_error.emit(files)
            return
            
        results = []
        total = len(files)
        
        for idx, f in enumerate(files):
            self.progress_update.emit(idx + 1, total, f.get('name', 'Unknown'))
            
            # Scan file
            scan_result = self.scanner.download_and_scan(f)
            
            status = scan_result.get('status', 'error')
            findings = ", ".join(scan_result.get('findings', [])) if scan_result.get('findings') else "None"
            if status == "flagged":
                findings += " (Double-click for details)"
                
            results.append({
                'id': f.get('id', ''),
                'name': f.get('name', 'Unknown'),
                'mimeType': f.get('mimeType', 'Unknown'),
                'size': f.get('size', 'N/A'),
                'status': status,
                'findings': findings,
                'raw_findings': scan_result.get('raw_findings', [])
            })
            
        self.scan_complete.emit(results)


class CloudSecurityWidget(QWidget):
    def __init__(self, session_manager=None):
        super().__init__()
        self.session = session_manager
        self.access_token = self.session.auth_token if self.session and self.session.auth_type == "google" else None
        self.client_id = None
        self.client_secret = None
        
        # Load client secret
        current_dir = os.path.dirname(os.path.abspath(__file__))
        project_root = os.path.dirname(os.path.dirname(current_dir))
        secret_path = os.path.join(project_root, "client_secret.json")
        
        if os.path.exists(secret_path):
            with open(secret_path, 'r') as f:
                data = json.load(f)
                creds = data.get('installed') or data.get('web') or {}
                self.client_id = creds.get('client_id')
                self.client_secret = creds.get('client_secret')

        self.init_ui()

    def init_ui(self):
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(20, 20, 20, 20)
        main_layout.setSpacing(20)
        
        # --- TITLE ---
        header_layout = QVBoxLayout()
        title_row = QHBoxLayout()
        
        title_label = QLabel("☁️ Cloud Access Security Broker (CASB) for Google Drive")
        title_label.setObjectName("PageTitle")
        title_label.setStyleSheet("font-size: 24px; font-weight: bold; color: #0078d7;")
        
        self.lbl_status = QLabel("Status: Not Connected")
        self.lbl_status.setStyleSheet("color: #dc3545; font-size: 14px; font-weight: bold;")
        
        title_row.addWidget(title_label)
        title_row.addStretch()
        title_row.addWidget(self.lbl_status)
        
        subtitle_label = QLabel("Enterprise-grade Posture Management, Threat Intelligence, and Context-Aware Data Loss Prevention.")
        subtitle_label.setStyleSheet("font-size: 14px; color: #aaa; margin-bottom: 10px;")
        
        header_layout.addLayout(title_row)
        header_layout.addWidget(subtitle_label)
        main_layout.addLayout(header_layout)
        
        # --- DASHBOARD ---
        self.dashboard_layout = QHBoxLayout()
        self.lbl_stat_exposure = self._create_stat_card("Active Public Shares", "0", "#ffc107")
        self.lbl_stat_dlp = self._create_stat_card("Sensitive Data Leaks", "0", "#dc3545")
        self.lbl_stat_malware = self._create_stat_card("Malware IoCs", "0", "#dc3545")
        self.lbl_stat_vaulted = self._create_stat_card("Vaulted Assets", "0", "#28a745")
        
        self.dashboard_layout.addWidget(self.lbl_stat_exposure)
        self.dashboard_layout.addWidget(self.lbl_stat_dlp)
        self.dashboard_layout.addWidget(self.lbl_stat_malware)
        self.dashboard_layout.addWidget(self.lbl_stat_vaulted)
        main_layout.addLayout(self.dashboard_layout)
        
        # --- ACTIONS ---
        action_bar = QHBoxLayout()
        
        self.btn_auth = QPushButton("🔑 Connect Google Drive")
        self.btn_auth.setObjectName("BtnPrimary")
        self.btn_auth.setMinimumHeight(40)
        self.btn_auth.clicked.connect(self.start_auth)
        self.btn_auth.setVisible(False) # Replaced by global login
        
        self.btn_disconnect = QPushButton("❌ Clear View")
        self.btn_disconnect.setObjectName("BtnDanger")
        self.btn_disconnect.setMinimumHeight(40)
        self.btn_disconnect.clicked.connect(self.disconnect_drive)
        
        self.btn_scan = QPushButton("🔄 Refresh & Scan Drive Files")
        self.btn_scan.setObjectName("BtnPrimary")
        self.btn_scan.setMinimumHeight(40)
        self.btn_scan.clicked.connect(self.start_scan)
        
        self.btn_export_csv = QPushButton("📄 CSV")
        self.btn_export_csv.setObjectName("BtnSecondary")
        self.btn_export_csv.clicked.connect(self.export_csv)
        
        self.btn_export_pdf = QPushButton("📑 PDF")
        self.btn_export_pdf.setObjectName("BtnSecondary")
        self.btn_export_pdf.clicked.connect(self.export_pdf)
        
        if not self.session or self.session.auth_type != "google":
            self.lbl_status.setText("Status: Requires Google Sign-In")
            self.btn_scan.setEnabled(False)
            self.btn_disconnect.setEnabled(False)
            self.btn_export_csv.setEnabled(False)
            self.btn_export_pdf.setEnabled(False)
        else:
            self.lbl_status.setText("Status: Connected via Login 🟢")
            self.lbl_status.setStyleSheet("color: #28a745; font-size: 14px; font-weight: bold;")
            self.btn_scan.setEnabled(True)
            self.btn_disconnect.setEnabled(True)
            self.btn_export_csv.setEnabled(True)
            self.btn_export_pdf.setEnabled(True)
            
        action_bar.addWidget(self.btn_auth)
        action_bar.addWidget(self.btn_disconnect)
        action_bar.addWidget(self.btn_scan)
        action_bar.addWidget(self.btn_export_csv)
        action_bar.addWidget(self.btn_export_pdf)
        action_bar.addStretch()
        
        self.prog_bar = QProgressBar()
        self.prog_bar.setMinimumWidth(300)
        self.prog_bar.setVisible(False)
        action_bar.addWidget(self.prog_bar)
        
        main_layout.addLayout(action_bar)
        
        # --- TABLE ---
        self.table = QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels(["File Name", "Type", "Status", "Findings"])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setAlternatingRowColors(True)
        self.table.itemDoubleClicked.connect(self.show_report)
        self.table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self.show_context_menu)
        main_layout.addWidget(self.table)

    def show_context_menu(self, pos):
        menu = QMenu(self)
        menu.setStyleSheet("QMenu { background-color: #2b2b2b; color: white; border: 1px solid #444; } QMenu::item:selected { background-color: #0078d7; }")
        view_action = QAction("View Full Report", self)
        view_action.triggered.connect(lambda: self.show_report(self.table.currentItem()))
        menu.addAction(view_action)
        menu.exec(self.table.viewport().mapToGlobal(pos))

    def export_csv(self):
        import csv
        import io
        try:
            output = io.StringIO()
            writer = csv.writer(output)
            writer.writerow(["File Name", "Type", "Status", "Findings"])
            for r in range(self.table.rowCount()):
                writer.writerow([
                    self.table.item(r, 0).text() if self.table.item(r, 0) else "",
                    self.table.item(r, 1).text() if self.table.item(r, 1) else "",
                    self.table.item(r, 2).text() if self.table.item(r, 2) else "",
                    self.table.item(r, 3).text() if self.table.item(r, 3) else ""
                ])
                
            if self.session and hasattr(self.session, 'file_manager'):
                self.session.file_manager.export_file(
                    filename="cloud_scan_results.csv",
                    content=output.getvalue(),
                    module_source="Cloud CASB",
                    file_type="CSV",
                    tags="Warning"
                )
                QMessageBox.information(self, "Vaulted", "Cloud scan results CSV securely vaulted in FMS.")
            else:
                QMessageBox.warning(self, "Warning", "FMS not available.")
        except Exception as e:
            QMessageBox.critical(self, "Export Error", str(e))

    def export_pdf(self):
        import tempfile
        import os
        import datetime
        from PyQt6.QtPrintSupport import QPrinter
        from PyQt6.QtGui import QTextDocument
        try:
            temp_fd, temp_path = tempfile.mkstemp(suffix=".pdf")
            os.close(temp_fd)
            
            printer = QPrinter(QPrinter.PrinterMode.HighResolution)
            printer.setOutputFormat(QPrinter.OutputFormat.PdfFormat)
            printer.setOutputFileName(temp_path)
            
            html = f"""
            <html>
            <head>
                <style>
                    h1 {{ text-align: center; font-family: Arial, sans-serif; }}
                    table {{ border-collapse: collapse; width: 100%; font-family: Arial, sans-serif; font-size: 10pt; }}
                    th, td {{ border: 1px solid #333; padding: 4px; text-align: left; }}
                    th {{ background-color: #f2f2f2; font-weight: bold; }}
                </style>
            </head>
            <body>
                <h1>Cloud CASB Scan Report</h1>
                <p>Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                <table>
                    <thead>
                        <tr>
                            <th>File Name</th><th>Type</th><th>Status</th><th>Findings</th>
                        </tr>
                    </thead>
                    <tbody>
            """
            for r in range(self.table.rowCount()):
                n = self.table.item(r, 0).text() if self.table.item(r, 0) else ""
                t = self.table.item(r, 1).text() if self.table.item(r, 1) else ""
                s = self.table.item(r, 2).text() if self.table.item(r, 2) else ""
                fnd = self.table.item(r, 3).text() if self.table.item(r, 3) else ""
                html += f"<tr><td>{n}</td><td>{t}</td><td>{s}</td><td>{fnd}</td></tr>"
                
            html += "</tbody></table></body></html>"
            
            doc = QTextDocument()
            doc.setHtml(html)
            doc.print(printer)
            
            with open(temp_path, "rb") as f:
                pdf_bytes = f.read()
            os.remove(temp_path)
            
            if self.session and hasattr(self.session, 'file_manager'):
                self.session.file_manager.export_file(
                    filename="cloud_scan_results.pdf",
                    content=pdf_bytes,
                    module_source="Cloud CASB",
                    file_type="PDF",
                    tags="Warning"
                )
                QMessageBox.information(self, "Vaulted", "Cloud scan PDF securely vaulted in FMS.")
            else:
                QMessageBox.warning(self, "Warning", "FMS not available.")
        except Exception as e:
            QMessageBox.critical(self, "Export Error", str(e))

    def _create_stat_card(self, title, value, value_color):
        card = QFrame()
        card.setStyleSheet("background-color: #252526; border-radius: 8px; padding: 15px;")
        layout = QVBoxLayout(card)
        
        title_lbl = QLabel(title)
        title_lbl.setStyleSheet("color: #aaaaaa; font-size: 14px; font-weight: bold;")
        title_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        val_lbl = QLabel(value)
        val_lbl.setStyleSheet(f"color: {value_color}; font-size: 28px; font-weight: bold;")
        val_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        layout.addWidget(title_lbl)
        layout.addWidget(val_lbl)
        card.val_lbl = val_lbl
        return card
        
    def start_auth(self):
        if not self.client_id:
            QMessageBox.critical(self, "Error", "client_secret.json is missing or invalid.")
            return
            
        self.lbl_status.setText("Status: Authenticating...")
        self.lbl_status.setStyleSheet("color: #ffc107; font-size: 14px; font-weight: bold;")
        self.btn_auth.setEnabled(False)
        
        self.auth_worker = GoogleDriveAuthWorker(self.client_id, self.client_secret)
        self.auth_worker.auth_success.connect(self.on_auth_success)
        self.auth_worker.auth_error.connect(self.on_auth_error)
        self.auth_worker.start()
        
    def on_auth_success(self, token):
        self.access_token = token
        self.lbl_status.setText("Status: Connected 🟢")
        self.lbl_status.setStyleSheet("color: #28a745; font-size: 14px; font-weight: bold;")
        self.btn_auth.setEnabled(False)
        self.btn_auth.setText("✓ Connected")
        self.btn_disconnect.setEnabled(True)
        self.btn_scan.setEnabled(True)
        self.btn_scan.setObjectName("BtnPrimary")
        self.btn_scan.style().unpolish(self.btn_scan)
        self.btn_scan.style().polish(self.btn_scan)
        
    def disconnect_drive(self):
        self.table.setRowCount(0)
        self.lbl_stat_exposure.val_lbl.setText("0")
        self.lbl_stat_dlp.val_lbl.setText("0")
        self.lbl_stat_malware.val_lbl.setText("0")
        self.lbl_stat_vaulted.val_lbl.setText("0")
        
    def on_auth_error(self, msg):
        self.lbl_status.setText("Status: Not Connected")
        self.lbl_status.setStyleSheet("color: #dc3545; font-size: 14px; font-weight: bold;")
        self.btn_auth.setEnabled(True)
        QMessageBox.critical(self, "Auth Error", msg)
        
    def start_scan(self):
        self.table.setRowCount(0)
        self.btn_scan.setEnabled(False)
        self.prog_bar.setVisible(True)
        self.prog_bar.setValue(0)
        
        self.scan_worker = CloudStorageScannerWorker(self.access_token)
        self.scan_worker.progress_update.connect(self.on_scan_progress)
        self.scan_worker.scan_complete.connect(self.on_scan_complete)
        self.scan_worker.scan_error.connect(self.on_scan_error)
        self.scan_worker.start()
        
    def on_scan_progress(self, current, total, filename):
        self.prog_bar.setMaximum(total)
        self.prog_bar.setValue(current)
        self.prog_bar.setFormat(f"Scanning: {filename} (%p%)")
        
    def on_scan_complete(self, results):
        self.prog_bar.setVisible(False)
        self.btn_scan.setEnabled(True)
        
        stats_exposure = 0
        stats_dlp = 0
        stats_malware = 0
        
        self.table.setRowCount(len(results))
        for row, res in enumerate(results):
            raw_findings = res.get('raw_findings', [])
            for f in raw_findings:
                if f['label'] == 'Publicly Exposed File': stats_exposure += 1
                elif f['label'] == 'Known Malware (Threat Intel)': stats_malware += 1
                else: stats_dlp += 1

            # Name
            item_name = QTableWidgetItem(res['name'])
            item_name.setData(Qt.ItemDataRole.UserRole, res.get('id', ''))
            self.table.setItem(row, 0, item_name)
            
            # Type
            mtype = res['mimeType'].replace('application/vnd.google-apps.', 'G-')
            item_type = QTableWidgetItem(mtype)
            self.table.setItem(row, 1, item_type)
            
            # Status
            item_status = QTableWidgetItem(res['status'].upper())
            if res['status'] == 'flagged':
                item_status.setForeground(Qt.GlobalColor.red)
                item_status.setBackground(QBrush(QColor(60, 20, 20)))
            elif res['status'] == 'clean':
                item_status.setForeground(Qt.GlobalColor.green)
            elif res['status'] == 'skipped':
                item_status.setForeground(Qt.GlobalColor.gray)
            self.table.setItem(row, 2, item_status)
            
            # Findings
            item_findings = QTableWidgetItem(res['findings'])
            item_findings.setData(Qt.ItemDataRole.UserRole, res.get('raw_findings', []))
            self.table.setItem(row, 3, item_findings)
            
        # Update Dashboard
        self.lbl_stat_exposure.val_lbl.setText(str(stats_exposure))
        self.lbl_stat_dlp.val_lbl.setText(str(stats_dlp))
        self.lbl_stat_malware.val_lbl.setText(str(stats_malware))
            
    def show_report(self, item):
        row = item.row()
        findings_item = self.table.item(row, 3)
        name_item = self.table.item(row, 0)
        
        raw_findings = findings_item.data(Qt.ItemDataRole.UserRole)
        if not raw_findings:
            return
            
        dlg = DLPReportDialog(name_item.text(), raw_findings, self)
        dlg.exec()
            
    def on_scan_error(self, msg):
        self.prog_bar.setVisible(False)
        self.btn_scan.setEnabled(True)
        QMessageBox.critical(self, "Scan Error", msg)

    def show_context_menu(self, pos):
        item = self.table.itemAt(pos)
        if not item:
            return
            
        row = item.row()
        name_item = self.table.item(row, 0)
        file_id = name_item.data(Qt.ItemDataRole.UserRole)
        file_name = name_item.text()
        
        if not file_id:
            return
            
        menu = QMenu(self)
        
        action_revoke = QAction("🛡️ Enforce Zero-Trust (Revoke Public Access)", self)
        action_vault = QAction("🔒 Cryptographic Vault (Quarantine & Delete from Cloud)", self)
        
        action_revoke.triggered.connect(lambda checked, fid=file_id, fname=file_name: self.execute_remediation('revoke', fid, fname))
        action_vault.triggered.connect(lambda checked, fid=file_id, fname=file_name: self.execute_remediation('vault', fid, fname))
        
        menu.addAction(action_revoke)
        menu.addAction(action_vault)
        menu.exec(self.table.viewport().mapToGlobal(pos))
        
    def execute_remediation(self, action_type, file_id, file_name):
        if not self.access_token: return
        scanner = CloudStorageScanner(self.access_token)
        
        try:
            if action_type == 'revoke':
                scanner.revoke_public_access(file_id)
                QMessageBox.information(self, "Remediation Successful", f"Zero-Trust Policy Enforced.\n\nPublic access has been completely revoked for '{file_name}'.")
            elif action_type == 'vault':
                vault_path = scanner.vault_file(file_id, file_name)
                QMessageBox.information(self, "Asset Vaulted", f"Asset successfully quarantined.\n\n'{file_name}' was encrypted and stored safely at:\n{vault_path}\n\nThe original asset has been permanently deleted from Google Drive.")
                
                # Increment vaulted stats
                current_vaulted = int(self.lbl_stat_vaulted.val_lbl.text())
                self.lbl_stat_vaulted.val_lbl.setText(str(current_vaulted + 1))
                
            self.start_scan() # Refresh table
        except Exception as e:
            QMessageBox.critical(self, "Remediation Failed", f"An error occurred during automated remediation:\n{str(e)}")
