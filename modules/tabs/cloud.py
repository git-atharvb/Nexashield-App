"""
NexaShield - Enterprise Cloud Access Security Broker (CASB) & CSPM Suite
Features:
- Dual View Architecture: Security Audit & Compliance Matrix <--> Interactive Cloud Storage Explorer
- In-System Cloud Document Previewer & Inspector with inline DLP leak highlighting
- Multi-Vector Context-Aware DLP (Credit Cards, SSNs, AWS/GCP/GitHub Keys, DB URIs, Private Keys)
- Zero-Trust Automated Remediation (Public link revocation & Cryptographic Vault quarantine)
- Dual-Mode Engine: Seamless Live Google Drive OAuth2 + Built-in Virtual Cloud Sandbox
- 440px Slide-out Asset Forensic Dossier Drawer, Telemetry Donut Chart, and Metric Ribbon
"""

import os
import sys
import json
import math
import tempfile
import webbrowser
import requests
import datetime
import html
import csv
import io
from http.server import HTTPServer
from collections import deque

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QTableWidget,
    QTableWidgetItem, QHeaderView, QAbstractItemView, QMessageBox, QFrame,
    QProgressBar, QDialog, QTextEdit, QMenu, QLineEdit, QComboBox,
    QSplitter, QTreeWidget, QTreeWidgetItem, QStackedWidget, QSizePolicy,
    QApplication, QToolTip, QTabWidget, QFileDialog
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QRectF, QEvent
from PyQt6.QtGui import (
    QColor, QBrush, QPainter, QPainterPath, QLinearGradient,
    QPen, QFont, QPalette, QAction
)

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from google_auth import OAuthCallbackHandler
from cloud_logic import CloudStorageScanner, VIRTUAL_CLOUD_FOLDERS, VIRTUAL_CLOUD_FILES
from database import DatabaseManager


# ==========================================================
# Telemetry Metric Tile (InfoCard)
# ==========================================================
class InfoCard(QFrame):
    """High-density styled telemetry tile for metric summary ribbon."""
    def __init__(self, title, value="-", icon="ℹ️", color=None):
        super().__init__()
        self.setObjectName("InfoCard")
        self.setMinimumHeight(56)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 6, 12, 6)
        layout.setSpacing(2)

        header = QHBoxLayout()
        header.setSpacing(5)
        lbl_icon = QLabel(icon)
        lbl_icon.setStyleSheet("font-size: 11px; background: transparent;")
        lbl_title = QLabel(title)
        lbl_title.setStyleSheet("font-size: 9px; font-weight: 700; color: #94a3b8; text-transform: uppercase; letter-spacing: 0.3px; background: transparent;")
        header.addWidget(lbl_icon)
        header.addWidget(lbl_title)
        header.addStretch()
        layout.addLayout(header)

        self.lbl_value = QLabel(value)
        val_color = color if color else "#f8fafc"
        self.lbl_value.setStyleSheet(f"font-size: 13px; font-weight: 800; color: {val_color}; background: transparent;")
        self.lbl_value.setWordWrap(False)
        layout.addWidget(self.lbl_value)

    def set_value(self, value):
        self.lbl_value.setText(str(value))


# ==========================================================
# Telemetry Chart: Cloud Security Donut Chart
# ==========================================================
class CloudThreatDonutChart(QWidget):
    """Modern glassmorphic donut chart for cloud asset posture distribution."""
    filter_requested = pyqtSignal(str)

    def __init__(self):
        super().__init__()
        self.setMinimumSize(160, 130)
        self.stats = {"Clean": 0, "Public Exposed": 0, "DLP Leak": 0, "Malware / IoC": 0}
        self.colors = {
            "Clean": QColor("#10b981"),           # Emerald
            "Public Exposed": QColor("#f59e0b"),  # Amber
            "DLP Leak": QColor("#ef4444"),        # Red
            "Malware / IoC": QColor("#dc2626")    # Dark Red
        }

    def update_stats(self, clean: int, exposed: int, dlp: int, malware: int):
        self.stats["Clean"] = clean
        self.stats["Public Exposed"] = exposed
        self.stats["DLP Leak"] = dlp
        self.stats["Malware / IoC"] = malware
        self.update()

    def reset(self):
        self.stats = {"Clean": 0, "Public Exposed": 0, "DLP Leak": 0, "Malware / IoC": 0}
        self.update()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        w, h = self.width(), self.height()
        is_dark = self.palette().color(QPalette.ColorRole.Window).lightness() < 128
        bg_col = QColor("#111726") if is_dark else QColor("#ffffff")
        bdr_col = QColor("#1e293b") if is_dark else QColor("#e2e8f0")
        text_col = self.palette().color(QPalette.ColorRole.WindowText)

        painter.fillRect(0, 0, w, h, bg_col)
        painter.setPen(QPen(bdr_col, 1))
        painter.drawRect(0, 0, w - 1, h - 1)

        # Title
        painter.setPen(text_col)
        painter.setFont(QFont("Segoe UI", 9, QFont.Weight.Bold))
        painter.drawText(10, 18, "☁️ Cloud Security Posture")

        chart_size = min(w - 20, h - 35)
        rect = QRectF((w - chart_size) / 2, 26, chart_size, chart_size)
        total = sum(self.stats.values())

        if total == 0:
            painter.setBrush(QColor(100, 116, 139, 40))
            painter.setPen(Qt.PenStyle.NoPen)
            painter.drawEllipse(rect)
        else:
            start_angle = 90 * 16
            for label, count in self.stats.items():
                if count > 0:
                    span = int((count / total) * 360 * 16)
                    painter.setBrush(self.colors.get(label, QColor("#64748b")))
                    painter.setPen(Qt.PenStyle.NoPen)
                    painter.drawPie(rect, start_angle, span)
                    start_angle += span

        # Center Hole
        inner_size = chart_size * 0.65
        inner_rect = QRectF((w - inner_size) / 2, 26 + (chart_size - inner_size) / 2, inner_size, inner_size)
        painter.setBrush(bg_col)
        painter.setPen(Qt.PenStyle.NoPen)
        painter.drawEllipse(inner_rect)

        # Center Text
        painter.setPen(text_col)
        painter.setFont(QFont("Segoe UI", 10, QFont.Weight.Bold))
        painter.drawText(inner_rect, Qt.AlignmentFlag.AlignCenter, f"{total}\nAssets")

    def mouseMoveEvent(self, event):
        total = sum(self.stats.values())
        if total == 0:
            return super().mouseMoveEvent(event)

        pos = event.pos()
        w, h = self.width(), self.height()
        chart_size = min(w - 20, h - 35)
        rect = QRectF((w - chart_size) / 2, 26, chart_size, chart_size)
        dx = pos.x() - rect.center().x()
        dy = pos.y() - rect.center().y()
        dist = math.hypot(dx, dy)

        if (chart_size * 0.65) / 2 <= dist <= chart_size / 2:
            angle = math.degrees(math.atan2(-dy, dx))
            if angle < 0:
                angle += 360
            mapped = (angle - 90) % 360

            cur = 0
            for label, count in self.stats.items():
                if count > 0:
                    span = (count / total) * 360
                    if cur <= mapped <= cur + span:
                        QToolTip.showText(
                            event.globalPosition().toPoint(),
                            f"Posture: {label}\nAssets: {count}\nShare: {(count/total)*100:.1f}%",
                            self
                        )
                        return
                    cur += span
        QToolTip.hideText()
        super().mouseMoveEvent(event)


# ==========================================================
# Google Drive OAuth Background Worker Thread
# ==========================================================
class GoogleDriveAuthWorker(QThread):
    auth_success = pyqtSignal(str)
    auth_error = pyqtSignal(str)

    def __init__(self, client_id, client_secret):
        super().__init__()
        self.client_id = client_id
        self.client_secret = client_secret

    def run(self):
        try:
            server = HTTPServer(('127.0.0.1', 0), OAuthCallbackHandler)
            redirect_port = server.server_port
            redirect_uri = f"http://127.0.0.1:{redirect_port}/callback"
            server.auth_code = None
            server.auth_error = None

            auth_url = (
                f"https://accounts.google.com/o/oauth2/auth?"
                f"response_type=code&client_id={self.client_id}&"
                f"redirect_uri={redirect_uri}&"
                f"scope=https://www.googleapis.com/auth/drive.readonly%20https://www.googleapis.com/auth/drive"
            )

            webbrowser.open(auth_url)
            server.timeout = 1.0
            timeout_counter = 0

            while not server.auth_code and not server.auth_error and timeout_counter < 90:
                server.handle_request()
                timeout_counter += 1

            if not server.auth_code and not server.auth_error:
                self.auth_error.emit("Authentication timed out or browser was closed.")
                server.server_close()
                return

            if server.auth_error:
                self.auth_error.emit(f"OAuth Error: {server.auth_error}")
                server.server_close()
                return

            token_data = {
                'code': server.auth_code,
                'client_id': self.client_id,
                'client_secret': self.client_secret,
                'redirect_uri': redirect_uri,
                'grant_type': 'authorization_code'
            }

            resp = requests.post("https://oauth2.googleapis.com/token", data=token_data, timeout=10)
            tokens = resp.json()

            if 'access_token' in tokens:
                self.auth_success.emit(tokens['access_token'])
            else:
                self.auth_error.emit(f"Failed to obtain access token: {tokens.get('error_description', 'Unknown error')}")

            server.server_close()
        except Exception as e:
            self.auth_error.emit(f"Authentication exception: {str(e)}")


# ==========================================================
# Cloud Deep Scanner Background Worker Thread
# ==========================================================
class CloudStorageScannerWorker(QThread):
    progress_update = pyqtSignal(int, int, str)
    scan_complete = pyqtSignal(list)
    scan_error = pyqtSignal(str)

    def __init__(self, scanner: CloudStorageScanner):
        super().__init__()
        self.scanner = scanner

    def run(self):
        try:
            files = self.scanner.list_files(limit=60)
            if isinstance(files, str):
                self.scan_error.emit(files)
                return

            results = []
            total = len(files)

            for idx, f in enumerate(files):
                self.progress_update.emit(idx + 1, total, f.get('name', 'Unknown'))
                scan_res = self.scanner.download_and_scan(f)

                status = scan_res.get('status', 'clean')
                findings_list = scan_res.get('findings', [])
                findings_str = ", ".join(findings_list) if findings_list else "Clean (No Violations)"

                results.append({
                    'id': f.get('id', ''),
                    'name': f.get('name', 'Unknown'),
                    'mimeType': f.get('mimeType', 'Unknown'),
                    'size': f.get('size', 'N/A'),
                    'shared': f.get('shared', False),
                    'permissions': f.get('permissions', []),
                    'is_folder': f.get('is_folder', False),
                    'status': status,
                    'score': scan_res.get('score', 0),
                    'findings': findings_str,
                    'raw_findings': scan_res.get('raw_findings', []),
                    'content_preview': scan_res.get('content_preview', '')
                })

            self.scan_complete.emit(results)
        except Exception as e:
            self.scan_error.emit(str(e))


# ==========================================================
# Main Enterprise Cloud Security Widget
# ==========================================================
class CloudSecurityWidget(QWidget):
    """
    Enterprise CASB / CSPM Suite featuring:
    - Dual Operational Modes: Security Audit Matrix <--> Interactive Cloud Storage Explorer
    - In-System Cloud Document Previewer with inline DLP leak highlighting
    - Multi-Vector DLP & Posture Engine (Credit Cards, SSNs, API/Private Keys, Zero-Trust Permissions)
    - Zero-Trust Automated Remediation (Public link revocation & Cryptographic Vault quarantine)
    - Dual Engine: Live Google Drive OAuth2 + Built-in Virtual Cloud Sandbox
    """
    def __init__(self, session_manager=None):
        super().__init__()
        self.session = session_manager
        self.setObjectName("CloudSecurity")

        # Database Setup
        db_path = self.session.get_db_path() if self.session and hasattr(self.session, "get_db_path") else "nexashield.db"
        self.db = DatabaseManager(db_name=db_path)

        # Connection / Engine State
        self.access_token = self.session.auth_token if self.session and self.session.auth_type == "google" else None
        self.is_sandbox = (not self.access_token)
        self.scanner = CloudStorageScanner(access_token=self.access_token, sandbox_mode=self.is_sandbox)

        # Loaded Scan Results
        self.scan_results = []
        self.current_dossier_asset = None
        self.vaulted_count = 0

        # OAuth Client Credentials
        self.client_id = None
        self.client_secret = None
        self._load_client_secret()

        self.setup_ui()
        self.load_initial_data()

    def _load_client_secret(self):
        """Loads client_secret.json if present."""
        try:
            curr_dir = os.path.dirname(os.path.abspath(__file__))
            proj_root = os.path.dirname(os.path.dirname(curr_dir))
            sec_path = os.path.join(proj_root, "client_secret.json")
            if os.path.exists(sec_path):
                with open(sec_path, 'r') as f:
                    data = json.load(f)
                    creds = data.get('installed') or data.get('web') or {}
                    self.client_id = creds.get('client_id')
                    self.client_secret = creds.get('client_secret')
        except Exception:
            pass

    def is_dark_mode(self) -> bool:
        """Determines active dark/light mode reliably."""
        win = self.window()
        if win and win is not self and hasattr(win, "is_dark_mode"):
            val = getattr(win, "is_dark_mode")
            if isinstance(val, bool):
                return val
            elif callable(val):
                return bool(val())
        app = QApplication.instance()
        if app:
            for top_w in app.topLevelWidgets():
                if top_w is not self and hasattr(top_w, "is_dark_mode"):
                    val = getattr(top_w, "is_dark_mode")
                    if isinstance(val, bool):
                        return val
                    elif callable(val):
                        return bool(val())
        return self.palette().color(QPalette.ColorRole.Window).lightness() < 128

    def changeEvent(self, event):
        """Re-renders UI elements on theme change."""
        super().changeEvent(event)
        if event.type() in (QEvent.Type.PaletteChange, QEvent.Type.StyleChange):
            self.chart_donut.update()
            if self.dossier_panel.isVisible() and self.current_dossier_asset:
                self.txt_dossier_report.setHtml(self.generate_dossier_html(self.current_dossier_asset))
                self.render_file_preview(self.current_dossier_asset)

    def setup_ui(self):
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(15, 12, 15, 12)
        main_layout.setSpacing(10)

        # ==========================================================
        # 1. TOP TOOLBAR (2-Row Spacious Control Panel)
        # ==========================================================
        self.toolbar = QFrame()
        self.toolbar.setObjectName("ProcessToolbar")
        self.toolbar.setMinimumHeight(84)
        toolbar_layout = QVBoxLayout(self.toolbar)
        toolbar_layout.setContentsMargins(12, 8, 12, 8)
        toolbar_layout.setSpacing(8)

        # ----------------- ROW 1: Mode Switcher & Cloud Connection -----------------
        row1 = QHBoxLayout()
        row1.setSpacing(8)

        # Mode Toggle Buttons (Audit View vs Storage Explorer)
        self.btn_mode_audit = QPushButton("🛡️ CASB Security Audit")
        self.btn_mode_audit.setObjectName("BtnPrimary")
        self.btn_mode_audit.setFixedHeight(32)
        self.btn_mode_audit.setCheckable(True)
        self.btn_mode_audit.setChecked(True)
        self.btn_mode_audit.clicked.connect(lambda: self.switch_view(0))
        row1.addWidget(self.btn_mode_audit)

        self.btn_mode_explorer = QPushButton("📂 Cloud Storage Explorer")
        self.btn_mode_explorer.setObjectName("BtnSecondary")
        self.btn_mode_explorer.setFixedHeight(32)
        self.btn_mode_explorer.setCheckable(True)
        self.btn_mode_explorer.setChecked(False)
        self.btn_mode_explorer.clicked.connect(lambda: self.switch_view(1))
        row1.addWidget(self.btn_mode_explorer)

        # Connection Buttons
        self.btn_connect_gdrive = QPushButton("🔑 Connect Google Drive")
        self.btn_connect_gdrive.setFixedHeight(32)
        self.btn_connect_gdrive.clicked.connect(self.start_oauth_flow)
        row1.addWidget(self.btn_connect_gdrive)

        self.btn_load_sandbox = QPushButton("🧪 Cloud Sandbox (Offline)")
        self.btn_load_sandbox.setFixedHeight(32)
        self.btn_load_sandbox.clicked.connect(self.load_sandbox_mode)
        row1.addWidget(self.btn_load_sandbox)

        # Zero-Trust One-Click Bulk Remediation
        self.btn_bulk_revoke = QPushButton("⚡ Revoke All Public Shares")
        self.btn_bulk_revoke.setObjectName("BtnDanger")
        self.btn_bulk_revoke.setFixedHeight(32)
        self.btn_bulk_revoke.clicked.connect(self.execute_bulk_revocation)
        row1.addWidget(self.btn_bulk_revoke)

        row1.addStretch()

        # Connection Status Badge
        self.lbl_connection_badge = QLabel("🔵 Virtual Cloud Sandbox")
        self.lbl_connection_badge.setFixedHeight(32)
        self.lbl_connection_badge.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.lbl_connection_badge.setStyleSheet("font-weight: bold; font-size: 11px; color: #38bdf8; padding: 4px 10px; border-radius: 4px; background: rgba(56, 189, 248, 0.15);")
        row1.addWidget(self.lbl_connection_badge)

        toolbar_layout.addLayout(row1)

        # ----------------- ROW 2: Search, Filters & Scan Execution -----------------
        row2 = QHBoxLayout()
        row2.setSpacing(8)

        # Live Search
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Filter by filename, extension, or detected secret...")
        self.search_input.setClearButtonEnabled(True)
        self.search_input.setMinimumWidth(240)
        self.search_input.setFixedHeight(32)
        self.search_input.setStyleSheet("padding: 4px 10px; font-size: 11px;")
        self.search_input.textChanged.connect(self.apply_filters)
        row2.addWidget(self.search_input, 1)

        # Severity Filter Dropdown (Expanded width to prevent chevron clipping)
        self.filter_severity = QComboBox()
        self.filter_severity.setMinimumWidth(160)
        self.filter_severity.setFixedHeight(32)
        self.filter_severity.addItems(["All Severities", "Critical", "High", "Medium", "Clean"])
        self.filter_severity.currentTextChanged.connect(self.apply_filters)
        row2.addWidget(self.filter_severity)

        # Exposure Filter Dropdown (Expanded width to prevent chevron clipping)
        self.filter_exposure = QComboBox()
        self.filter_exposure.setMinimumWidth(160)
        self.filter_exposure.setFixedHeight(32)
        self.filter_exposure.addItems(["All Exposures", "Public Internet", "External Domain", "Private"])
        self.filter_exposure.currentTextChanged.connect(self.apply_filters)
        row2.addWidget(self.filter_exposure)

        # Action Buttons
        self.btn_scan = QPushButton("🔄 Run Deep Cloud Scan")
        self.btn_scan.setObjectName("BtnPrimary")
        self.btn_scan.setFixedHeight(32)
        self.btn_scan.setMinimumWidth(160)
        self.btn_scan.clicked.connect(self.start_deep_scan)
        row2.addWidget(self.btn_scan)

        self.btn_export_csv = QPushButton("💾 Export CSV")
        self.btn_export_csv.setFixedHeight(32)
        self.btn_export_csv.clicked.connect(self.export_csv)
        row2.addWidget(self.btn_export_csv)

        self.btn_export_pdf = QPushButton("📄 PDF Report")
        self.btn_export_pdf.setFixedHeight(32)
        self.btn_export_pdf.clicked.connect(self.export_pdf)
        row2.addWidget(self.btn_export_pdf)

        self.btn_clear = QPushButton("🗑️ Clear")
        self.btn_clear.setFixedHeight(32)
        self.btn_clear.clicked.connect(self.clear_view)
        row2.addWidget(self.btn_clear)

        toolbar_layout.addLayout(row2)
        main_layout.addWidget(self.toolbar)

        # Progress Bar (Hidden during idle)
        self.prog_bar = QProgressBar()
        self.prog_bar.setFixedHeight(14)
        self.prog_bar.setTextVisible(True)
        self.prog_bar.hide()
        main_layout.addWidget(self.prog_bar)

        # ==========================================================
        # 2. METRIC RIBBON (4 InfoCards)
        # ==========================================================
        metrics_layout = QHBoxLayout()
        metrics_layout.setSpacing(10)

        self.card_score = InfoCard("Posture Security Score", "100%", "🛡️", "#10b981")
        self.card_exposed = InfoCard("Public Internet Assets", "0", "🌐", "#f59e0b")
        self.card_dlp = InfoCard("Sensitive DLP Leaks", "0", "🚨", "#ef4444")
        self.card_vaulted = InfoCard("Quarantined Assets", "0", "🔒", "#38bdf8")

        metrics_layout.addWidget(self.card_score)
        metrics_layout.addWidget(self.card_exposed)
        metrics_layout.addWidget(self.card_dlp)
        metrics_layout.addWidget(self.card_vaulted)
        main_layout.addLayout(metrics_layout)

        # ==========================================================
        # 3. MAIN WORKSPACE (Dual-View Stack + 440px Forensic Drawer)
        # ==========================================================
        workspace_layout = QHBoxLayout()
        workspace_layout.setSpacing(10)

        left_container = QWidget()
        left_layout = QVBoxLayout(left_container)
        left_layout.setContentsMargins(0, 0, 0, 0)
        left_layout.setSpacing(10)

        # Telemetry Banner: Donut Chart + Storage Insight Card
        banner_layout = QHBoxLayout()
        banner_layout.setSpacing(10)

        self.chart_donut = CloudThreatDonutChart()
        banner_layout.addWidget(self.chart_donut, 1)

        self.card_insight = QFrame()
        self.card_insight.setObjectName("CardContainer")
        self.card_insight.setFixedHeight(130)
        card_insight_layout = QVBoxLayout(self.card_insight)
        card_insight_layout.setContentsMargins(12, 10, 12, 10)
        card_insight_layout.setSpacing(4)

        lbl_ins_title = QLabel("💡 Cloud Access & Storage Intelligence")
        lbl_ins_title.setStyleSheet("font-size: 11px; font-weight: bold; color: #38bdf8;")
        card_insight_layout.addWidget(lbl_ins_title)

        self.lbl_insight_text = QLabel(
            "<b>Zero-Trust Policy:</b> Public link sharing (`anyone with link`) bypasses all perimeter firewalls. "
            "Use the <i>Revoke Public Link</i> action to enforce least-privilege identity access.<br>"
            "<b>Contextual DLP:</b> All credit card findings are verified via Luhn checksum. High-risk AWS/GCP/SSH keys trigger immediate severity alerts."
        )
        self.lbl_insight_text.setWordWrap(True)
        self.lbl_insight_text.setStyleSheet("font-size: 10px; color: #94a3b8;")
        card_insight_layout.addWidget(self.lbl_insight_text)
        card_insight_layout.addStretch()

        banner_layout.addWidget(self.card_insight, 2)
        left_layout.addLayout(banner_layout)

        # View Stack: Index 0 = Audit Table, Index 1 = Cloud Storage Explorer
        self.view_stack = QStackedWidget()

        # --- VIEW 1: SECURITY AUDIT TABLE ---
        self.table_audit = QTableWidget()
        self.table_audit.setColumnCount(6)
        self.table_audit.setHorizontalHeaderLabels([
            "Asset Name", "MIME Type", "Size", "Sharing Posture", "Security Score", "DLP & Threat Findings"
        ])
        self.table_audit.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.table_audit.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self.table_audit.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self.table_audit.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        self.table_audit.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        self.table_audit.horizontalHeader().setSectionResizeMode(5, QHeaderView.ResizeMode.Stretch)
        self.table_audit.verticalHeader().setDefaultSectionSize(36)
        self.table_audit.verticalHeader().setVisible(False)
        self.table_audit.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table_audit.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table_audit.cellClicked.connect(self.on_audit_row_clicked)
        self.view_stack.addWidget(self.table_audit)

        # --- VIEW 2: EXCLUSIVE CLOUD STORAGE EXPLORER ---
        self.explorer_widget = QWidget()
        explorer_layout = QVBoxLayout(self.explorer_widget)
        explorer_layout.setContentsMargins(0, 0, 0, 0)
        explorer_layout.setSpacing(6)

        # Breadcrumbs bar
        self.lbl_breadcrumbs = QLabel("📂 My Drive")
        self.lbl_breadcrumbs.setStyleSheet("font-size: 11px; font-weight: bold; color: #38bdf8; padding: 4px 8px; background: rgba(56, 189, 248, 0.1); border-radius: 4px;")
        explorer_layout.addWidget(self.lbl_breadcrumbs)

        splitter = QSplitter(Qt.Orientation.Horizontal)

        # Folder Tree (Left)
        self.tree_folders = QTreeWidget()
        self.tree_folders.setHeaderLabel("Cloud Drive Directory Hierarchy")
        self.tree_folders.itemClicked.connect(self.on_folder_tree_clicked)
        splitter.addWidget(self.tree_folders)

        # File List (Right)
        self.table_files = QTableWidget()
        self.table_files.setColumnCount(4)
        self.table_files.setHorizontalHeaderLabels(["Name", "Type", "Size", "Sharing"])
        self.table_files.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.table_files.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self.table_files.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self.table_files.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        self.table_files.verticalHeader().setDefaultSectionSize(32)
        self.table_files.verticalHeader().setVisible(False)
        self.table_files.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table_files.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table_files.cellClicked.connect(self.on_explorer_row_clicked)
        splitter.addWidget(self.table_files)

        splitter.setSizes([220, 580])
        explorer_layout.addWidget(splitter)
        self.view_stack.addWidget(self.explorer_widget)

        left_layout.addWidget(self.view_stack, 1)
        workspace_layout.addWidget(left_container, 1)

        # ==========================================================
        # 4. RIGHT WING: 440px Slide-out Forensic Drawer & In-App Previewer
        # ==========================================================
        self.dossier_panel = QFrame()
        self.dossier_panel.setObjectName("PhishingDossier")
        self.dossier_panel.setFixedWidth(440)
        self.dossier_panel.hide()

        dossier_layout = QVBoxLayout(self.dossier_panel)
        dossier_layout.setContentsMargins(12, 12, 12, 12)
        dossier_layout.setSpacing(10)

        # Header
        d_header = QHBoxLayout()
        self.lbl_dossier_title = QLabel("🔬 Cloud Asset Intelligence Dossier")
        self.lbl_dossier_title.setStyleSheet("font-size: 13px; font-weight: 800; color: #38bdf8;")
        d_header.addWidget(self.lbl_dossier_title)
        d_header.addStretch()

        self.btn_close_dossier = QPushButton("✖")
        self.btn_close_dossier.setFixedSize(26, 26)
        self.btn_close_dossier.setStyleSheet("background: transparent; border: none; font-size: 13px; font-weight: bold; color: #94a3b8;")
        self.btn_close_dossier.clicked.connect(lambda: self.dossier_panel.hide())
        d_header.addWidget(self.btn_close_dossier)
        dossier_layout.addLayout(d_header)

        # Tab Widget: Tab 1 = Audit Report, Tab 2 = In-System Document Previewer
        self.dossier_tabs = QTabWidget()

        # Tab 1: Audit Report
        self.txt_dossier_report = QTextEdit()
        self.txt_dossier_report.setReadOnly(True)
        self.txt_dossier_report.setStyleSheet("border: none; background: transparent;")
        self.dossier_tabs.addTab(self.txt_dossier_report, "🛡️ Posture && DLP")

        # Tab 2: In-App Document Previewer (Direct Content Viewer with DLP Highlights)
        preview_container = QWidget()
        preview_layout = QVBoxLayout(preview_container)
        preview_layout.setContentsMargins(6, 6, 6, 6)
        preview_layout.setSpacing(6)

        self.lbl_pv_notice = QLabel("📄 In-System Document & Content Inspector:")
        self.lbl_pv_notice.setStyleSheet("font-size: 10px; font-weight: bold; color: #38bdf8;")
        preview_layout.addWidget(self.lbl_pv_notice)

        self.txt_file_preview = QTextEdit()
        self.txt_file_preview.setReadOnly(True)
        self.txt_file_preview.setStyleSheet("border: 1px solid rgba(148, 163, 184, 0.2); border-radius: 6px;")
        preview_layout.addWidget(self.txt_file_preview, 1)

        self.dossier_tabs.addTab(preview_container, "👁️ In-App Previewer")
        dossier_layout.addWidget(self.dossier_tabs, 1)

        # Zero-Trust Remediation Buttons
        d_actions = QHBoxLayout()
        d_actions.setSpacing(8)

        self.btn_action_revoke = QPushButton("🛡️ Revoke Public Link")
        self.btn_action_revoke.setObjectName("BtnWarning")
        self.btn_action_revoke.setFixedHeight(32)
        self.btn_action_revoke.clicked.connect(self.execute_single_revocation)
        d_actions.addWidget(self.btn_action_revoke)

        self.btn_action_vault = QPushButton("🔒 Quarantine & Vault")
        self.btn_action_vault.setObjectName("BtnDanger")
        self.btn_action_vault.setFixedHeight(32)
        self.btn_action_vault.clicked.connect(self.execute_single_vault)
        d_actions.addWidget(self.btn_action_vault)

        dossier_layout.addLayout(d_actions)
        workspace_layout.addWidget(self.dossier_panel)
        main_layout.addLayout(workspace_layout)

    def switch_view(self, index: int):
        """Switches between Security Audit View (0) and Storage Explorer (1)."""
        self.view_stack.setCurrentIndex(index)
        self.btn_mode_audit.setChecked(index == 0)
        self.btn_mode_explorer.setChecked(index == 1)

    def load_initial_data(self):
        """Populates the Virtual Cloud Sandbox by default for seamless exploration."""
        self.build_explorer_tree()
        self.start_deep_scan()

    def build_explorer_tree(self):
        """Populates directory tree for the Cloud Storage Explorer."""
        self.tree_folders.clear()
        root_item = QTreeWidgetItem(["📂 My Drive"])
        root_item.setData(0, Qt.ItemDataRole.UserRole, "root")
        self.tree_folders.addTopLevelItem(root_item)

        for fldr in VIRTUAL_CLOUD_FOLDERS:
            if fldr["id"] != "root":
                sub_item = QTreeWidgetItem([fldr["name"]])
                sub_item.setData(0, Qt.ItemDataRole.UserRole, fldr["id"])
                root_item.addChild(sub_item)

        self.tree_folders.expandAll()
        self.populate_explorer_files("root")

    def on_folder_tree_clicked(self, item, column):
        """Filters the file explorer list to the selected folder."""
        fldr_id = item.data(0, Qt.ItemDataRole.UserRole)
        self.lbl_breadcrumbs.setText(f"📂 {item.text(0)}")
        self.populate_explorer_files(fldr_id)

    def populate_explorer_files(self, folder_id: str):
        """Loads files inside the selected folder into the explorer view."""
        self.table_files.setRowCount(0)
        items = self.scanner.list_files(folder_id=folder_id)
        if isinstance(items, str):
            return

        files = [f for f in items if not f.get("is_folder")]
        self.table_files.setRowCount(len(files))

        for row, f in enumerate(files):
            # Name
            name_item = QTableWidgetItem(f.get("name", "Unknown"))
            name_item.setData(Qt.ItemDataRole.UserRole, f)
            self.table_files.setItem(row, 0, name_item)

            # Type
            mtype = f.get("mimeType", "").split("/")[-1].upper()
            self.table_files.setItem(row, 1, QTableWidgetItem(mtype))

            # Size
            size_val = f.get("size", "0")
            size_str = f"{int(size_val)/1024:.1f} KB" if str(size_val).isdigit() else str(size_val)
            self.table_files.setItem(row, 2, QTableWidgetItem(size_str))

            # Sharing
            shared = f.get("shared", False)
            sh_str = "🌐 Public Link" if any(p.get("type") == "anyone" for p in f.get("permissions", [])) else ("👥 Shared" if shared else "🔒 Private")
            self.table_files.setItem(row, 3, QTableWidgetItem(sh_str))

    def on_explorer_row_clicked(self, row: int, col: int):
        """Opens dossier preview directly from the storage explorer."""
        item = self.table_files.item(row, 0)
        if not item:
            return
        f_meta = item.data(Qt.ItemDataRole.UserRole)
        if f_meta:
            # Match with scanned asset or scan dynamically
            matched = next((a for a in self.scan_results if a.get("id") == f_meta.get("id")), None)
            if not matched:
                matched = self.scanner.download_and_scan(f_meta)
                matched["id"] = f_meta.get("id")
                matched["name"] = f_meta.get("name")
                matched["mimeType"] = f_meta.get("mimeType")
                matched["permissions"] = f_meta.get("permissions", [])
                matched["size"] = f_meta.get("size", "N/A")
            self.open_asset_dossier(matched)

    def load_sandbox_mode(self):
        """Switches to the offline Virtual Cloud Sandbox."""
        self.is_sandbox = True
        self.scanner = CloudStorageScanner(sandbox_mode=True)
        self.lbl_connection_badge.setText("🔵 Virtual Cloud Sandbox")
        self.lbl_connection_badge.setStyleSheet("font-weight: bold; font-size: 11px; color: #38bdf8; padding: 4px 10px; border-radius: 4px; background: rgba(56, 189, 248, 0.15);")
        self.build_explorer_tree()
        self.start_deep_scan()

    def start_oauth_flow(self):
        """Initiates OAuth2 authentication with Google Drive."""
        if not self.client_id:
            QMessageBox.warning(self, "Client Secret Missing", "client_secret.json was not found in the project root. Using Virtual Cloud Sandbox instead.")
            self.load_sandbox_mode()
            return

        self.btn_connect_gdrive.setEnabled(False)
        self.lbl_connection_badge.setText("🟡 Authenticating...")
        self.lbl_connection_badge.setStyleSheet("font-weight: bold; font-size: 11px; color: #f59e0b; padding: 4px 10px; border-radius: 4px; background: rgba(245, 158, 11, 0.15);")

        self.auth_worker = GoogleDriveAuthWorker(self.client_id, self.client_secret)
        self.auth_worker.auth_success.connect(self.on_oauth_success)
        self.auth_worker.auth_error.connect(self.on_oauth_error)
        self.auth_worker.start()

    def on_oauth_success(self, token: str):
        self.access_token = token
        self.is_sandbox = False
        self.scanner = CloudStorageScanner(access_token=token, sandbox_mode=False)
        self.btn_connect_gdrive.setEnabled(True)
        self.lbl_connection_badge.setText("🟢 Connected (Google Drive)")
        self.lbl_connection_badge.setStyleSheet("font-weight: bold; font-size: 11px; color: #10b981; padding: 4px 10px; border-radius: 4px; background: rgba(16, 185, 129, 0.15);")
        QMessageBox.information(self, "Google Drive Connected", "Live Google Drive connection established successfully.")
        self.start_deep_scan()

    def on_oauth_error(self, err_msg: str):
        self.btn_connect_gdrive.setEnabled(True)
        self.load_sandbox_mode()
        QMessageBox.warning(self, "OAuth Error", f"Google authentication failed:\n{err_msg}\n\nFalling back to Virtual Cloud Sandbox.")

    def start_deep_scan(self):
        """Runs background CASB / CSPM deep inspection."""
        self.btn_scan.setEnabled(False)
        self.prog_bar.show()
        self.prog_bar.setValue(0)

        self.worker = CloudStorageScannerWorker(self.scanner)
        self.worker.progress_update.connect(self.on_scan_progress)
        self.worker.scan_complete.connect(self.on_scan_finished)
        self.worker.scan_error.connect(self.on_scan_error)
        self.worker.start()

    def on_scan_progress(self, current: int, total: int, filename: str):
        self.prog_bar.setMaximum(total)
        self.prog_bar.setValue(current)
        self.prog_bar.setFormat(f"Analyzing: {filename} (%p%)")

    def on_scan_finished(self, results: list):
        self.prog_bar.hide()
        self.btn_scan.setEnabled(True)
        self.scan_results = results

        # Metric tallies
        total_files = len(results)
        exposed_count = 0
        dlp_count = 0
        malware_count = 0
        clean_count = 0

        for r in results:
            raw = r.get("raw_findings", [])
            has_exposed = any(f["label"] == "Public Internet Exposure" for f in raw)
            has_malware = any("Malware" in f["label"] or "Script" in f["label"] for f in raw)
            has_dlp = any(f["label"] not in ("Public Internet Exposure", "External Domain Share") and "Malware" not in f["label"] for f in raw)

            if has_exposed:
                exposed_count += 1
            if has_malware:
                malware_count += 1
            if has_dlp:
                dlp_count += 1
            if not raw:
                clean_count += 1

        # Posture Security Score Calculation (100 minus exposure and leak penalties)
        score_penalty = (exposed_count * 15) + (dlp_count * 20) + (malware_count * 25)
        posture_score = max(0, min(100, 100 - score_penalty))

        # Update metric cards
        score_col = "#10b981" if posture_score >= 80 else ("#f59e0b" if posture_score >= 50 else "#ef4444")
        self.card_score.set_value(f"{posture_score}%")
        self.card_score.lbl_value.setStyleSheet(f"font-size: 13px; font-weight: 800; color: {score_col}; background: transparent;")
        self.card_exposed.set_value(str(exposed_count))
        self.card_dlp.set_value(str(dlp_count))

        # Update Donut Chart
        self.chart_donut.update_stats(clean_count, exposed_count, dlp_count, malware_count)

        # Populate Audit Table
        self.populate_audit_table(results)

        # Persist to database
        try:
            self.db.save_cloud_scan(total_files, exposed_count, dlp_count, malware_count, posture_score)
            self.db.save_cloud_assets(results)
        except Exception:
            pass

    def on_scan_error(self, err: str):
        self.prog_bar.hide()
        self.btn_scan.setEnabled(True)
        QMessageBox.critical(self, "Scan Failed", f"Cloud scan failed:\n{err}")

    def populate_audit_table(self, assets: list):
        """Populates the primary CASB Security Audit table."""
        self.table_audit.setRowCount(len(assets))

        for row, a in enumerate(assets):
            raw = a.get("raw_findings", [])
            score = a.get("score", 0)

            # Name with icon
            name_item = QTableWidgetItem(a.get("name", "Unknown"))
            name_item.setData(Qt.ItemDataRole.UserRole, a)
            self.table_audit.setItem(row, 0, name_item)

            # MIME Type
            mtype = a.get("mimeType", "").split("/")[-1].upper()
            self.table_audit.setItem(row, 1, QTableWidgetItem(mtype))

            # Size
            size_val = a.get("size", "0")
            size_str = f"{int(size_val)/1024:.1f} KB" if str(size_val).isdigit() else str(size_val)
            self.table_audit.setItem(row, 2, QTableWidgetItem(size_str))

            # Sharing Posture
            has_public = any(f["label"] == "Public Internet Exposure" for f in raw)
            has_ext = any(f["label"] == "External Domain Share" for f in raw)
            if has_public:
                sh_item = QTableWidgetItem("🌐 Public Internet")
                sh_item.setForeground(QBrush(QColor("#ef4444")))
            elif has_ext:
                sh_item = QTableWidgetItem("👥 External Share")
                sh_item.setForeground(QBrush(QColor("#f59e0b")))
            else:
                sh_item = QTableWidgetItem("🔒 Private")
                sh_item.setForeground(QBrush(QColor("#10b981")))
            self.table_audit.setItem(row, 3, sh_item)

            # Security Threat Score
            score_item = QTableWidgetItem(f" {score} / 100 ")
            score_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            if score >= 75:
                score_item.setForeground(QBrush(QColor("#ef4444")))
            elif score >= 50:
                score_item.setForeground(QBrush(QColor("#f59e0b")))
            else:
                score_item.setForeground(QBrush(QColor("#10b981")))
            self.table_audit.setItem(row, 4, score_item)

            # DLP & Threat Findings
            find_item = QTableWidgetItem(a.get("findings", "None"))
            self.table_audit.setItem(row, 5, find_item)

    def on_audit_row_clicked(self, row: int, col: int):
        """Opens the forensic dossier and in-app file preview on row click."""
        name_item = self.table_audit.item(row, 0)
        if not name_item:
            return
        data = name_item.data(Qt.ItemDataRole.UserRole)
        if data:
            self.open_asset_dossier(data)

    def is_file_unsecure(self, asset: dict) -> tuple[bool, str]:
        """
        Determines whether a file is unsecure under NexaShield Zero-Trust rules.
        Returns (is_unsecure: bool, threat_summary: str).
        """
        raw = asset.get("raw_findings", [])
        score = asset.get("score", 0)
        name = asset.get("name", "").lower()
        mime = asset.get("mimeType", "").lower()

        # 1. Dangerous executable/script extensions
        dangerous_exts = (
            '.vbs', '.bat', '.cmd', '.exe', '.scr', '.dll', '.ps1',
            '.jar', '.hta', '.cpl', '.msi', '.com', '.pif', '.reg',
            '.wsf', '.vbe', '.jse', '.xlsm', '.docm'
        )
        for ext in dangerous_exts:
            if name.endswith(ext):
                return True, f"Dangerous Executable / Script Format ({ext})"

        # 2. Known dangerous payload MIME types
        dangerous_mimes = (
            'application/x-msdownload', 'application/x-msdos-program',
            'application/x-vbs', 'text/vbscript', 'application/x-bat',
            'application/x-sh', 'application/x-csh'
        )
        if any(dm in mime for dm in dangerous_mimes):
            return True, f"Restricted Payload MIME Type ({mime})"

        # 3. Active Threat Intelligence / Malware / Dropper findings
        for f in raw:
            sev = f.get("severity", "")
            lbl = f.get("label", "")
            if sev in ("Critical", "High"):
                if any(k in lbl.lower() for k in ("malware", "dropper", "phishing", "c2", "trojan", "exploit", "key", "password", "database")):
                    return True, f"{lbl} [{sev} Threat]"

        # 4. Elevated Threat Score
        if score >= 70:
            first_crit = next((f.get("label") for f in raw if f.get("severity") in ("Critical", "High")), "High-Risk Threat Assessment")
            return True, f"{first_crit} (Security Threat Score: {score}/100)"

        return False, ""

    def generate_blocked_preview_html(self, asset: dict, reason: str) -> str:
        """Renders explicit Zero-Trust access restriction warning for unsecure files."""
        is_dark = self.is_dark_mode()
        card_bg = "#1e131d" if is_dark else "#fef2f2"
        border_col = "#ef4444"
        text_title = "#f87171" if is_dark else "#dc2626"
        text_body = "#fca5a5" if is_dark else "#991b1b"
        sub_bg = "rgba(239, 68, 68, 0.15)" if is_dark else "rgba(239, 68, 68, 0.08)"

        score = asset.get('score', 0)
        findings = asset.get('raw_findings', [])
        findings_list = "".join(f"<li style='margin-bottom: 3px;'><b>{html.escape(f.get('label', 'Violation'))}</b> ({html.escape(f.get('severity', 'High'))}) - {html.escape(f.get('desc', ''))}</li>" for f in findings[:3])

        return f"""
        <div style="font-family: 'Segoe UI', sans-serif; padding: 14px; text-align: center;">
            <div style="background-color: {card_bg}; border: 2px solid {border_col}; border-radius: 8px; padding: 20px 16px;">
                <div style="font-size: 32px; margin-bottom: 6px;">🛑</div>
                <div style="font-size: 13px; font-weight: 800; color: {text_title}; letter-spacing: 0.5px; text-transform: uppercase;">
                    Content Preview Blocked: Zero-Trust Security Policy
                </div>
                <div style="font-size: 11px; font-weight: bold; color: {text_body}; margin-top: 8px;">
                    Access Restricted For: <span style="font-family: 'Consolas', monospace;">{html.escape(asset.get('name', 'Unknown'))}</span>
                </div>
                <div style="font-size: 11px; color: {text_body}; margin-top: 4px;">
                    Trigger: <b>{html.escape(reason)}</b> (Threat Score: <b>{score}/100</b>)
                </div>

                <div style="background-color: {sub_bg}; border-radius: 6px; padding: 10px; margin-top: 14px; text-align: left; font-size: 10px; color: {text_body};">
                    <b>Zero-Trust Isolation Notice:</b>
                    <p style="margin: 4px 0;">This file has been categorized as an unsecure or hostile risk asset. Direct rendering and execution are strictly disabled to prevent arbitrary code execution, credential exfiltration, or payload delivery.</p>
                    {"<ul style='margin: 4px 0; padding-left: 18px;'>" + findings_list + "</ul>" if findings_list else ""}
                </div>

                <div style="margin-top: 14px; font-size: 10px; color: #94a3b8;">
                    🛡️ To safely isolate and encrypt this file, use <b>🔒 Quarantine & Vault</b> below.
                </div>
            </div>
        </div>
        """

    def format_notebook_preview(self, content_str: str) -> str:
        """Parses Jupyter Notebook (.ipynb) JSON, renders cells, and strips heavy base64 images."""
        try:
            nb = json.loads(content_str)
            cells = nb.get("cells", [])
            if not cells:
                return "<div style='color: #94a3b8; font-style: italic; padding: 12px;'>Jupyter Notebook is empty (0 cells).</div>"

            is_dark = self.is_dark_mode()
            code_bg = "#0f172a" if is_dark else "#f1f5f9"
            code_color = "#38bdf8" if is_dark else "#0369a1"
            text_color = "#f8fafc" if is_dark else "#0f172a"
            out_color = "#94a3b8" if is_dark else "#475569"

            html_out = [
                f"<div style=\"font-family: 'Segoe UI', sans-serif; font-size: 11px; color: {text_color};\">",
                f"<div style=\"font-weight: bold; margin-bottom: 8px; color: #38bdf8;\">📓 Jupyter Notebook Inspector ({len(cells)} cells):</div>"
            ]

            for i, cell in enumerate(cells[:35]):
                cell_type = cell.get("cell_type", "code")
                raw_src = cell.get("source", "")
                src_text = "".join(raw_src) if isinstance(raw_src, list) else str(raw_src)
                esc_src = html.escape(src_text.strip())

                if cell_type == "markdown":
                    html_out.append(
                        f"<div style='margin-bottom: 8px; padding: 6px 10px; background: rgba(148, 163, 184, 0.1); border-left: 3px solid #38bdf8; border-radius: 4px;'>"
                        f"<div style='font-size: 9px; font-weight: bold; color: #94a3b8; text-transform: uppercase;'>📝 Markdown Cell [{i+1}]</div>"
                        f"<div style='margin-top: 4px; white-space: pre-wrap; font-size: 10px;'>{esc_src}</div>"
                        f"</div>"
                    )
                else:
                    exec_count = cell.get("execution_count", " ")
                    cell_html = (
                        f"<div style='margin-bottom: 10px; border: 1px solid rgba(148, 163, 184, 0.2); border-radius: 4px; overflow: hidden;'>"
                        f"<div style='background: {code_bg}; padding: 4px 8px; font-size: 9px; font-weight: bold; color: {code_color}; font-family: Consolas, monospace;'>"
                        f"▶ In [{exec_count if exec_count is not None else ' '}]:"
                        f"</div>"
                        f"<pre style='margin: 0; padding: 6px 8px; background: {code_bg}; font-family: Consolas, monospace; font-size: 10px; color: {text_color}; white-space: pre-wrap;'>{esc_src}</pre>"
                    )

                    outputs = cell.get("outputs", [])
                    if outputs:
                        cell_html += f"<div style='border-top: 1px dashed rgba(148, 163, 184, 0.2); padding: 4px 8px; font-size: 9px; background: rgba(0,0,0,0.15);'>"
                        for out in outputs:
                            out_type = out.get("output_type", "")
                            if "data" in out:
                                data_dict = out.get("data", {})
                                if "text/plain" in data_dict:
                                    tp = data_dict["text/plain"]
                                    tp_str = "".join(tp) if isinstance(tp, list) else str(tp)
                                    cell_html += f"<pre style='margin: 2px 0; font-family: Consolas, monospace; color: {out_color}; white-space: pre-wrap;'>{html.escape(tp_str[:500])}</pre>"
                                for mime in ("image/png", "image/jpeg", "image/svg+xml"):
                                    if mime in data_dict:
                                        img_data = data_dict[mime]
                                        img_len = len(img_data) if isinstance(img_data, str) else 0
                                        cell_html += (
                                            f"<div style='margin: 4px 0; padding: 3px 6px; background: rgba(56, 189, 248, 0.15); "
                                            f"border: 1px solid rgba(56, 189, 248, 0.3); border-radius: 4px; color: #38bdf8; font-weight: bold; font-size: 9px;'>"
                                            f"🖼️ [Rendered Visual Plot / Image: {mime} ({img_len/1024:.1f} KB base64 omitted)]"
                                            f"</div>"
                                        )
                            elif "text" in out:
                                t = out.get("text", "")
                                t_str = "".join(t) if isinstance(t, list) else str(t)
                                cell_html += f"<pre style='margin: 2px 0; font-family: Consolas, monospace; color: {out_color}; white-space: pre-wrap;'>{html.escape(t_str[:500])}</pre>"
                            elif out_type == "error":
                                ename = out.get("ename", "Error")
                                evalue = out.get("evalue", "")
                                cell_html += f"<div style='color: #ef4444; font-family: Consolas, monospace; font-size: 9px;'><b>{ename}:</b> {html.escape(evalue)}</div>"
                        cell_html += "</div>"

                    cell_html += "</div>"
                    html_out.append(cell_html)

            if len(cells) > 35:
                html_out.append(f"<div style='color: #f59e0b; margin-top: 8px; font-size: 9px;'><i>... [{len(cells) - 35} additional notebook cells truncated for display performance] ...</i></div>")

            html_out.append("</div>")
            return "".join(html_out)
        except Exception as e:
            return f"<pre style='font-family: Consolas, monospace; font-size: 10px;'>{html.escape(content_str[:4000])}</pre>"

    def format_csv_preview(self, content_str: str) -> str:
        """Parses CSV/TSV data and renders a clean, styled HTML table."""
        try:
            reader = csv.reader(io.StringIO(content_str))
            rows = list(reader)
            if not rows:
                return "<div style='color: #94a3b8; font-style: italic; padding: 12px;'>CSV file is empty.</div>"

            is_dark = self.is_dark_mode()
            header_bg = "#1e293b" if is_dark else "#e2e8f0"
            header_color = "#38bdf8" if is_dark else "#0369a1"
            row_alt = "rgba(255, 255, 255, 0.03)" if is_dark else "#f8fafc"
            text_color = "#f8fafc" if is_dark else "#0f172a"
            border_col = "rgba(148, 163, 184, 0.2)"

            html_out = [
                f"<div style=\"font-family: 'Segoe UI', sans-serif; font-size: 10px;\">",
                f"<div style=\"font-weight: bold; margin-bottom: 6px; color: #38bdf8;\">📊 Tabular Data Preview ({len(rows)} records):</div>",
                f"<table width=\"100%\" cellpadding=\"4\" cellspacing=\"0\" style=\"border-collapse: collapse; border: 1px solid {border_col}; color: {text_color};\">"
            ]

            headers = rows[0]
            html_out.append(f"<tr style='background-color: {header_bg}; font-weight: bold; color: {header_color};'>")
            for h in headers[:8]:
                html_out.append(f"<th style='padding: 6px; border: 1px solid {border_col}; text-align: left;'>{html.escape(h[:30])}</th>")
            if len(headers) > 8:
                html_out.append(f"<th style='padding: 6px; border: 1px solid {border_col};'>+{len(headers)-8} more</th>")
            html_out.append("</tr>")

            for r_idx, row in enumerate(rows[1:51]):
                bg = row_alt if r_idx % 2 == 1 else "transparent"
                html_out.append(f"<tr style='background-color: {bg};'>")
                for c_idx, cell in enumerate(row[:8]):
                    html_out.append(f"<td style='padding: 4px 6px; border: 1px solid {border_col};'>{html.escape(cell[:40])}</td>")
                if len(row) > 8:
                    html_out.append(f"<td style='padding: 4px 6px; border: 1px solid {border_col}; color: #94a3b8;'>...</td>")
                html_out.append("</tr>")

            html_out.append("</table>")
            if len(rows) > 51:
                html_out.append(f"<div style='color: #94a3b8; margin-top: 6px; font-size: 9px;'><i>Showing first 50 rows of {len(rows)} total records.</i></div>")
            html_out.append("</div>")
            return "".join(html_out)
        except Exception:
            return f"<pre style='font-family: Consolas, monospace; font-size: 10px;'>{html.escape(content_str[:4000])}</pre>"

    def format_json_preview(self, content_str: str) -> str:
        """Pretty-prints JSON data with large binary/base64 payload truncation."""
        try:
            obj = json.loads(content_str)

            def sanitize_val(v, depth=0):
                if depth > 10:
                    return "..."
                if isinstance(v, str) and len(v) > 150 and (' ' not in v):
                    return f"[Payload Data ({len(v)} bytes omitted)]"
                elif isinstance(v, dict):
                    return {k: sanitize_val(val, depth + 1) for k, val in list(v.items())[:50]}
                elif isinstance(v, list):
                    return [sanitize_val(item, depth + 1) for item in v[:50]]
                return v

            clean_obj = sanitize_val(obj)
            pretty = json.dumps(clean_obj, indent=2)
            if len(pretty) > 15000:
                pretty = pretty[:15000] + "\n\n... [JSON truncated for preview performance] ..."

            is_dark = self.is_dark_mode()
            color = "#e2e8f0" if is_dark else "#0f172a"
            return f"<div style='font-family: Consolas, monospace; font-size: 10px; color: {color}; white-space: pre-wrap;'>{html.escape(pretty)}</div>"
        except Exception:
            return f"<pre style='font-family: Consolas, monospace; font-size: 10px;'>{html.escape(content_str[:4000])}</pre>"

    def format_binary_metadata_preview(self, asset: dict) -> str:
        """Renders an asset metadata card for binary documents, archives, or images."""
        is_dark = self.is_dark_mode()
        card_bg = "#111726" if is_dark else "#f8fafc"
        card_border = "#1e293b" if is_dark else "#e2e8f0"
        text_color = "#f8fafc" if is_dark else "#0f172a"
        name = asset.get("name", "Asset")
        size = asset.get("size", "0")
        size_str = f"{int(size)/1024:.1f} KB" if str(size).isdigit() else str(size)
        mtype = asset.get("mimeType", "application/octet-stream")

        ext = os.path.splitext(name)[1].lower()
        if ext in ('.png', '.jpg', '.jpeg', '.gif', '.webp'):
            icon = "🖼️ Image Asset"
        elif ext in ('.zip', '.tar', '.gz', '.7z', '.rar'):
            icon = "🗜️ Compressed Archive"
        elif ext == '.pdf':
            icon = "📑 Adobe PDF Document"
        elif ext in ('.docx', '.xlsx', '.pptx'):
            icon = "📊 Office Document"
        else:
            icon = "📦 Binary Cloud Asset"

        return f"""
        <div style="font-family: 'Segoe UI', sans-serif; padding: 14px; text-align: center;">
            <div style="background-color: {card_bg}; border: 1px solid {card_border}; border-radius: 8px; padding: 24px 16px;">
                <div style="font-size: 36px; margin-bottom: 8px;">{icon[:2]}</div>
                <div style="font-size: 13px; font-weight: 800; color: #38bdf8;">
                    {html.escape(name)}
                </div>
                <div style="font-size: 11px; color: #94a3b8; margin-top: 4px;">
                    MIME: <b>{html.escape(mtype)}</b> | Size: <b>{size_str}</b>
                </div>
                <div style="background: rgba(56, 189, 248, 0.08); border-radius: 6px; padding: 10px; margin-top: 14px; font-size: 10px; color: {text_color}; text-align: left;">
                    ℹ️ <b>Binary Format Content Card:</b><br>
                    This asset is encoded in binary format ({ext.upper() or 'BINARY'}).
                    Raw binary characters are suppressed to prevent display corruption.
                    Inspect forensic security telemetry and permissions in the <b>Posture && DLP</b> tab.
                </div>
            </div>
        </div>
        """

    def format_text_preview(self, content_str: str, name: str) -> str:
        """Renders standard text/code documents in clean monospace view."""
        is_dark = self.is_dark_mode()
        text_color = "#f8fafc" if is_dark else "#0f172a"
        esc = html.escape(content_str[:12000])
        return f"""
        <div style="font-family: Consolas, 'Courier New', monospace; font-size: 10px; color: {text_color}; white-space: pre-wrap; line-height: 1.4;">{esc}</div>
        """

    def render_file_preview(self, asset: dict):
        """Zero-Trust Gatekeeper & Multi-Format In-System File Content Inspector."""
        is_unsecure, reason = self.is_file_unsecure(asset)
        is_dark = self.is_dark_mode()

        bg_col = "#0b0f19" if is_dark else "#ffffff"
        border_col = "#1e293b" if is_dark else "#e2e8f0"
        self.txt_file_preview.setStyleSheet(f"background-color: {bg_col}; border: 1px solid {border_col}; border-radius: 6px; padding: 6px;")

        if is_unsecure:
            self.lbl_pv_notice.setText("🛑 Zero-Trust Security Gatekeeper: File Preview Prohibited")
            self.lbl_pv_notice.setStyleSheet("font-size: 10px; font-weight: bold; color: #ef4444;")
            blocked_html = self.generate_blocked_preview_html(asset, reason)
            self.txt_file_preview.setHtml(blocked_html)
            return

        self.lbl_pv_notice.setText("📄 In-System Document & Content Inspector:")
        self.lbl_pv_notice.setStyleSheet("font-size: 10px; font-weight: bold; color: #38bdf8;")

        name = asset.get("name", "").lower()
        mime = asset.get("mimeType", "").lower()

        binary_exts = (
            '.pdf', '.png', '.jpg', '.jpeg', '.gif', '.bmp', '.webp', '.ico',
            '.zip', '.tar', '.gz', '.tgz', '.bz2', '.7z', '.rar',
            '.docx', '.xlsx', '.pptx', '.bin', '.iso', '.dmg'
        )
        if any(name.endswith(ext) for ext in binary_exts) or ("image/" in mime or "application/pdf" in mime or "application/zip" in mime):
            self.txt_file_preview.setHtml(self.format_binary_metadata_preview(asset))
            return

        content = asset.get("content_preview", "")
        if not content or content == "Binary preview unavailable":
            content = self.scanner.get_file_content(asset.get("id"), asset.get("mimeType"))
            asset["content_preview"] = content

        if not content or content.strip() == "":
            self.txt_file_preview.setHtml("<div style='color: #94a3b8; font-style: italic; padding: 12px;'>File is empty (0 bytes).</div>")
            return

        if name.endswith(".ipynb"):
            self.txt_file_preview.setHtml(self.format_notebook_preview(content))
        elif name.endswith((".csv", ".tsv")):
            self.txt_file_preview.setHtml(self.format_csv_preview(content))
        elif name.endswith(".json"):
            self.txt_file_preview.setHtml(self.format_json_preview(content))
        else:
            self.txt_file_preview.setHtml(self.format_text_preview(content, name))

    def open_asset_dossier(self, asset: dict):
        """Displays deep metadata, permission breakdown, and in-app text preview."""
        self.current_dossier_asset = asset
        self.txt_dossier_report.setHtml(self.generate_dossier_html(asset))
        self.render_file_preview(asset)

        # Configure action buttons
        raw = asset.get("raw_findings", [])
        is_public = any(f["label"] == "Public Internet Exposure" for f in raw)
        self.btn_action_revoke.setEnabled(is_public)
        self.btn_action_revoke.setText("🛡️ Revoke Public Link" if is_public else "✓ No Public Link")
        if is_public:
            self.btn_action_revoke.setStyleSheet("")
        else:
            self.btn_action_revoke.setStyleSheet("background-color: rgba(148, 163, 184, 0.12); color: #64748b; border: 1px solid rgba(148, 163, 184, 0.2); font-weight: 600;")

        self.dossier_panel.show()

    def generate_dossier_html(self, asset: dict) -> str:
        """Renders rich HTML forensic analysis for the cloud asset."""
        is_dark = self.is_dark_mode()
        card_bg = "#111726" if is_dark else "#f8fafc"
        card_border = "#1e293b" if is_dark else "#e2e8f0"
        header_text = "#38bdf8"
        text_primary = "#f8fafc" if is_dark else "#0f172a"
        text_muted = "#94a3b8"

        score = asset.get("score", 0)
        risk_color = "#ef4444" if score >= 75 else ("#f59e0b" if score >= 50 else "#10b981")
        verdict = "CRITICAL DATA RISK" if score >= 75 else ("ELEVATED RISK" if score >= 50 else "CLEAN COMPLIANT ASSET")
        raw_findings = asset.get("raw_findings", [])

        html = f"""
        <table width="100%" cellpadding="10" cellspacing="0" style="background-color: {card_bg}; border: 1px solid {card_border}; border-radius: 6px; margin-bottom: 8px; font-family: 'Segoe UI', sans-serif;">
            <tr>
                <td>
                    <div style="font-size: 11px; font-weight: bold; color: {header_text}; text-transform: uppercase;">
                        TARGET CLOUD ASSET POSTURE
                    </div>
                    <div style="font-size: 13px; font-weight: 800; color: {risk_color}; margin-top: 4px;">
                        {verdict} (Risk Score: {score}/100)
                    </div>
                    <div style="font-size: 11px; color: {text_primary}; margin-top: 4px;">
                        File: <b>{asset.get('name', '')}</b>
                    </div>
                </td>
            </tr>
        </table>

        <table width="100%" cellpadding="8" cellspacing="0" style="background-color: {card_bg}; border: 1px solid {card_border}; border-radius: 6px; margin-bottom: 8px; font-family: 'Segoe UI', sans-serif; font-size: 11px;">
            <tr>
                <td colspan="2" style="font-weight: bold; color: {header_text}; border-bottom: 1px solid {card_border};">
                    📋 CLOUD ASSET METADATA
                </td>
            </tr>
            <tr>
                <td width="35%" style="color: {text_muted};">MIME Type:</td>
                <td style="color: {text_primary}; font-family: 'Consolas', monospace;">{asset.get('mimeType', '')}</td>
            </tr>
            <tr>
                <td style="color: {text_muted};">File Size:</td>
                <td style="color: {text_primary};">{asset.get('size', 'N/A')} bytes</td>
            </tr>
            <tr>
                <td style="color: {text_muted};">Unique Asset ID:</td>
                <td style="color: #38bdf8; font-family: 'Consolas', monospace;">{asset.get('id', '')}</td>
            </tr>
        </table>
        """

        if raw_findings:
            html += f"""
            <table width="100%" cellpadding="8" cellspacing="0" style="background-color: {card_bg}; border: 1px solid {card_border}; border-radius: 6px; font-family: 'Segoe UI', sans-serif; font-size: 11px;">
                <tr>
                    <td style="font-weight: bold; color: #ef4444; border-bottom: 1px solid {card_border};">
                        🚨 TRIGGERED DLP & SECURITY VIOLATIONS ({len(raw_findings)})
                    </td>
                </tr>
            """
            for f in raw_findings:
                badge_bg = "#fee2e2" if not is_dark else "rgba(239, 68, 68, 0.2)"
                html += f"""
                <tr>
                    <td style="border-bottom: 1px dashed {card_border}; padding-top: 6px; padding-bottom: 6px;">
                        <span style="font-weight: bold; color: #ef4444;">[{f.get('severity')}] {f.get('label')}</span>
                        <span style="color: {text_muted}; font-size: 10px; margin-left: 6px;">(Found {f.get('count')} times)</span><br>
                        <span style="color: {text_primary}; font-size: 10px;">{f.get('desc')}</span><br>
                        <span style="color: #f59e0b; font-family: 'Consolas', monospace; font-size: 10px;">Sample: {f.get('sample', '')}</span>
                    </td>
                </tr>
                """
            html += "</table>"
        else:
            html += f"""
            <table width="100%" cellpadding="10" cellspacing="0" style="background-color: {card_bg}; border: 1px solid {card_border}; border-radius: 6px; font-family: 'Segoe UI', sans-serif; font-size: 11px;">
                <tr>
                    <td style="color: #10b981; font-weight: bold;">
                        ✓ Clean Compliance: No sensitive data leaks, public links, or malware IoCs detected.
                    </td>
                </tr>
            </table>
            """

        return html

    def execute_single_revocation(self):
        """Zero-Trust Remediation: Revokes public link for currently selected asset."""
        if not self.current_dossier_asset:
            return
        f_id = self.current_dossier_asset.get("id")
        f_name = self.current_dossier_asset.get("name")

        ok, msg = self.scanner.revoke_public_access(f_id)
        if ok:
            QMessageBox.information(self, "Zero-Trust Enforcement", f"Successfully revoked public link access for '{f_name}'.")
            self.start_deep_scan()
            self.dossier_panel.hide()
        else:
            QMessageBox.critical(self, "Revocation Failed", msg)

    def execute_bulk_revocation(self):
        """Bulk Zero-Trust Remediation: Revokes all public links across all scanned files."""
        public_files = [a for a in self.scan_results if any(f["label"] == "Public Internet Exposure" for f in a.get("raw_findings", []))]
        if not public_files:
            QMessageBox.information(self, "Zero-Trust Verified", "No publicly exposed assets found. All assets meet Zero-Trust privacy rules.")
            return

        reply = QMessageBox.question(
            self, "Confirm Bulk Revocation",
            f"Are you sure you want to enforce Zero-Trust and revoke public links on {len(public_files)} file(s)?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        if reply == QMessageBox.StandardButton.Yes:
            success_count = 0
            for a in public_files:
                ok, _ = self.scanner.revoke_public_access(a.get("id"))
                if ok:
                    success_count += 1
            QMessageBox.information(self, "Bulk Remediation Complete", f"Successfully revoked public link access for {success_count} asset(s).")
            self.start_deep_scan()

    def execute_single_vault(self):
        """Cryptographic Quarantine: Pulls file, encrypts locally, and purges from cloud."""
        if not self.current_dossier_asset:
            return
        f_id = self.current_dossier_asset.get("id")
        f_name = self.current_dossier_asset.get("name")

        reply = QMessageBox.question(
            self, "Confirm Quarantine & Vault",
            f"Quarantine and vault '{f_name}'?\n\nThis will encrypt the asset locally into ~/NexaShield_Vault and PERMANENTLY delete it from Cloud Storage.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        if reply == QMessageBox.StandardButton.Yes:
            ok, vault_path = self.scanner.vault_file(f_id, f_name)
            if ok:
                self.vaulted_count += 1
                self.card_vaulted.set_value(str(self.vaulted_count))
                try:
                    self.db.save_cloud_vaulted_asset(f_name, f_id, vault_path, reason="User Quarantined Threat")
                except Exception:
                    pass
                QMessageBox.information(self, "Asset Vaulted", f"Asset safely neutralized and quarantined at:\n{vault_path}\n\nOriginal asset purged from cloud.")
                self.start_deep_scan()
                self.dossier_panel.hide()
            else:
                QMessageBox.critical(self, "Quarantine Failed", vault_path)

    def apply_filters(self):
        """Applies search keyword, severity filter, and exposure filter across audit table rows."""
        query = self.search_input.text().strip().lower()
        sev_filter = self.filter_severity.currentText()
        exp_filter = self.filter_exposure.currentText()

        for r in range(self.table_audit.rowCount()):
            name = self.table_audit.item(r, 0).text().lower() if self.table_audit.item(r, 0) else ""
            mtype = self.table_audit.item(r, 1).text().lower() if self.table_audit.item(r, 1) else ""
            sharing = self.table_audit.item(r, 3).text() if self.table_audit.item(r, 3) else ""
            score_text = self.table_audit.item(r, 4).text().strip() if self.table_audit.item(r, 4) else ""
            findings = self.table_audit.item(r, 5).text().lower() if self.table_audit.item(r, 5) else ""

            # Check query
            match_query = (not query or query in name or query in mtype or query in findings)

            # Check severity
            score_val = int(score_text.split("/")[0].strip()) if "/" in score_text else 0
            if sev_filter == "Critical":
                match_sev = (score_val >= 75)
            elif sev_filter == "High":
                match_sev = (50 <= score_val < 75)
            elif sev_filter == "Medium":
                match_sev = (25 <= score_val < 50)
            elif sev_filter == "Clean":
                match_sev = (score_val == 0)
            else:
                match_sev = True

            # Check exposure
            if exp_filter == "Public Internet":
                match_exp = ("Public" in sharing)
            elif exp_filter == "External Domain":
                match_exp = ("External" in sharing)
            elif exp_filter == "Private":
                match_exp = ("Private" in sharing)
            else:
                match_exp = True

            self.table_audit.setRowHidden(r, not (match_query and match_sev and match_exp))

    def export_csv(self):
        """Exports cloud CASB audit findings to CSV and vaults in FMS."""
        import csv
        import io
        if self.table_audit.rowCount() == 0:
            QMessageBox.warning(self, "No Data", "No cloud assets available to export.")
            return

        try:
            output = io.StringIO()
            writer = csv.writer(output)
            writer.writerow(["Asset Name", "MIME Type", "Size", "Sharing Posture", "Security Score", "Findings"])
            for r in range(self.table_audit.rowCount()):
                writer.writerow([
                    self.table_audit.item(r, 0).text() if self.table_audit.item(r, 0) else "",
                    self.table_audit.item(r, 1).text() if self.table_audit.item(r, 1) else "",
                    self.table_audit.item(r, 2).text() if self.table_audit.item(r, 2) else "",
                    self.table_audit.item(r, 3).text() if self.table_audit.item(r, 3) else "",
                    self.table_audit.item(r, 4).text() if self.table_audit.item(r, 4) else "",
                    self.table_audit.item(r, 5).text() if self.table_audit.item(r, 5) else ""
                ])

            file_path, _ = QFileDialog.getSaveFileName(self, "Export Cloud Audit CSV", "cloud_casb_audit.csv", "CSV Files (*.csv)")
            if file_path:
                with open(file_path, "w", newline="", encoding="utf-8") as f:
                    f.write(output.getvalue())
                QMessageBox.information(self, "CSV Exported", f"Cloud CASB audit exported successfully:\n{file_path}")
        except Exception as e:
            QMessageBox.critical(self, "Export Error", str(e))

    def export_pdf(self):
        """Generates an enterprise Cloud CASB Audit PDF report."""
        if self.table_audit.rowCount() == 0:
            QMessageBox.warning(self, "No Data", "No cloud assets available to export.")
            return

        file_path, _ = QFileDialog.getSaveFileName(self, "Export Cloud Audit PDF", "Cloud_CASB_Audit_Report.pdf", "PDF Files (*.pdf)")
        if not file_path:
            return

        try:
            from reportlab.lib.pagesizes import letter
            from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.lib import colors

            doc = SimpleDocTemplate(file_path, pagesize=letter, rightMargin=36, leftMargin=36, topMargin=36, bottomMargin=36)
            styles = getSampleStyleSheet()
            story = []

            title_style = ParagraphStyle('Title', parent=styles['Heading1'], fontSize=18, textColor=colors.HexColor("#0284c7"), spaceAfter=10)
            story.append(Paragraph("☁️ NexaShield - Cloud CASB & CSPM Security Audit", title_style))
            story.append(Paragraph(f"Audit Date: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | Total Scanned: {len(self.scan_results)}", styles['Normal']))
            story.append(Spacer(1, 15))

            table_data = [["Asset Name", "Type", "Size", "Sharing", "Score", "Security Findings"]]
            for r in range(min(45, self.table_audit.rowCount())):
                table_data.append([
                    (self.table_audit.item(r, 0).text()[:26] + "...") if self.table_audit.item(r, 0) else "",
                    self.table_audit.item(r, 1).text() if self.table_audit.item(r, 1) else "",
                    self.table_audit.item(r, 2).text() if self.table_audit.item(r, 2) else "",
                    self.table_audit.item(r, 3).text() if self.table_audit.item(r, 3) else "",
                    self.table_audit.item(r, 4).text().strip() if self.table_audit.item(r, 4) else "",
                    (self.table_audit.item(r, 5).text()[:35] + "...") if self.table_audit.item(r, 5) else ""
                ])

            t = Table(table_data, colWidths=[120, 60, 50, 75, 45, 190])
            t.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#0284c7")),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 8),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 6),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ]))
            story.append(t)
            doc.build(story)
            QMessageBox.information(self, "PDF Exported", f"Forensic Cloud Security PDF exported successfully:\n{file_path}")
        except Exception as e:
            # Fallback to native PyQt6 QPrinter / QTextDocument if ReportLab is unavailable
            try:
                from PyQt6.QtGui import QTextDocument
                from PyQt6.QtPrintSupport import QPrinter
                printer = QPrinter(QPrinter.PrinterMode.HighResolution)
                printer.setOutputFormat(QPrinter.OutputFormat.PdfFormat)
                printer.setOutputFileName(file_path)
                
                rows_html = "".join(f"<tr><td>{self.table_audit.item(r,0).text() if self.table_audit.item(r,0) else ''}</td><td>{self.table_audit.item(r,1).text() if self.table_audit.item(r,1) else ''}</td><td>{self.table_audit.item(r,2).text() if self.table_audit.item(r,2) else ''}</td><td>{self.table_audit.item(r,3).text() if self.table_audit.item(r,3) else ''}</td><td>{self.table_audit.item(r,4).text() if self.table_audit.item(r,4) else ''}</td><td>{self.table_audit.item(r,5).text() if self.table_audit.item(r,5) else ''}</td></tr>" for r in range(self.table_audit.rowCount()))
                doc = QTextDocument()
                doc.setHtml(f"<h2>☁️ NexaShield Cloud Security Audit</h2><table border='1' cellspacing='0' cellpadding='4'><tr><th>Asset Name</th><th>Type</th><th>Size</th><th>Sharing</th><th>Score</th><th>Findings</th></tr>{rows_html}</table>")
                doc.print(printer)
                QMessageBox.information(self, "PDF Exported", f"Forensic Cloud Security PDF exported successfully:\n{file_path}")
            except Exception as e2:
                QMessageBox.critical(self, "PDF Export Failed", str(e2))

    def clear_view(self):
        """Clears tables and resets charts."""
        self.table_audit.setRowCount(0)
        self.table_files.setRowCount(0)
        self.scan_results.clear()
        self.chart_donut.reset()
        self.card_score.set_value("100%")
        self.card_exposed.set_value("0")
        self.card_dlp.set_value("0")
        self.dossier_panel.hide()
