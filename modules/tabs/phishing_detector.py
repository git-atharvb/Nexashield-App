import os
import sys
import re
import math
import time
import json
import socket
import datetime
from collections import deque

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QGridLayout, QLineEdit, QPushButton,
    QLabel, QTableWidget, QTableWidgetItem, QHeaderView, QMessageBox,
    QFileDialog, QFrame, QGroupBox, QProgressBar, QAbstractItemView,
    QToolTip, QComboBox, QCheckBox, QTextEdit, QApplication, QSizePolicy
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QRectF, QTimer, QEvent
from PyQt6.QtGui import (
    QColor, QBrush, QTextDocument, QFont, QPainter, QPen, QPalette,
    QLinearGradient, QPainterPath, QPageSize
)
from PyQt6.QtPrintSupport import QPrinter

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from database import DatabaseManager
from phishing_logic import PhishingIntelligenceEngine

# --- Sortable Table Item ---
class SortableTableWidgetItem(QTableWidgetItem):
    """Custom table item supporting numerical and alphanumeric sorting."""
    def __lt__(self, other):
        val1 = self.data(Qt.ItemDataRole.UserRole)
        val2 = other.data(Qt.ItemDataRole.UserRole)
        if val1 is not None and val2 is not None:
            try:
                return float(val1) < float(val2)
            except (ValueError, TypeError):
                return str(val1).lower() < str(val2).lower()
        return super().__lt__(other)


# --- InfoCard (Telemetry Metric Tile) ---
class InfoCard(QFrame):
    """High-density styled telemetry tile for stats banner."""
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


# --- Enhanced Glassmorphic Donut Chart ---
class EnhancedPhishingStatsChart(QWidget):
    """
    Modern cyber donut chart with hover tooltips, click-to-filter support,
    and high-contrast centered total counters.
    """
    filter_requested = pyqtSignal(str)

    def __init__(self):
        super().__init__()
        self.setMinimumSize(160, 130)
        self.stats = {"Safe": 0, "Low Risk": 0, "Medium Risk": 0, "High Risk": 0}
        self.colors = {
            "Safe": QColor("#10b981"),        # Emerald Green
            "Low Risk": QColor("#0ea5e9"),    # Sky Blue
            "Medium Risk": QColor("#f59e0b"), # Amber
            "High Risk": QColor("#ef4444")    # Red
        }
        self.setMouseTracking(True)

    def update_stats(self, stats_dict):
        self.stats = {
            "Safe": stats_dict.get("Safe", 0),
            "Low Risk": stats_dict.get("Low Risk", 0),
            "Medium Risk": stats_dict.get("Medium Risk", 0),
            "High Risk": stats_dict.get("High Risk", 0)
        }
        self.update()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        w = self.width()
        h = self.height()
        is_dark = self.palette().color(QPalette.ColorRole.Window).lightness() < 128
        bg_col = QColor("#111726") if is_dark else QColor("#ffffff")
        bdr_col = QColor("#1e293b") if is_dark else QColor("#e2e8f0")
        text_col = self.palette().color(QPalette.ColorRole.WindowText)

        painter.fillRect(0, 0, w, h, bg_col)
        painter.setPen(QPen(bdr_col, 1))
        painter.drawRect(0, 0, w - 1, h - 1)

        # Header Title
        painter.setPen(text_col)
        painter.setFont(QFont("Segoe UI", 9, QFont.Weight.Bold))
        painter.drawText(10, 18, "📊 Threat Distribution")

        # Donut dimensions
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

        # Center text
        painter.setPen(text_col)
        painter.setFont(QFont("Segoe UI", 10, QFont.Weight.Bold))
        painter.drawText(inner_rect, Qt.AlignmentFlag.AlignCenter, f"{total}\nScans")

    def mouseMoveEvent(self, event):
        total = sum(self.stats.values())
        if total == 0:
            return super().mouseMoveEvent(event)

        pos = event.pos()
        w, h = self.width(), self.height()
        chart_size = min(w - 20, h - 35)
        rect = QRectF((w - chart_size) / 2, 26, chart_size, chart_size)
        center = rect.center()
        dx = pos.x() - center.x()
        dy = pos.y() - center.y()
        distance = math.hypot(dx, dy)

        inner_radius = (chart_size * 0.65) / 2
        outer_radius = chart_size / 2

        if inner_radius <= distance <= outer_radius:
            angle = math.degrees(math.atan2(-dy, dx))
            if angle < 0:
                angle += 360
            mapped = (angle - 90) % 360

            cur = 0
            for label, count in self.stats.items():
                if count > 0:
                    span = (count / total) * 360
                    if cur <= mapped <= cur + span:
                        pct = (count / total) * 100
                        QToolTip.showText(
                            event.globalPosition().toPoint(),
                            f"<b>{label}</b><br>Scans: {count}<br>Share: {pct:.1f}%<br><i>(Click to filter)</i>",
                            self
                        )
                        return
                    cur += span
        QToolTip.hideText()
        super().mouseMoveEvent(event)

    def mousePressEvent(self, event):
        total = sum(self.stats.values())
        if total == 0:
            return super().mousePressEvent(event)

        pos = event.pos()
        w, h = self.width(), self.height()
        chart_size = min(w - 20, h - 35)
        rect = QRectF((w - chart_size) / 2, 26, chart_size, chart_size)
        center = rect.center()
        dx = pos.x() - center.x()
        dy = pos.y() - center.y()
        distance = math.hypot(dx, dy)

        inner_radius = (chart_size * 0.65) / 2
        outer_radius = chart_size / 2

        if inner_radius <= distance <= outer_radius:
            angle = math.degrees(math.atan2(-dy, dx))
            if angle < 0: angle += 360
            mapped = (angle - 90) % 360

            cur = 0
            for label, count in self.stats.items():
                if count > 0:
                    span = (count / total) * 360
                    if cur <= mapped <= cur + span:
                        self.filter_requested.emit(label)
                        return
                    cur += span
        super().mousePressEvent(event)


# --- Scan Timeline Bézier Chart ---
class ScanTimelineChart(QWidget):
    """Telemetry curve showing recent threat scores with gradient fill and peak watermark."""
    def __init__(self, title="📈 Threat Activity Timeline"):
        super().__init__()
        self.title = title
        self.data = deque([0.0] * 30, maxlen=30)
        self.setMinimumSize(180, 130)
        self.peak_value = 0.0

    def update_history(self, scores: list[float]):
        if not scores:
            scores = [0.0]
        self.data.clear()
        recent = scores[:30][::-1]
        while len(recent) < 30:
            recent.insert(0, 0.0)
        for s in recent:
            self.data.append(s)
            if s > self.peak_value:
                self.peak_value = s
        self.update()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        w = self.width()
        h = self.height()
        is_dark = self.palette().color(QPalette.ColorRole.Window).lightness() < 128
        bg_col = QColor("#111726") if is_dark else QColor("#ffffff")
        bdr_col = QColor("#1e293b") if is_dark else QColor("#e2e8f0")
        text_col = self.palette().color(QPalette.ColorRole.WindowText)
        line_color = QColor("#0ea5e9")

        painter.fillRect(0, 0, w, h, bg_col)
        painter.setPen(QPen(bdr_col, 1))
        painter.drawRect(0, 0, w - 1, h - 1)

        painter.setPen(text_col)
        painter.setFont(QFont("Segoe UI", 9, QFont.Weight.Bold))
        painter.drawText(10, 18, self.title)

        top_pad = 28
        bottom_pad = 18
        chart_h = max(10, h - top_pad - bottom_pad)

        # Grid lines
        grid_col = QColor(255, 255, 255, 12) if is_dark else QColor(0, 0, 0, 15)
        painter.setPen(QPen(grid_col, 1, Qt.PenStyle.DashLine))
        for i in range(1, 3):
            y_line = top_pad + i * (chart_h / 3)
            painter.drawLine(10, int(y_line), w - 10, int(y_line))

        if not self.data:
            return

        step_x = (w - 20) / (self.data.maxlen - 1) if self.data.maxlen > 1 else w
        scale_max = 100.0

        # Build Bézier Path
        path = QPainterPath()
        first_x = 10
        first_y = top_pad + chart_h - (self.data[0] / scale_max * chart_h)
        path.moveTo(first_x, first_y)

        prev_x, prev_y = first_x, first_y
        for i in range(1, len(self.data)):
            x = 10 + i * step_x
            y = top_pad + chart_h - (self.data[i] / scale_max * chart_h)
            ctrl_x1 = prev_x + (x - prev_x) * 0.5
            ctrl_y1 = prev_y
            ctrl_x2 = prev_x + (x - prev_x) * 0.5
            ctrl_y2 = y
            path.cubicTo(ctrl_x1, ctrl_y1, ctrl_x2, ctrl_y2, x, y)
            prev_x, prev_y = x, y

        # Fill under curve
        fill_path = QPainterPath(path)
        fill_path.lineTo(prev_x, top_pad + chart_h)
        fill_path.lineTo(10, top_pad + chart_h)
        fill_path.closeSubpath()

        grad = QLinearGradient(0, top_pad, 0, top_pad + chart_h)
        grad.setColorAt(0, QColor(14, 165, 233, 100))
        grad.setColorAt(1, QColor(14, 165, 233, 5))
        painter.setBrush(grad)
        painter.setPen(Qt.PenStyle.NoPen)
        painter.drawPath(fill_path)

        # Draw line
        painter.setPen(QPen(line_color, 2, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap))
        painter.setBrush(Qt.BrushStyle.NoBrush)
        painter.drawPath(path)

        # Peak indicator
        painter.setFont(QFont("Segoe UI", 8))
        painter.setPen(QColor(148, 163, 184, 160))
        painter.drawText(10, h - 5, f"Peak Threat: {self.peak_value:.0f}/100")


# --- Background Workers ---
class PhishingScannerWorker(QThread):
    """Background worker for deep single URL scan."""
    scan_complete = pyqtSignal(dict)
    error_occurred = pyqtSignal(str)

    def __init__(self, url: str):
        super().__init__()
        self.url = url

    def run(self):
        try:
            engine = PhishingIntelligenceEngine()
            result = engine.scan(self.url)
            self.scan_complete.emit(result)
        except Exception as e:
            self.error_occurred.emit(str(e))


class BatchPhishingWorker(QThread):
    """Background thread for batch URL imports."""
    progress = pyqtSignal(int, int)
    result_ready = pyqtSignal(dict)
    finished_batch = pyqtSignal()

    def __init__(self, urls: list[str]):
        super().__init__()
        self.urls = urls
        self.is_running = True

    def stop(self):
        self.is_running = False

    def run(self):
        engine = PhishingIntelligenceEngine()
        total = len(self.urls)
        for i, url in enumerate(self.urls):
            if not self.is_running:
                break
            url = url.strip()
            if url:
                try:
                    res = engine.scan(url)
                    self.result_ready.emit(res)
                except Exception:
                    pass
            self.progress.emit(i + 1, total)
        self.finished_batch.emit()


# --- Main Phishing Detector Widget ---
class PhishingDetectorWidget(QWidget):
    """
    Enterprise Phishing Threat Intelligence, Forensic Investigation & Dossier Suite.
    Integrates 22+ rule deep heuristics, live SSL/TLS & DOM checks, permanent database storage,
    a 440px right slide-out forensic dossier drawer, batch scanning, and FMS vaulting.
    """
    def __init__(self, session_manager=None):
        super().__init__()
        self.session = session_manager
        self.setObjectName("PhishingDetector")

        # Database Setup
        db_path = self.session.get_db_path() if self.session and hasattr(self.session, "get_db_path") else "nexashield.db"
        self.db = DatabaseManager(db_name=db_path)

        # State Variables
        self.current_scans = []
        self.selected_scan_ids = set()
        self.current_dossier_data = {}
        self.search_filter = ""
        self.threat_filter = "All Threat Levels"
        self.worker = None
        self.batch_worker = None

        self.setup_ui()
        self.migrate_legacy_data()
        self.refresh_data()

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
        super().changeEvent(event)
        if event.type() in (QEvent.Type.PaletteChange, QEvent.Type.StyleChange):
            # Refresh currently open dossier to match new theme
            if self.dossier_panel.isVisible() and self.current_dossier_data:
                self.txt_dossier.setHtml(self.generate_dossier_html(self.current_dossier_data))
            # Refresh table badges
            if self.current_scans:
                self.populate_table(self.current_scans)
            self.stats_chart.update()
            self.timeline_chart.update()

    def setup_ui(self):
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(15, 12, 15, 12)
        main_layout.setSpacing(10)

        # ==========================================================
        # 1. TOP TOOLBAR (Matching Process/Network toolbar styling)
        # ==========================================================
        self.toolbar = QFrame()
        self.toolbar.setObjectName("ProcessToolbar")
        self.toolbar.setFixedHeight(46)
        toolbar_layout = QHBoxLayout(self.toolbar)
        toolbar_layout.setContentsMargins(10, 0, 10, 0)
        toolbar_layout.setSpacing(8)

        # Search Box
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("🔍 Filter scans by URL, domain, or IP...")
        self.search_input.setClearButtonEnabled(True)
        self.search_input.setMinimumWidth(220)
        self.search_input.setMaximumWidth(280)
        self.search_input.textChanged.connect(self.on_search_changed)
        toolbar_layout.addWidget(self.search_input)

        # Threat Filter Dropdown (Adequate width so text is never truncated)
        self.combo_threat = QComboBox()
        self.combo_threat.addItems(["All Threat Levels", "Safe", "Low Risk", "Medium Risk", "High Risk"])
        self.combo_threat.setMinimumWidth(175)
        self.combo_threat.setSizePolicy(QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Fixed)
        self.combo_threat.currentTextChanged.connect(self.on_threat_filter_changed)
        toolbar_layout.addWidget(self.combo_threat)

        toolbar_layout.addStretch()

        # Action Buttons
        self.btn_select_all = QPushButton("☑ Select All")
        self.btn_select_all.setObjectName("BtnSecondary")
        self.btn_select_all.setFixedHeight(30)
        self.btn_select_all.setMinimumWidth(100)
        self.btn_select_all.clicked.connect(self.toggle_select_all)
        toolbar_layout.addWidget(self.btn_select_all)

        self.btn_delete_selected = QPushButton("🗑️ Delete Selected")
        self.btn_delete_selected.setObjectName("BtnDanger")
        self.btn_delete_selected.setFixedHeight(30)
        self.btn_delete_selected.setMinimumWidth(120)
        self.btn_delete_selected.setEnabled(False)
        self.btn_delete_selected.clicked.connect(self.delete_selected_records)
        toolbar_layout.addWidget(self.btn_delete_selected)

        self.btn_clear_all = QPushButton("🧹 Clear All")
        self.btn_clear_all.setObjectName("BtnDanger")
        self.btn_clear_all.setFixedHeight(30)
        self.btn_clear_all.setMinimumWidth(95)
        self.btn_clear_all.clicked.connect(self.clear_all_history)
        toolbar_layout.addWidget(self.btn_clear_all)

        self.btn_export_pdf = QPushButton("📄 Export PDF")
        self.btn_export_pdf.setObjectName("BtnWarning")
        self.btn_export_pdf.setFixedHeight(30)
        self.btn_export_pdf.setMinimumWidth(105)
        self.btn_export_pdf.clicked.connect(self.export_history_pdf)
        toolbar_layout.addWidget(self.btn_export_pdf)

        self.btn_export_csv = QPushButton("📊 Export CSV")
        self.btn_export_csv.setObjectName("BtnSecondary")
        self.btn_export_csv.setFixedHeight(30)
        self.btn_export_csv.setMinimumWidth(105)
        self.btn_export_csv.clicked.connect(self.export_history_csv)
        toolbar_layout.addWidget(self.btn_export_csv)

        self.btn_refresh = QPushButton("🔄 Refresh")
        self.btn_refresh.setObjectName("BtnPrimary")
        self.btn_refresh.setFixedHeight(30)
        self.btn_refresh.setMinimumWidth(95)
        self.btn_refresh.clicked.connect(self.refresh_data)
        toolbar_layout.addWidget(self.btn_refresh)

        main_layout.addWidget(self.toolbar)

        # ==========================================================
        # 2. METRIC RIBBON (4 InfoCards)
        # ==========================================================
        ribbon_layout = QHBoxLayout()
        ribbon_layout.setSpacing(10)

        self.card_total = InfoCard("Total Scans", "0", "🌐", "#0ea5e9")
        self.card_threats = InfoCard("High Risk Threats", "0", "🚨", "#ef4444")
        self.card_safe = InfoCard("Safe / Benign", "0", "🛡️", "#10b981")
        self.card_avg = InfoCard("Avg Threat Score", "0.0/100", "⚡", "#f59e0b")

        ribbon_layout.addWidget(self.card_total)
        ribbon_layout.addWidget(self.card_threats)
        ribbon_layout.addWidget(self.card_safe)
        ribbon_layout.addWidget(self.card_avg)
        main_layout.addLayout(ribbon_layout)

        # ==========================================================
        # 3. URL SCANNER INPUT BAR
        # ==========================================================
        scanner_group = QGroupBox("🔍 Deep URL Threat Scanner")
        scanner_layout = QHBoxLayout(scanner_group)
        scanner_layout.setContentsMargins(12, 10, 12, 10)
        scanner_layout.setSpacing(10)

        self.url_input = QLineEdit()
        self.url_input.setPlaceholderText("🌐 Enter target URL to inspect (e.g., https://secure-login.update-paypal.xyz)...")
        self.url_input.setClearButtonEnabled(True)
        self.url_input.returnPressed.connect(self.start_scan)
        scanner_layout.addWidget(self.url_input, 1)

        self.btn_scan = QPushButton("🔍 Deep Scan")
        self.btn_scan.setObjectName("BtnPrimary")
        self.btn_scan.setFixedHeight(34)
        self.btn_scan.setMinimumWidth(125)
        self.btn_scan.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_scan.clicked.connect(self.start_scan)
        scanner_layout.addWidget(self.btn_scan)

        # Generous minimum width so "📂 Import Batch" is never cut off
        self.btn_batch = QPushButton("📂 Import Batch")
        self.btn_batch.setObjectName("BtnSecondary")
        self.btn_batch.setFixedHeight(34)
        self.btn_batch.setMinimumWidth(138)
        self.btn_batch.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_batch.clicked.connect(self.import_batch)
        scanner_layout.addWidget(self.btn_batch)

        self.batch_progress = QProgressBar()
        self.batch_progress.setFixedHeight(22)
        self.batch_progress.setFixedWidth(160)
        self.batch_progress.hide()
        scanner_layout.addWidget(self.batch_progress)

        main_layout.addWidget(scanner_group)

        # ==========================================================
        # 4. MAIN WORKSPACE: TABLE (Left) + SLIDE-OUT DOSSIER (Right)
        # ==========================================================
        workspace_layout = QHBoxLayout()
        workspace_layout.setSpacing(10)

        # --- LEFT WING ---
        left_wing = QWidget()
        left_layout = QVBoxLayout(left_wing)
        left_layout.setContentsMargins(0, 0, 0, 0)
        left_layout.setSpacing(10)

        # Charts Bar (Side-by-side Distribution Donut & Timeline Curve)
        charts_layout = QHBoxLayout()
        charts_layout.setSpacing(10)

        self.stats_chart = EnhancedPhishingStatsChart()
        self.stats_chart.filter_requested.connect(self.on_chart_filter_requested)
        charts_layout.addWidget(self.stats_chart, 1)

        self.timeline_chart = ScanTimelineChart()
        charts_layout.addWidget(self.timeline_chart, 2)

        left_layout.addLayout(charts_layout)

        # History Table
        self.table = QTableWidget()
        self.table.setColumnCount(8)
        self.table.setHorizontalHeaderLabels([
            "☑", "🕒 Timestamp", "🌐 Target URL", "🛡️ Threat Level",
            "📊 Score", "⚙️ Method", "🏷️ Domain", "📡 IP Address"
        ])
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Fixed)
        self.table.setColumnWidth(0, 36)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(5, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(6, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(7, QHeaderView.ResizeMode.ResizeToContents)

        self.table.verticalHeader().setDefaultSectionSize(36)
        self.table.verticalHeader().setVisible(False)
        self.table.setAlternatingRowColors(True)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setSortingEnabled(True)
        self.table.cellClicked.connect(self.on_row_clicked)
        self.table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self.show_context_menu)

        left_layout.addWidget(self.table, 1)
        workspace_layout.addWidget(left_wing, 1)

        # --- RIGHT WING (440px Slide-out Forensic Drawer) ---
        self.dossier_panel = QFrame()
        self.dossier_panel.setObjectName("PhishingDossier")
        self.dossier_panel.setFixedWidth(440)
        self.dossier_panel.hide()

        dossier_layout = QVBoxLayout(self.dossier_panel)
        dossier_layout.setContentsMargins(12, 12, 12, 12)
        dossier_layout.setSpacing(10)

        # Dossier Header
        header_bar = QHBoxLayout()
        self.lbl_dossier_title = QLabel("🔬 URL Intelligence Dossier")
        self.lbl_dossier_title.setStyleSheet("font-size: 13px; font-weight: 800; color: #38bdf8;")
        header_bar.addWidget(self.lbl_dossier_title)
        header_bar.addStretch()

        self.btn_fms_vault = QPushButton("📥 Vault PDF")
        self.btn_fms_vault.setObjectName("BtnPrimary")
        self.btn_fms_vault.setFixedHeight(28)
        self.btn_fms_vault.setToolTip("Generate & Vault Printable Forensic PDF into FMS Vault")
        self.btn_fms_vault.clicked.connect(self.vault_current_dossier_pdf)
        header_bar.addWidget(self.btn_fms_vault)

        self.btn_close_dossier = QPushButton("✕")
        self.btn_close_dossier.setFixedSize(28, 28)
        self.btn_close_dossier.setObjectName("BtnSecondary")
        self.btn_close_dossier.clicked.connect(self.dossier_panel.hide)
        header_bar.addWidget(self.btn_close_dossier)
        dossier_layout.addLayout(header_bar)

        # Scrollable HTML Forensic View
        self.txt_dossier = QTextEdit()
        self.txt_dossier.setReadOnly(True)
        self.txt_dossier.setFrameShape(QFrame.Shape.NoFrame)
        self.txt_dossier.setStyleSheet("background: transparent; border: none;")
        dossier_layout.addWidget(self.txt_dossier, 1)

        # Dossier Action Bar
        action_bar = QHBoxLayout()
        action_bar.setSpacing(6)

        self.btn_rescan = QPushButton("🔄 Re-Scan URL")
        self.btn_rescan.setObjectName("BtnSecondary")
        self.btn_rescan.setFixedHeight(30)
        self.btn_rescan.clicked.connect(self.rescan_current_url)
        action_bar.addWidget(self.btn_rescan)

        self.btn_copy_url = QPushButton("📋 Copy URL")
        self.btn_copy_url.setObjectName("BtnSecondary")
        self.btn_copy_url.setFixedHeight(30)
        self.btn_copy_url.clicked.connect(self.copy_current_url)
        action_bar.addWidget(self.btn_copy_url)

        self.btn_delete_one = QPushButton("🗑️ Delete")
        self.btn_delete_one.setObjectName("BtnDanger")
        self.btn_delete_one.setFixedHeight(30)
        self.btn_delete_one.clicked.connect(self.delete_current_dossier)
        action_bar.addWidget(self.btn_delete_one)

        dossier_layout.addLayout(action_bar)
        workspace_layout.addWidget(self.dossier_panel, 0)

        main_layout.addLayout(workspace_layout, 1)

        # ==========================================================
        # 5. STATUS BAR
        # ==========================================================
        self.status_bar = QFrame()
        self.status_bar.setObjectName("ProcessStatusBar")
        self.status_bar.setFixedHeight(28)
        sb_layout = QHBoxLayout(self.status_bar)
        sb_layout.setContentsMargins(10, 0, 10, 0)

        self.lbl_status = QLabel("Ready")
        self.lbl_status.setStyleSheet("color: #94a3b8; font-size: 11px;")
        sb_layout.addWidget(self.lbl_status)
        sb_layout.addStretch()

        self.lbl_record_count = QLabel("Scans: 0")
        self.lbl_record_count.setStyleSheet("color: #f59e0b; font-weight: bold; font-size: 11px;")
        sb_layout.addWidget(self.lbl_record_count)

        main_layout.addWidget(self.status_bar)

    # --- Data Migration from Legacy schema ---
    def migrate_legacy_data(self):
        """Silently migrates rows from legacy phishing_history table if present."""
        try:
            cursor = self.db.cursor
            cursor.execute("SELECT name FROM sqlite3_master WHERE type='table' AND name='phishing_history'")
            if cursor.fetchone():
                cursor.execute("SELECT url, threat_level, score, timestamp, details, reasons FROM phishing_history")
                rows = cursor.fetchall()
                for r in rows:
                    url, level, score, ts, det_raw, reas_raw = r
                    det = {}
                    reas = []
                    try:
                        if det_raw: det = json.loads(det_raw)
                    except Exception: pass
                    try:
                        if reas_raw: reas = json.loads(reas_raw)
                    except Exception: pass

                    self.db.add_phishing_scan({
                        "url": url,
                        "threat_level": level,
                        "score": score,
                        "timestamp": ts,
                        "method": "Migrated",
                        "reasons": reas,
                        "details": {"anatomy": det, "rules_triggered": []}
                    })
                cursor.execute("ALTER TABLE phishing_history RENAME TO phishing_history_migrated")
                self.db.conn.commit()
        except Exception:
            pass

    # --- Lifecycle Methods ---
    def start_monitoring(self):
        self.refresh_data()

    def cleanup(self):
        """Cleanly terminates background workers."""
        if self.worker and self.worker.isRunning():
            self.worker.terminate()
            self.worker.wait(150)
        if self.batch_worker and self.batch_worker.isRunning():
            self.batch_worker.stop()
            self.batch_worker.terminate()
            self.batch_worker.wait(150)

    def showEvent(self, event):
        super().showEvent(event)
        self.refresh_data()

    def reset_ui(self):
        """Full reset called on tab refresh."""
        self.url_input.clear()
        self.search_input.clear()
        self.combo_threat.setCurrentIndex(0)
        self.dossier_panel.hide()
        self.refresh_data()

    # --- Refresh & Populate Table ---
    def refresh_data(self):
        query = self.search_input.text().strip()
        threat_sel = self.combo_threat.currentText()
        scans = self.db.search_phishing_history(query=query, threat_filter=threat_sel)
        self.current_scans = scans

        # Refresh InfoCards and Charts
        stats = self.db.get_phishing_stats()
        self.card_total.set_value(stats.get("Total", 0))
        self.card_threats.set_value(stats.get("High Risk", 0))
        self.card_safe.set_value(stats.get("Safe", 0))
        self.card_avg.set_value(f"{stats.get('AvgScore', 0.0):.1f}/100")

        self.stats_chart.update_stats(stats)
        scores = [s.get("score", 0.0) for s in scans]
        self.timeline_chart.update_history(scores)

        # Repopulate table
        self.populate_table(scans)
        self.lbl_record_count.setText(f"Showing {len(scans)} of {stats.get('Total', 0)} scans")
        self.lbl_status.setText(f"Synchronized at {time.strftime('%H:%M:%S')}")

    def populate_table(self, scans: list[dict]):
        self.table.setSortingEnabled(False)
        self.table.setRowCount(len(scans))
        is_dark = self.is_dark_mode()

        for row, scan in enumerate(scans):
            scan_id = scan.get("id")

            # Col 0: Checkbox
            chk = QCheckBox()
            chk.setChecked(scan_id in self.selected_scan_ids)
            chk.stateChanged.connect(lambda state, s_id=scan_id: self.on_checkbox_changed(s_id, state))
            chk_widget = QWidget()
            chk_widget.setStyleSheet("background: transparent;")
            chk_layout = QHBoxLayout(chk_widget)
            chk_layout.setContentsMargins(0, 0, 0, 0)
            chk_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
            chk_layout.addWidget(chk)
            self.table.setCellWidget(row, 0, chk_widget)

            # Col 1: Timestamp
            ts_item = SortableTableWidgetItem(scan.get("timestamp", "-"))
            ts_item.setData(Qt.ItemDataRole.UserRole, scan.get("timestamp", ""))
            self.table.setItem(row, 1, ts_item)

            # Col 2: URL
            url_str = scan.get("url", "-")
            url_item = SortableTableWidgetItem(url_str)
            url_item.setToolTip(url_str)
            url_item.setData(Qt.ItemDataRole.UserRole, url_str)
            self.table.setItem(row, 2, url_item)

            # Col 3: Clean, non-clipping Threat Badge
            level = scan.get("threat_level", "Safe")
            lvl_lower = level.lower()
            if "high" in lvl_lower or "critical" in lvl_lower:
                icon = "🔴"
                bg = "rgba(239, 68, 68, 0.20)" if is_dark else "#fee2e2"
                fg = "#f87171" if is_dark else "#b91c1c"
                bdr = "rgba(239, 68, 68, 0.45)" if is_dark else "#fca5a5"
            elif "medium" in lvl_lower or "suspicious" in lvl_lower:
                icon = "🟡"
                bg = "rgba(245, 158, 11, 0.20)" if is_dark else "#fef3c7"
                fg = "#fbbf24" if is_dark else "#b45309"
                bdr = "rgba(245, 158, 11, 0.45)" if is_dark else "#fcd34d"
            elif "low" in lvl_lower:
                icon = "🔵"
                bg = "rgba(14, 165, 233, 0.20)" if is_dark else "#e0f2fe"
                fg = "#38bdf8" if is_dark else "#0369a1"
                bdr = "rgba(14, 165, 233, 0.45)" if is_dark else "#bae6fd"
            else:
                icon = "🟢"
                bg = "rgba(16, 185, 129, 0.20)" if is_dark else "#dcfce7"
                fg = "#34d399" if is_dark else "#15803d"
                bdr = "rgba(16, 185, 129, 0.45)" if is_dark else "#a7f3d0"

            threat_container = QWidget()
            threat_container.setStyleSheet("background: transparent;")
            threat_layout = QHBoxLayout(threat_container)
            threat_layout.setContentsMargins(4, 2, 4, 2)
            threat_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

            lbl_threat = QLabel(f"{icon} {level.upper()}")
            lbl_threat.setAlignment(Qt.AlignmentFlag.AlignCenter)
            lbl_threat.setStyleSheet(f"""
                background-color: {bg};
                color: {fg};
                border: 1px solid {bdr};
                border-radius: 11px;
                padding: 3px 10px;
                font-size: 10px;
                font-weight: 700;
            """)
            threat_layout.addWidget(lbl_threat)
            self.table.setCellWidget(row, 3, threat_container)

            # Col 4: Score
            score = scan.get("score", 0.0)
            score_item = SortableTableWidgetItem(f"{score:.1f}")
            score_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            score_item.setData(Qt.ItemDataRole.UserRole, score)
            if score >= 80:
                score_item.setForeground(QBrush(QColor("#ef4444" if is_dark else "#b91c1c")))
            elif score >= 60:
                score_item.setForeground(QBrush(QColor("#f59e0b" if is_dark else "#b45309")))
            elif score >= 30:
                score_item.setForeground(QBrush(QColor("#0ea5e9" if is_dark else "#0369a1")))
            else:
                score_item.setForeground(QBrush(QColor("#10b981" if is_dark else "#15803d")))
            self.table.setItem(row, 4, score_item)

            # Col 5: Method
            method_item = SortableTableWidgetItem(scan.get("method", "-"))
            method_item.setData(Qt.ItemDataRole.UserRole, scan.get("method", ""))
            self.table.setItem(row, 5, method_item)

            # Col 6: Domain
            dom_item = SortableTableWidgetItem(scan.get("domain", "-"))
            dom_item.setData(Qt.ItemDataRole.UserRole, scan.get("domain", ""))
            self.table.setItem(row, 6, dom_item)

            # Col 7: IP
            ip_item = SortableTableWidgetItem(scan.get("resolved_ip", "-"))
            ip_item.setData(Qt.ItemDataRole.UserRole, scan.get("resolved_ip", ""))
            self.table.setItem(row, 7, ip_item)

        self.table.setSortingEnabled(True)

    # --- Scanning Triggers ---
    def start_scan(self):
        url = self.url_input.text().strip()
        if not url:
            QMessageBox.warning(self, "Input Error", "Please enter a valid URL to scan.")
            return

        if not (url.startswith("http://") or url.startswith("https://")):
            url = "http://" + url
            self.url_input.setText(url)

        self.btn_scan.setEnabled(False)
        self.btn_scan.setText("Analyzing...")
        self.lbl_status.setText(f"Running deep forensic scan on: {url}")

        self.worker = PhishingScannerWorker(url)
        self.worker.scan_complete.connect(self.on_scan_completed)
        self.worker.error_occurred.connect(self.on_scan_failed)
        self.worker.start()

    def on_scan_completed(self, result: dict):
        self.btn_scan.setEnabled(True)
        self.btn_scan.setText("🔍 Deep Scan")

        # 1. Save into permanent DB
        scan_id = self.db.add_phishing_scan(result)
        result["id"] = scan_id

        # 2. SIEM event logging for High Risk
        score = result.get("score", 0.0)
        threat_level = result.get("threat_level", "Safe")
        if score >= 60.0:
            sev = "HIGH" if score >= 80.0 else "MEDIUM"
            self.db.log_siem_event(
                source="Phishing Scanner",
                description=f"Detected {threat_level} URL: {result.get('url')} (Score: {score:.1f})",
                severity=sev
            )

        # 3. Refresh table & open right-side dossier immediately
        self.refresh_data()
        self.display_dossier(result)
        self.lbl_status.setText(f"Deep scan complete for {result.get('url')} (Score: {score:.1f})")

    def on_scan_failed(self, err_msg: str):
        self.btn_scan.setEnabled(True)
        self.btn_scan.setText("🔍 Deep Scan")
        self.lbl_status.setText(f"Scan failed: {err_msg}")
        QMessageBox.critical(self, "Scan Error", f"Deep URL analysis encountered an error:\n{err_msg}")

    # --- Batch Import ---
    def import_batch(self):
        path, _ = QFileDialog.getOpenFileName(self, "Import Batch URLs", "", "Text Files (*.txt);;All Files (*.*)")
        if not path:
            return

        try:
            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                urls = [line.strip() for line in f if line.strip() and not line.strip().startswith("#")]

            if not urls:
                QMessageBox.warning(self, "Empty File", "No URLs found in the selected file.")
                return

            self.batch_progress.show()
            self.batch_progress.setValue(0)
            self.btn_batch.setEnabled(False)
            self.lbl_status.setText(f"Processing batch of {len(urls)} URLs...")

            self.batch_worker = BatchPhishingWorker(urls)
            self.batch_worker.progress.connect(lambda c, t: self.batch_progress.setValue(int((c / t) * 100)))
            self.batch_worker.result_ready.connect(lambda res: self.db.add_phishing_scan(res))
            self.batch_worker.finished_batch.connect(self.on_batch_complete)
            self.batch_worker.start()

        except Exception as e:
            QMessageBox.critical(self, "Import Error", f"Failed to read file: {e}")

    def on_batch_complete(self):
        self.btn_batch.setEnabled(True)
        self.batch_progress.hide()
        self.refresh_data()
        self.lbl_status.setText("Batch import completed successfully.")
        QMessageBox.information(self, "Batch Complete", "Batch URL scanning and intelligence synthesis finished.")

    # --- Table Row Click → Load Stored Dossier ---
    def on_row_clicked(self, row, col):
        if col == 0:
            return  # Clicked checkbox
        if 0 <= row < len(self.current_scans):
            scan_summary = self.current_scans[row]
            scan_id = scan_summary.get("id")
            full_data = self.db.get_phishing_scan_detail(scan_id)
            if not full_data:
                full_data = scan_summary
            self.display_dossier(full_data)

    def display_dossier(self, data: dict):
        self.current_dossier_data = data
        self.dossier_panel.show()
        html = self.generate_dossier_html(data)
        self.txt_dossier.setHtml(html)

    # --- Rich HTML Dossier Builder (Robust Dark/Light Mode Formatting) ---
    def generate_dossier_html(self, data: dict) -> str:
        is_dark = self.is_dark_mode()
        card_bg = "#111726" if is_dark else "#f8fafc"
        card_bdr = "#1e293b" if is_dark else "#e2e8f0"
        text_color = "#f8fafc" if is_dark else "#0f172a"
        sub_color = "#94a3b8" if is_dark else "#64748b"
        accent_color = "#38bdf8" if is_dark else "#0284c7"
        sec_header_color = "#38bdf8" if is_dark else "#0369a1"
        row_bdr = "#161f32" if is_dark else "#edf2f7"

        url = data.get("url", "-")
        threat_level = data.get("threat_level", "Safe")
        score = float(data.get("score", 0.0))
        method = data.get("method", "Heuristics")
        timestamp = data.get("timestamp", "-")
        duration = data.get("scan_duration", 0.0)

        details = data.get("details", {})
        anatomy = details.get("anatomy", {})
        rules = details.get("rules_triggered", [])
        ssl_info = details.get("ssl_analysis", {})
        http_info = details.get("http_analysis", {})
        content_info = details.get("content_analysis", {})
        redirects = details.get("redirect_chain", [])
        ml_res = details.get("ml_results", {})

        # High-contrast Verdict Theme
        if score >= 80:
            v_bg = "rgba(239, 68, 68, 0.16)" if is_dark else "#fef2f2"
            v_bdr = "#ef4444"
            v_fg = "#ef4444" if is_dark else "#b91c1c"
            v_meta = "#fca5a5" if is_dark else "#7f1d1d"
            v_tag = "L5 ◆ CRITICAL THREAT"
        elif score >= 60:
            v_bg = "rgba(245, 158, 11, 0.16)" if is_dark else "#fffbeb"
            v_bdr = "#f59e0b"
            v_fg = "#f59e0b" if is_dark else "#b45309"
            v_meta = "#fde68a" if is_dark else "#78350f"
            v_tag = "L3 ◆ SUSPICIOUS URL"
        elif score >= 30:
            v_bg = "rgba(14, 165, 233, 0.16)" if is_dark else "#f0f9ff"
            v_bdr = "#0ea5e9"
            v_fg = "#38bdf8" if is_dark else "#0369a1"
            v_meta = "#bae6fd" if is_dark else "#0c4a6e"
            v_tag = "L2 ◆ LOW RISK"
        else:
            v_bg = "rgba(16, 185, 129, 0.16)" if is_dark else "#f0fdf4"
            v_bdr = "#10b981"
            v_fg = "#34d399" if is_dark else "#15803d"
            v_meta = "#a7f3d0" if is_dark else "#14532d"
            v_tag = "L1 ◆ VERIFIED BENIGN"

        # Build clean HTML tables that Qt RichText renders natively without block bugs
        html = f"""
        <table width="100%" cellspacing="0" cellpadding="0" style="font-family:'Segoe UI',sans-serif; color:{text_color}; font-size:11px;">
          
          <!-- Card 1: Target URL & AI Verdict -->
          <tr><td style="padding-bottom:8px;">
            <table width="100%" cellspacing="0" cellpadding="8" style="background-color:{card_bg}; border:1px solid {card_bdr}; border-radius:8px;">
              <tr>
                <td style="font-size:10px; font-weight:700; color:{sub_color}; text-transform:uppercase; letter-spacing:0.5px;">
                  TARGET URL INSPECTION
                </td>
              </tr>
              <tr>
                <td style="font-size:12px; font-weight:bold; color:{accent_color}; font-family:monospace; word-break:break-all; padding-top:2px; padding-bottom:8px;">
                  {url}
                </td>
              </tr>
              <tr>
                <td>
                  <table width="100%" cellspacing="0" cellpadding="8" style="background-color:{v_bg}; border:1px solid {v_bdr}; border-left:4px solid {v_bdr}; border-radius:6px;">
                    <tr>
                      <td><b style="color:{v_fg}; font-size:11.5px;">🧠 AI VERDICT: {v_tag}</b></td>
                      <td align="right"><b style="color:{v_fg}; font-size:13px;">{score:.1f}%</b></td>
                    </tr>
                    <tr>
                      <td colspan="2" style="font-size:10px; color:{v_meta}; padding-top:4px;">
                        Engine: <b>{method}</b> &nbsp;|&nbsp; Latency: <b>{duration}s</b> &nbsp;|&nbsp; Scanned: <b>{timestamp}</b>
                      </td>
                    </tr>
                  </table>
                </td>
              </tr>
            </table>
          </td></tr>

          <!-- Card 2: URL Anatomy & DNS Resolution -->
          <tr><td style="padding-bottom:8px;">
            <table width="100%" cellspacing="0" cellpadding="8" style="background-color:{card_bg}; border:1px solid {card_bdr}; border-radius:8px;">
              <tr>
                <td style="font-size:11px; font-weight:bold; color:{sec_header_color}; border-bottom:1px solid {card_bdr}; padding-bottom:4px;">
                  📋 URL Anatomy & DNS Resolution
                </td>
              </tr>
              <tr>
                <td style="padding-top:6px;">
                  <table width="100%" cellspacing="0" cellpadding="2" style="font-size:10.5px; color:{text_color};">
                    <tr><td width="32%" style="color:{sub_color};">Scheme / Protocol:</td><td><b>{anatomy.get('scheme', '-')}</b> (Port {anatomy.get('port', '-')})</td></tr>
                    <tr><td style="color:{sub_color};">Registered Domain:</td><td style="color:{text_color};"><b>{anatomy.get('registered_domain', '-')}</b></td></tr>
                    <tr><td style="color:{sub_color};">Subdomains:</td><td>{anatomy.get('subdomains') or 'None'}</td></tr>
                    <tr><td style="color:{sub_color};">Path / Segments:</td><td style="font-family:monospace; word-break:break-all;">{anatomy.get('path', '/')}</td></tr>
                    <tr><td style="color:{sub_color};">Query Payload:</td><td style="font-family:monospace; word-break:break-all; color:{accent_color};">{anatomy.get('query') or 'None'}</td></tr>
                    <tr><td style="color:{sub_color};">Shannon Entropy:</td><td><b>{anatomy.get('entropy', 0.0)}</b> / 8.0</td></tr>
                    <tr><td style="color:{sub_color};">Resolved IP(s):</td><td style="font-family:monospace; color:{accent_color};">{', '.join(anatomy.get('resolved_ips', ['-']))}</td></tr>
                    <tr><td style="color:{sub_color};">Reverse DNS:</td><td style="font-family:monospace;">{anatomy.get('reverse_dns', '-')}</td></tr>
                  </table>
                </td>
              </tr>
            </table>
          </td></tr>
        """

        # Card 3: Triggered Heuristic Rules
        if rules:
            html += f"""
            <tr><td style="padding-bottom:8px;">
              <table width="100%" cellspacing="0" cellpadding="8" style="background-color:{card_bg}; border:1px solid {card_bdr}; border-radius:8px;">
                <tr>
                  <td style="font-size:11px; font-weight:bold; color:#ef4444; border-bottom:1px solid {card_bdr}; padding-bottom:4px;">
                    🚨 Triggered Security Heuristics ({len(rules)} Rules Flagged)
                  </td>
                </tr>
                <tr>
                  <td style="padding-top:6px;">
                    <table width="100%" cellspacing="0" cellpadding="3" style="font-size:10px; color:{text_color};">
            """
            for r in rules:
                pts = r.get("points", 0)
                r_id = r.get("id", "-")
                name = r.get("name", "-")
                evid = r.get("evidence", "-")
                mitre = r.get("mitre", "-")
                html += f"""
                <tr>
                  <td width="20%" valign="top" style="color:#ef4444; font-weight:bold; border-bottom:1px solid {row_bdr};">+{pts:.0f} pts</td>
                  <td style="border-bottom:1px solid {row_bdr};">
                    <b style="color:{text_color};">{name}</b> <span style="color:{sub_color}; font-size:9px;">[{r_id} &bull; MITRE {mitre}]</span><br>
                    <span style="color:{sub_color}; font-size:9.5px;">&bull; {evid}</span>
                  </td>
                </tr>
                """
            html += """
                    </table>
                  </td>
                </tr>
              </table>
            </td></tr>
            """

        # Card 4: SSL/TLS Certificate Analysis
        if ssl_info and ssl_info.get("status") != "Skipped":
            has_ssl = ssl_info.get("has_ssl", False)
            ssl_badge = "✅ Valid SSL" if has_ssl and not ssl_info.get("is_expired") else "⚠️ Insecure / Untrusted"
            ssl_col = "#10b981" if has_ssl and not ssl_info.get("is_self_signed") else "#ef4444"
            html += f"""
            <tr><td style="padding-bottom:8px;">
              <table width="100%" cellspacing="0" cellpadding="8" style="background-color:{card_bg}; border:1px solid {card_bdr}; border-radius:8px;">
                <tr>
                  <td style="font-size:11px; font-weight:bold; color:{sec_header_color}; border-bottom:1px solid {card_bdr}; padding-bottom:4px;">
                    🔒 SSL / TLS Certificate Security &bull; <span style="color:{ssl_col};">{ssl_badge}</span>
                  </td>
                </tr>
                <tr>
                  <td style="padding-top:6px;">
                    <table width="100%" cellspacing="0" cellpadding="2" style="font-size:10.5px; color:{text_color};">
                      <tr><td width="32%" style="color:{sub_color};">Subject (CN):</td><td style="font-family:monospace;">{ssl_info.get('subject', '-')}</td></tr>
                      <tr><td style="color:{sub_color};">Issuer (CA):</td><td>{ssl_info.get('issuer', '-')}</td></tr>
                      <tr><td style="color:{sub_color};">Days to Expiry:</td><td><b>{ssl_info.get('days_until_expiry', 0)} days</b> (Valid to: {ssl_info.get('valid_to', '-')})</td></tr>
                      <tr><td style="color:{sub_color};">Self-Signed:</td><td style="color:{'#ef4444' if ssl_info.get('is_self_signed') else '#10b981'};"><b>{'Yes (Untrusted)' if ssl_info.get('is_self_signed') else 'No (Trusted CA)'}</b></td></tr>
                      <tr><td style="color:{sub_color};">Wildcard Cert:</td><td>{'Yes (*)' if ssl_info.get('is_wildcard') else 'No'}</td></tr>
                    </table>
                  </td>
                </tr>
              </table>
            </td></tr>
            """

        # Card 5: HTTP Live Response & Security Headers
        if http_info:
            sec_headers = http_info.get("security_headers", {})
            missing = http_info.get("missing_headers", [])
            hdr_score = http_info.get("headers_score", 0)
            html += f"""
            <tr><td style="padding-bottom:8px;">
              <table width="100%" cellspacing="0" cellpadding="8" style="background-color:{card_bg}; border:1px solid {card_bdr}; border-radius:8px;">
                <tr>
                  <td style="font-size:11px; font-weight:bold; color:{sec_header_color}; border-bottom:1px solid {card_bdr}; padding-bottom:4px;">
                    📡 HTTP Live Response & Security Headers Audit
                  </td>
                </tr>
                <tr>
                  <td style="padding-top:6px;">
                    <table width="100%" cellspacing="0" cellpadding="2" style="font-size:10.5px; color:{text_color};">
                      <tr><td width="32%" style="color:{sub_color};">HTTP Status:</td><td><b>{http_info.get('status_code', '-')}</b> &bull; Server: <b>{http_info.get('server', '-')}</b></td></tr>
                      <tr><td style="color:{sub_color};">Network Latency:</td><td>{http_info.get('latency_ms', 0)} ms</td></tr>
                      <tr><td style="color:{sub_color};">Headers Hardening:</td><td><b>{hdr_score:.0f}%</b> configured</td></tr>
                      <tr><td style="color:{sub_color};">Active Headers:</td><td style="color:#10b981;">{', '.join(sec_headers.keys()) or 'None'}</td></tr>
                      <tr><td style="color:{sub_color};">Missing Headers:</td><td style="color:#f59e0b;">{', '.join(missing) or 'None'}</td></tr>
                    </table>
                  </td>
                </tr>
              </table>
            </td></tr>
            """

        # Card 6: DOM & Page Content Intelligence
        if content_info:
            has_login = content_info.get("has_login_form", False)
            html += f"""
            <tr><td style="padding-bottom:8px;">
              <table width="100%" cellspacing="0" cellpadding="8" style="background-color:{card_bg}; border:1px solid {card_bdr}; border-radius:8px;">
                <tr>
                  <td style="font-size:11px; font-weight:bold; color:{sec_header_color}; border-bottom:1px solid {card_bdr}; padding-bottom:4px;">
                    📄 DOM & Page Content Intelligence
                  </td>
                </tr>
                <tr>
                  <td style="padding-top:6px;">
                    <table width="100%" cellspacing="0" cellpadding="2" style="font-size:10.5px; color:{text_color};">
                      <tr><td width="32%" style="color:{sub_color};">Page Title:</td><td><b>{content_info.get('page_title', '-')}</b></td></tr>
                      <tr><td style="color:{sub_color};">Login / Forms:</td><td>{'⚠️ Active Login Form' if has_login else 'No Password Inputs'} ({content_info.get('forms_count', 0)} forms)</td></tr>
                      <tr><td style="color:{sub_color};">Password Inputs:</td><td style="color:{'#ef4444' if content_info.get('password_inputs', 0) > 0 else text_color};"><b>{content_info.get('password_inputs', 0)}</b></td></tr>
                      <tr><td style="color:{sub_color};">Hidden Iframes:</td><td>{content_info.get('hidden_iframes', 0)}</td></tr>
                      <tr><td style="color:{sub_color};">External Scripts:</td><td>{content_info.get('external_scripts', 0)} scripts</td></tr>
                    </table>
                  </td>
                </tr>
              </table>
            </td></tr>
            """

        # Card 7: Redirect Chain Trajectory
        if redirects:
            html += f"""
            <tr><td style="padding-bottom:8px;">
              <table width="100%" cellspacing="0" cellpadding="8" style="background-color:{card_bg}; border:1px solid {card_bdr}; border-radius:8px;">
                <tr>
                  <td style="font-size:11px; font-weight:bold; color:{sec_header_color}; border-bottom:1px solid {card_bdr}; padding-bottom:4px;">
                    🔗 Redirect Chain Trajectory ({len(redirects)} Hops)
                  </td>
                </tr>
                <tr>
                  <td style="padding-top:6px;">
                    <table width="100%" cellspacing="0" cellpadding="2" style="font-size:10px; font-family:monospace; color:{text_color};">
            """
            for hop in redirects:
                html += f"""
                <tr>
                  <td width="18%" style="color:{sub_color};">Hop {hop.get('hop')}:</td>
                  <td width="22%" style="color:#0ea5e9;">HTTP {hop.get('status')}</td>
                  <td style="color:{text_color}; word-break:break-all;">{hop.get('url')}</td>
                </tr>
                """
            html += """
                    </table>
                  </td>
                </tr>
              </table>
            </td></tr>
            """

        # Card 8: Machine Learning Inference Details
        if ml_res:
            html += f"""
            <tr><td style="padding-bottom:8px;">
              <table width="100%" cellspacing="0" cellpadding="8" style="background-color:{card_bg}; border:1px solid {card_bdr}; border-radius:8px;">
                <tr>
                  <td style="font-size:11px; font-weight:bold; color:{sec_header_color}; border-bottom:1px solid {card_bdr}; padding-bottom:4px;">
                    🤖 Machine Learning Model Inference
                  </td>
                </tr>
                <tr>
                  <td style="padding-top:6px;">
                    <table width="100%" cellspacing="0" cellpadding="2" style="font-size:10.5px; color:{text_color};">
                      <tr><td width="32%" style="color:{sub_color};">Model Status:</td><td><b>{'Loaded & Active' if ml_res.get('ml_enabled') else 'Offline'}</b></td></tr>
                      <tr><td style="color:{sub_color};">Predicted Class:</td><td style="color:{accent_color};"><b>{ml_res.get('ml_decision', '-')}</b></td></tr>
                      <tr><td style="color:{sub_color};">Threat Probability:</td><td><b>{ml_res.get('ml_score', 0.0):.1f}%</b></td></tr>
                      <tr><td style="color:{sub_color};">Confidence Level:</td><td>{ml_res.get('ml_confidence', 0.0):.1f}%</td></tr>
                    </table>
                  </td>
                </tr>
              </table>
            </td></tr>
            """

        html += "</table>"
        return html

    # --- Actions inside Dossier ---
    def rescan_current_url(self):
        url = self.current_dossier_data.get("url")
        if url:
            self.url_input.setText(url)
            self.start_scan()

    def copy_current_url(self):
        url = self.current_dossier_data.get("url")
        if url:
            QApplication.clipboard().setText(url)
            self.lbl_status.setText("Target URL copied to clipboard.")

    def delete_current_dossier(self):
        scan_id = self.current_dossier_data.get("id")
        if not scan_id:
            return
        reply = QMessageBox.question(self, "Confirm Delete", "Delete this scan record permanently?",
                                     QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if reply == QMessageBox.StandardButton.Yes:
            self.db.delete_phishing_scans([scan_id])
            self.selected_scan_ids.discard(scan_id)
            self.dossier_panel.hide()
            self.refresh_data()

    # --- Checkbox Selection & Batch Deletion ---
    def on_checkbox_changed(self, scan_id: int, state: int):
        if state == 2:  # Checked
            self.selected_scan_ids.add(scan_id)
        else:
            self.selected_scan_ids.discard(scan_id)
        self.btn_delete_selected.setEnabled(len(self.selected_scan_ids) > 0)
        self.btn_delete_selected.setText(f"🗑️ Delete Selected ({len(self.selected_scan_ids)})")

    def toggle_select_all(self):
        all_ids = {s.get("id") for s in self.current_scans if s.get("id")}
        if self.selected_scan_ids == all_ids and len(all_ids) > 0:
            self.selected_scan_ids.clear()
            self.btn_select_all.setText("☑ Select All")
        else:
            self.selected_scan_ids = set(all_ids)
            self.btn_select_all.setText("☐ Deselect All")

        self.btn_delete_selected.setEnabled(len(self.selected_scan_ids) > 0)
        self.btn_delete_selected.setText(f"🗑️ Delete Selected ({len(self.selected_scan_ids)})")
        self.populate_table(self.current_scans)

    def delete_selected_records(self):
        if not self.selected_scan_ids:
            return
        count = len(self.selected_scan_ids)
        reply = QMessageBox.question(self, "Confirm Delete", f"Delete {count} selected scan records permanently?",
                                     QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if reply == QMessageBox.StandardButton.Yes:
            self.db.delete_phishing_scans(list(self.selected_scan_ids))
            self.selected_scan_ids.clear()
            self.btn_delete_selected.setEnabled(False)
            self.btn_delete_selected.setText("🗑️ Delete Selected")
            self.dossier_panel.hide()
            self.refresh_data()

    def clear_all_history(self):
        reply = QMessageBox.question(self, "Confirm Purge", "Purge all historical phishing scans and dossiers permanently?",
                                     QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if reply == QMessageBox.StandardButton.Yes:
            self.db.clear_phishing_history()
            self.selected_scan_ids.clear()
            self.dossier_panel.hide()
            self.refresh_data()

    # --- Filtering ---
    def on_search_changed(self, text: str):
        self.search_filter = text.strip()
        self.refresh_data()

    def on_threat_filter_changed(self, text: str):
        self.threat_filter = text
        self.refresh_data()

    def on_chart_filter_requested(self, level: str):
        idx = self.combo_threat.findText(level)
        if idx >= 0:
            self.combo_threat.setCurrentIndex(idx)

    # --- Context Menu ---
    def show_context_menu(self, pos):
        item = self.table.itemAt(pos)
        if not item:
            return
        row = item.row()
        scan = self.current_scans[row] if row < len(self.current_scans) else None
        if not scan:
            return

        from PyQt6.QtWidgets import QMenu
        menu = QMenu(self)
        action_inspect = menu.addAction("🔬 Inspect Forensic Dossier")
        action_rescan = menu.addAction("🔄 Re-Scan URL")
        action_copy = menu.addAction("📋 Copy URL")
        menu.addSeparator()
        action_del = menu.addAction("🗑️ Delete Record")

        act = menu.exec(self.table.viewport().mapToGlobal(pos))
        if act == action_inspect:
            full_data = self.db.get_phishing_scan_detail(scan.get("id"))
            self.display_dossier(full_data or scan)
        elif act == action_rescan:
            self.url_input.setText(scan.get("url"))
            self.start_scan()
        elif act == action_copy:
            QApplication.clipboard().setText(scan.get("url", ""))
        elif act == action_del:
            self.db.delete_phishing_scans([scan.get("id")])
            self.refresh_data()

    # --- Export PDF to FMS Vault ---
    def vault_current_dossier_pdf(self):
        """Generates executive forensic PDF for the currently open dossier and vaults in FMS."""
        data = self.current_dossier_data
        if not data:
            QMessageBox.warning(self, "No Data", "Please select a scan to generate a dossier.")
            return

        import tempfile
        try:
            temp_fd, temp_path = tempfile.mkstemp(suffix=".pdf")
            os.close(temp_fd)

            printer = QPrinter(QPrinter.PrinterMode.HighResolution)
            printer.setOutputFormat(QPrinter.OutputFormat.PdfFormat)
            printer.setOutputFileName(temp_path)
            printer.setPageSize(QPageSize(QPageSize.PageSizeId.A4))

            url = data.get("url", "-")
            score = data.get("score", 0.0)
            threat_level = data.get("threat_level", "Safe")
            timestamp = data.get("timestamp", "-")
            details = data.get("details", {})
            rules = details.get("rules_triggered", [])
            anatomy = details.get("anatomy", {})

            pdf_html = f"""<!DOCTYPE html>
            <html>
            <head>
              <meta charset="utf-8">
              <style>
                body {{ font-family: 'Segoe UI', Arial, sans-serif; font-size: 9pt; color: #1e293b; line-height: 1.4; }}
                h1 {{ font-size: 15pt; color: #0284c7; margin: 0 0 4px 0; }}
                .hdr {{ border-bottom: 2px solid #0284c7; padding-bottom: 6px; margin-bottom: 10px; }}
                .card {{ border: 1px solid #cbd5e1; background-color: #f8fafc; padding: 8px; margin-bottom: 8px; }}
                .tag {{ font-weight: bold; font-size: 11pt; color: {'#b91c1c' if score >= 80 else ('#b45309' if score >= 60 else '#15803d')}; }}
                table {{ width: 100%; border-collapse: collapse; font-size: 8.5pt; margin-bottom: 6px; }}
                td {{ padding: 3px 4px; border-bottom: 1px solid #e2e8f0; }}
                .sec-title {{ font-size: 10pt; font-weight: bold; color: #0f172a; margin-top: 10px; margin-bottom: 4px; border-bottom: 1px solid #0284c7; padding-bottom: 2px; }}
              </style>
            </head>
            <body>
              <div class="hdr">
                <h1>NexaShield Phishing Intelligence & Forensic Dossier</h1>
                <div style="font-size: 8pt; color: #64748b;">Zero-Trust Cyber Defense &bull; Machine Learning Assisted Analysis &bull; Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</div>
              </div>

              <div class="card">
                <table width="100%">
                  <tr>
                    <td><b>Target URL:</b> {url}</td>
                    <td align="right"><span class="tag">AI THREAT: {threat_level.upper()} ({score:.1f}%)</span></td>
                  </tr>
                  <tr>
                    <td colspan="2" style="font-size:8pt; color:#475569;">Registered Domain: <b>{anatomy.get('registered_domain', '-')}</b> &bull; Primary IP: <b>{anatomy.get('primary_ip', '-')}</b> &bull; Scanned: <b>{timestamp}</b></td>
                  </tr>
                </table>
              </div>

              <div class="sec-title">📋 URL Anatomy & Infrastructure</div>
              <table>
                <tr><td width="25%"><b>Scheme & Port:</b></td><td>{anatomy.get('scheme', '-')} (Port {anatomy.get('port', '-')})</td><td width="25%"><b>Shannon Entropy:</b></td><td>{anatomy.get('entropy', 0.0)} / 8.0</td></tr>
                <tr><td><b>Host & Domain:</b></td><td>{anatomy.get('hostname', '-')}</td><td><b>Reverse DNS:</b></td><td>{anatomy.get('reverse_dns', '-')}</td></tr>
                <tr><td><b>Path:</b></td><td colspan="3">{anatomy.get('path', '/')}</td></tr>
                <tr><td><b>Query String:</b></td><td colspan="3">{anatomy.get('query') or 'None'}</td></tr>
              </table>

              <div class="sec-title">🚨 Triggered Security Heuristics ({len(rules)} Rules)</div>
              <table>
                <thead>
                  <tr style="background:#f1f5f9;"><th>ID</th><th>Heuristic Rule</th><th>Points</th><th>Evidence</th><th>MITRE ATT&CK</th></tr>
                </thead>
                <tbody>
            """
            for r in rules:
                pdf_html += f"""
                <tr>
                  <td><b>{r.get('id')}</b></td>
                  <td>{r.get('name')}</td>
                  <td>+{r.get('points', 0):.0f}</td>
                  <td>{r.get('evidence')}</td>
                  <td>{r.get('mitre')}</td>
                </tr>
                """
            pdf_html += """
                </tbody>
              </table>

              <div style="margin-top: 15px; border-top: 1px solid #cbd5e1; padding-top: 4px; text-align: center; font-size: 7.5pt; color: #94a3b8;">
                NexaShield Threat Intelligence System &bull; Cryptographically Verified Forensic Dossier
              </div>
            </body>
            </html>
            """

            doc = QTextDocument()
            doc.setHtml(pdf_html)
            doc.print(printer)

            with open(temp_path, "rb") as f:
                pdf_bytes = f.read()
            os.remove(temp_path)

            if self.session and hasattr(self.session, "file_manager"):
                safe_host = re.sub(r'[^a-zA-Z0-9_\-]', '', anatomy.get('hostname', 'url')) or 'scan'
                filename = f"phishing_dossier_{safe_host}_{int(score)}.pdf"
                self.session.file_manager.export_file(
                    filename=filename,
                    content=pdf_bytes,
                    module_source="Phishing Detector",
                    file_type="PDF",
                    tags="Warning" if score >= 60 else "Info"
                )
                self.lbl_status.setText(f"Dossier {filename} securely vaulted in FMS.")
                QMessageBox.information(self, "Vaulted in FMS", f"Forensic dossier securely vaulted in NexaShield FMS:\n{filename}")
            else:
                QMessageBox.warning(self, "FMS Unavailable", "Session File Manager is not active.")

        except Exception as e:
            QMessageBox.critical(self, "PDF Generation Error", f"Failed to generate forensic dossier: {e}")

    # --- Full History PDF Export ---
    def export_history_pdf(self):
        import tempfile
        try:
            temp_fd, temp_path = tempfile.mkstemp(suffix=".pdf")
            os.close(temp_fd)

            printer = QPrinter(QPrinter.PrinterMode.HighResolution)
            printer.setOutputFormat(QPrinter.OutputFormat.PdfFormat)
            printer.setOutputFileName(temp_path)
            printer.setPageSize(QPageSize(QPageSize.PageSizeId.A4))

            scans = self.current_scans
            stats = self.db.get_phishing_stats()

            html = f"""<!DOCTYPE html>
            <html>
            <head>
              <meta charset="utf-8">
              <style>
                body {{ font-family: 'Segoe UI', Arial, sans-serif; font-size: 8.5pt; color: #1e293b; line-height: 1.35; }}
                h1 {{ font-size: 14pt; color: #0284c7; margin: 0 0 4px 0; }}
                table {{ width: 100%; border-collapse: collapse; font-size: 8pt; margin-top: 8px; }}
                th {{ background-color: #f1f5f9; padding: 4px; text-align: left; border: 1px solid #cbd5e1; }}
                td {{ padding: 3px 4px; border: 1px solid #e2e8f0; }}
              </style>
            </head>
            <body>
              <h1>NexaShield Phishing Threat Scan History</h1>
              <div style="font-size: 8pt; color: #64748b; margin-bottom: 8px;">
                Total Scans: <b>{stats.get('Total')}</b> &bull; High Risk: <b>{stats.get('High Risk')}</b> &bull; Safe: <b>{stats.get('Safe')}</b> &bull; Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}
              </div>
              <table>
                <thead>
                  <tr><th>Time</th><th>Target URL</th><th>Domain</th><th>Threat Level</th><th>Score</th><th>Method</th><th>Resolved IP</th></tr>
                </thead>
                <tbody>
            """
            for s in scans:
                score = s.get("score", 0.0)
                level = s.get("threat_level", "Safe")
                color = "#b91c1c" if score >= 80 else ("#b45309" if score >= 60 else "#15803d")
                html += f"""
                <tr>
                  <td>{s.get('timestamp', '-')}</td>
                  <td style="word-break:break-all;">{s.get('url', '-')}</td>
                  <td>{s.get('domain', '-')}</td>
                  <td style="color:{color}; font-weight:bold;">{level}</td>
                  <td>{score:.1f}</td>
                  <td>{s.get('method', '-')}</td>
                  <td>{s.get('resolved_ip', '-')}</td>
                </tr>
                """
            html += "</tbody></table></body></html>"

            doc = QTextDocument()
            doc.setHtml(html)
            doc.print(printer)

            with open(temp_path, "rb") as f:
                pdf_bytes = f.read()
            os.remove(temp_path)

            if self.session and hasattr(self.session, "file_manager"):
                self.session.file_manager.export_file(
                    filename="phishing_threat_history.pdf",
                    content=pdf_bytes,
                    module_source="Phishing Detector",
                    file_type="PDF",
                    tags="Audit"
                )
                self.lbl_status.setText("Scan history PDF securely vaulted in FMS.")
                QMessageBox.information(self, "Vaulted in FMS", "Phishing History PDF securely vaulted in FMS.")
            else:
                QMessageBox.warning(self, "Warning", "FMS session not active.")

        except Exception as e:
            QMessageBox.critical(self, "Export Error", f"Export failed: {e}")

    # --- CSV Export ---
    def export_history_csv(self):
        path, _ = QFileDialog.getSaveFileName(self, "Export Scan History CSV", "phishing_scans.csv", "CSV Files (*.csv)")
        if not path:
            return

        try:
            import csv
            with open(path, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["ID", "Timestamp", "URL", "Threat Level", "Score", "Heuristic Score", "ML Score", "Method", "Domain", "Resolved IP"])
                for s in self.current_scans:
                    writer.writerow([
                        s.get("id"),
                        s.get("timestamp"),
                        s.get("url"),
                        s.get("threat_level"),
                        s.get("score"),
                        s.get("heuristic_score"),
                        s.get("ml_score"),
                        s.get("method"),
                        s.get("domain"),
                        s.get("resolved_ip")
                    ])
            self.lbl_status.setText(f"Exported {len(self.current_scans)} scans to CSV.")
            QMessageBox.information(self, "Export Complete", f"Successfully exported {len(self.current_scans)} records to:\n{path}")
        except Exception as e:
            QMessageBox.critical(self, "Export Error", f"Failed to export CSV: {e}")
