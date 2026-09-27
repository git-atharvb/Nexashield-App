import os
import psutil
import sqlite3
import socket
import platform
import csv
import json
import math
import re
import datetime
import subprocess
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QFrame, QMenu, QApplication,
    QTableWidget, QTableWidgetItem, QHeaderView, QAbstractItemView, QGroupBox, QToolTip,
    QLineEdit, QComboBox, QPushButton, QFileDialog, QMessageBox, QDialog, QFormLayout, QCheckBox, QTextEdit
)
from PyQt6.QtCore import Qt, QTimer, QRectF, QThread, pyqtSignal
from PyQt6.QtGui import QColor, QBrush, QPainter, QPen, QFont, QPalette, QPainterPath, QLinearGradient, QTextDocument
from PyQt6.QtPrintSupport import QPrinter

class SyslogDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Configure Syslog Forwarding")
        self.setMinimumSize(350, 180)
        
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(25, 25, 25, 25)
        main_layout.setSpacing(15)
        
        # Header
        header = QLabel("📡 Syslog Configuration")
        header.setStyleSheet("font-size: 16px; font-weight: bold; color: #0078d7;")
        main_layout.addWidget(header)
        
        # Form Layout
        form_layout = QFormLayout()
        form_layout.setSpacing(15)
        
        self.ip_input = QLineEdit("127.0.0.1")
        self.ip_input.setMinimumHeight(32)
        self.port_input = QLineEdit("514")
        self.port_input.setMinimumHeight(32)
        
        form_layout.addRow(QLabel("Syslog IP:"), self.ip_input)
        form_layout.addRow(QLabel("Syslog Port:"), self.port_input)
        main_layout.addLayout(form_layout)
        
        main_layout.addStretch()
        
        self.btn_start = QPushButton("🚀 Send Logs")
        self.btn_start.setMinimumHeight(35)
        self.btn_start.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_start.setObjectName("BtnPrimary")
        self.btn_start.clicked.connect(self.accept)
        main_layout.addWidget(self.btn_start)

class ThreatDonutChart(QWidget):
    def __init__(self):
        super().__init__()
        self.setMinimumSize(150, 150)
        self.stats = {"Safe": 0, "Warning": 0, "Critical": 0}
        self.setMouseTracking(True)

    def update_stats(self, stats):
        self.stats = stats
        self.update()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        w, h = self.width(), self.height()
        
        painter.fillRect(0, 0, w, h, self.palette().color(QPalette.ColorRole.Window))
        
        total = sum(self.stats.values())
        if total == 0: return

        colors = {"Safe": "#28a745", "Warning": "#ffc107", "Critical": "#dc3545"}
        
        top_pad = 10
        size = min(w, h - top_pad) - 20
        rect = QRectF((w - size) / 2, top_pad + 10, size, size)
        
        # Subtle Drop Shadow Effect for whole pie area
        shadow_rect = rect.translated(0, 4)
        painter.setBrush(QColor(0, 0, 0, 40))
        painter.setPen(Qt.PenStyle.NoPen)
        painter.drawEllipse(shadow_rect)
        
        start_angle = 90 * 16
        
        for label, count in self.stats.items():
            if count > 0:
                span = int((count / total) * 360 * 16)
                
                # Draw main slice with rounded caps
                pen = QPen(QColor(colors.get(label, "#888")), 14, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap)
                painter.setPen(pen)
                painter.setBrush(Qt.BrushStyle.NoBrush)
                
                # Adjust rect to account for pen width
                arc_rect = rect.adjusted(7, 7, -7, -7)
                painter.drawArc(arc_rect, start_angle, span)
                
                start_angle += span
                
        text_col = self.palette().color(QPalette.ColorRole.WindowText)
        painter.setPen(text_col)
        painter.setFont(QFont("Segoe UI", 12, QFont.Weight.Bold))
        painter.drawText(rect, Qt.AlignmentFlag.AlignCenter, f"Total\n{total}")

    def mouseMoveEvent(self, event):
        total = sum(self.stats.values())
        if total == 0: return super().mouseMoveEvent(event)
            
        pos = event.pos()
        w, h = self.width(), self.height()
        top_pad = 10
        size = min(w, h - top_pad) - 20
        rect = QRectF((w - size) / 2, top_pad + 10, size, size)
        
        center = rect.center()
        dx = pos.x() - center.x()
        dy = pos.y() - center.y()
        distance = math.hypot(dx, dy)
        
        inner_radius = (size / 2) - 14
        outer_radius = (size / 2) + 7
        
        if inner_radius <= distance <= outer_radius:
            angle = math.degrees(math.atan2(-dy, dx))
            if angle < 0: angle += 360
            mapped_angle = (angle - 90) % 360
            
            current_span = 0
            for label, count in self.stats.items():
                if count > 0:
                    span = (count / total) * 360
                    if current_span <= mapped_angle <= current_span + span:
                        QToolTip.showText(event.globalPosition().toPoint(), f"{label}\nEvents: {count}\nShare: {(count/total)*100:.1f}%", self)
                        return
                    current_span += span
                    
        QToolTip.hideText()
        super().mouseMoveEvent(event)

class EventInspectorDialog(QDialog):
    def __init__(self, parent, db_info, basic_info):
        super().__init__(parent)
        self.setWindowTitle("Detailed Event Inspector")
        self.setMinimumSize(600, 450)
        
        layout = QVBoxLayout(self)
        
        header = QLabel(f"🔍 Event Details: {basic_info['source']}")
        header.setStyleSheet("font-size: 16px; font-weight: bold; color: #0078d7;")
        layout.addWidget(header)
        
        form_group = QGroupBox("General Information")
        form_layout = QFormLayout(form_group)
        form_layout.addRow("🕒 Time:", QLabel(basic_info['time']))
        
        sev_lbl = QLabel(basic_info['severity'])
        if basic_info['severity'] in ["Critical", "High", "High Risk"]:
            sev_lbl.setStyleSheet("color: #dc3545; font-weight: bold;")
        elif basic_info['severity'] in ["Medium", "Medium Risk", "Warning"]:
            sev_lbl.setStyleSheet("color: #ffc107; font-weight: bold;")
        else:
            sev_lbl.setStyleSheet("color: #28a745; font-weight: bold;")
            
        form_layout.addRow("⚠️ Severity:", sev_lbl)
        form_layout.addRow("📝 Description:", QLabel(basic_info['desc']))
        layout.addWidget(form_group)
        
        self.raw_text = QTextEdit()
        self.raw_text.setReadOnly(True)
        self.raw_text.setFontFamily("Courier New")
        layout.addWidget(QLabel("Raw Database Payload:"))
        layout.addWidget(self.raw_text)
        
        btn_close = QPushButton("Close")
        btn_close.clicked.connect(self.accept)
        layout.addWidget(btn_close, alignment=Qt.AlignmentFlag.AlignRight)
        
        self.load_db_info(db_info)

    def load_db_info(self, db_info):
        if not db_info:
            self.raw_text.setPlainText("No extended database record available for this event.")
            return
            
        table_name, record_id, db_path = db_info
        try:
            conn = sqlite3.connect(db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute(f"SELECT * FROM {table_name} WHERE id = ?", (record_id,))
            row = cursor.fetchone()
            conn.close()
            
            if row:
                details = dict(row)
                for k, v in details.items():
                    if isinstance(v, str) and (v.startswith('{') or v.startswith('[')):
                        try:
                            details[k] = json.loads(v)
                        except: pass
                self.raw_text.setPlainText(json.dumps(details, indent=4))
            else:
                self.raw_text.setPlainText("Record not found in database. It may have been deleted.")
        except Exception as e:
            self.raw_text.setPlainText(f"Error fetching details from database: {e}")

class OverviewWorker(QThread):
    """Background worker to fetch telemetry without freezing the GUI."""
    data_fetched = pyqtSignal(dict)

    def __init__(self, fetch_db=False, db_path="nexashield.db"):
        super().__init__()
        self.fetch_db = fetch_db
        self.db_path = db_path

    def run(self):
        data = {}
        data['cpu'] = psutil.cpu_percent()
        data['ram'] = psutil.virtual_memory().percent
        try:
            data['disk'] = psutil.disk_usage(os.path.abspath(os.sep)).percent
        except Exception:
            data['disk'] = 0.0
            
        try:
            io = psutil.net_io_counters()
            data['net_bytes'] = io.bytes_recv + io.bytes_sent
        except Exception:
            data['net_bytes'] = 0
            
        net_up = False
        try:
            stats = psutil.net_if_stats()
            for name, stat in stats.items():
                if stat.isup and name != "lo" and "Loopback" not in name:
                    net_up = True
                    break
        except Exception:
            pass
        data['net_up'] = net_up
        
        events = []
        if self.fetch_db:
            try:
                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()
                
                # Check existing tables to prevent failure on fresh installs
                cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
                tables = [r[0] for r in cursor.fetchall()]
                
                queries = []
                if 'phishing_history' in tables:
                    queries.append("SELECT id, timestamp, 'Phishing Detection' as source, url as description, threat_level as severity, 'phishing_history' as table_name FROM phishing_history")
                if 'scan_history' in tables:
                    queries.append("SELECT id, timestamp, 'Antivirus' as source, scan_type || ' Scan Completed - ' || threats_found || ' threat(s) found' as description, CASE WHEN threats_found > 0 THEN 'Critical' ELSE 'Safe' END as severity, 'scan_history' as table_name FROM scan_history")
                if 'siem_events' in tables:
                    queries.append("SELECT id, timestamp, source, description, severity, 'siem_events' as table_name FROM siem_events")
                    
                if queries:
                    full_query = " UNION ALL ".join(queries) + " ORDER BY timestamp DESC LIMIT 50"
                    cursor.execute(full_query)
                    for row in cursor.fetchall():
                        events.append((row[1], row[2], row[3], row[4], (row[5], row[0], self.db_path)))
                        
                conn.close()
            except Exception:
                pass
                
            # Calculate Unified Security Score
            score = 100
            if data['cpu'] > 85: score -= 10
            if data['ram'] > 85: score -= 10
            if data['disk'] > 90: score -= 10
            if not data['net_up']: score -= 20
            
            critical_count = sum(1 for e in events if e[3] in ["Critical", "High", "High Risk"])
            medium_count = sum(1 for e in events if e[3] in ["Medium", "Medium Risk", "Warning"])
            score -= (critical_count * 5) + (medium_count * 2)
            
            data['security_score'] = max(0, min(100, int(score)))
            data['events'] = events
            
        self.data_fetched.emit(data)

class OverviewBarChart(QWidget):
    """Draws a real-time smooth area chart for telemetry visualization."""
    def __init__(self, title, color="#28a745"):
        super().__init__()
        self.title = title
        self.primary_color = QColor(color)
        self.data = [0.0] * 40
        self.setMinimumHeight(160)

    def update_value(self, percent):
        self.data.pop(0)
        self.data.append(percent)
        self.update()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        w, h = self.width(), self.height()
        
        # Title and Current Value
        text_color = self.palette().color(QPalette.ColorRole.WindowText)
        painter.setPen(text_color)
        painter.setFont(QFont("Segoe UI", 11, QFont.Weight.Bold))
        painter.drawText(10, 25, f"{self.title}")
        
        painter.setPen(self.primary_color)
        painter.setFont(QFont("Segoe UI", 14, QFont.Weight.Bold))
        painter.drawText(w - 80, 25, 70, 25, Qt.AlignmentFlag.AlignRight, f"{self.data[-1]:.1f}%")

        # Grid lines
        top_pad = 40
        chart_h = h - top_pad - 10
        grid_col = QColor(128, 128, 128, 40)
        painter.setPen(QPen(grid_col, 1, Qt.PenStyle.DashLine))
        for i in range(3):
            y_line = top_pad + i * (chart_h / 2)
            painter.drawLine(10, int(y_line), w - 10, int(y_line))
            
        # Draw Smooth Area Chart
        if not self.data: return
        
        path = QPainterPath()
        step_x = (w - 20) / (len(self.data) - 1)
        
        # Start at bottom left
        path.moveTo(10, h - 10)
        
        # First point
        first_y = h - 10 - (self.data[0] / 100.0) * chart_h
        path.lineTo(10, first_y)
        
        for i in range(1, len(self.data)):
            x = 10 + i * step_x
            y = h - 10 - (self.data[i] / 100.0) * chart_h
            
            # Smooth cubic bezier curve
            prev_x = 10 + (i - 1) * step_x
            prev_y = h - 10 - (self.data[i-1] / 100.0) * chart_h
            
            cp1_x = prev_x + (x - prev_x) / 2
            cp1_y = prev_y
            cp2_x = cp1_x
            cp2_y = y
            
            path.cubicTo(cp1_x, cp1_y, cp2_x, cp2_y, x, y)
            
        # Complete path back to bottom right
        path.lineTo(w - 10, h - 10)
        path.closeSubpath()
        
        # Gradient Fill
        grad = QLinearGradient(0, top_pad, 0, h - 10)
        c = self.primary_color
        grad.setColorAt(0, QColor(c.red(), c.green(), c.blue(), 120))
        grad.setColorAt(1, QColor(c.red(), c.green(), c.blue(), 10))
        
        painter.setBrush(grad)
        painter.setPen(Qt.PenStyle.NoPen)
        painter.drawPath(path)
        
        # Draw top glow line (stroke only)
        stroke_path = QPainterPath()
        stroke_path.moveTo(10, first_y)
        for i in range(1, len(self.data)):
            x = 10 + i * step_x
            y = h - 10 - (self.data[i] / 100.0) * chart_h
            prev_x = 10 + (i - 1) * step_x
            prev_y = h - 10 - (self.data[i-1] / 100.0) * chart_h
            cp1_x = prev_x + (x - prev_x) / 2
            cp1_y = prev_y
            cp2_x = cp1_x
            cp2_y = y
            stroke_path.cubicTo(cp1_x, cp1_y, cp2_x, cp2_y, x, y)
            
        pen = QPen(self.primary_color, 2.5)
        pen.setJoinStyle(Qt.PenJoinStyle.RoundJoin)
        pen.setCapStyle(Qt.PenCapStyle.RoundCap)
        painter.setPen(pen)
        painter.setBrush(Qt.BrushStyle.NoBrush)
        painter.drawPath(stroke_path)

class OverviewWidget(QWidget):
    def __init__(self, session_manager=None):
        super().__init__()
        self.session = session_manager
        self._tick_count = 0
        self._last_events = None
        self.setup_ui()
        
        # Timer for real-time updates
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.update_dashboard)

    def setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(20)

        # 1. Header & Quick Status
        header_layout = QHBoxLayout()
        header = QLabel("⚡ Dashboard & Live Telemetry")
        header.setStyleSheet("font-size: 26px; font-weight: 800; color: #0078d7; letter-spacing: 1px;")
        header_layout.addWidget(header)
        
        header_layout.addStretch()
        
        # System Specs small badge
        sys_info = f"{platform.system()} {platform.release()} ({platform.machine()})"
        host_badge = QLabel(f"🖥️ {socket.gethostname()}  |  {sys_info}")
        host_badge.setStyleSheet("padding: 8px 15px; border-radius: 6px; font-weight: bold;")
        header_layout.addWidget(host_badge)
        
        layout.addLayout(header_layout)

        # 2. Histograms Row
        hist_frame = QFrame()
        hist_frame.setObjectName("CardContainer")
        hist_layout = QHBoxLayout(hist_frame)
        hist_layout.setContentsMargins(15, 15, 15, 15)
        hist_layout.setSpacing(15)
        
        self.cpu_hist = OverviewBarChart("CPU Utilization", "#0078d7")
        self.ram_hist = OverviewBarChart("Memory Usage", "#ffc107")
        self.disk_hist = OverviewBarChart("Storage I/O", "#dc3545")
        self.net_hist = OverviewBarChart("Network I/O", "#17a2b8")
        
        hist_layout.addWidget(self.cpu_hist)
        hist_layout.addWidget(self.ram_hist)
        hist_layout.addWidget(self.disk_hist)
        hist_layout.addWidget(self.net_hist)
        
        layout.addWidget(hist_frame, 2) # Give charts more vertical space

        # 3. Bottom Row: Health Modules & Recent Events
        bottom_layout = QHBoxLayout()
        bottom_layout.setSpacing(20)

        # Left: Device Health Checklist
        health_frame = QFrame()
        health_frame.setObjectName("CardContainer")
        health_layout = QVBoxLayout(health_frame)
        health_layout.setContentsMargins(15, 15, 15, 15)
        
        title_health = QLabel("🛡️ Protection Status")
        title_health.setStyleSheet("font-size: 16px; font-weight: bold; background: transparent;")
        health_layout.addWidget(title_health)
        health_layout.addSpacing(10)
        
        self.lbl_score = QLabel("🏆 Security Score: Calculating...")
        self.lbl_score.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.lbl_score.setStyleSheet("font-size: 24px; font-weight: 800; color: #0078d7; background: transparent; margin-top: 10px; margin-bottom: 5px;")
        health_layout.addWidget(self.lbl_score)
        
        donut_layout = QHBoxLayout()
        self.threat_donut = ThreatDonutChart()
        donut_layout.addWidget(self.threat_donut)
        health_layout.addLayout(donut_layout)
        
        health_layout.addSpacing(15)
        self.lbl_cpu_stat = self.create_dynamic_status_row(health_layout, "🧠 CPU Thermals & Load")
        self.lbl_ram_stat = self.create_dynamic_status_row(health_layout, "💾 Memory Integrity")
        self.lbl_disk_stat = self.create_dynamic_status_row(health_layout, "💽 Disk Health (S.M.A.R.T)")
        self.lbl_net_stat = self.create_dynamic_status_row(health_layout, "🌐 Secure Network Tunnel")
        
        health_layout.addStretch()
        bottom_layout.addWidget(health_frame, 1)

        # Right: Security Events Table
        events_frame = QFrame()
        events_frame.setObjectName("CardContainer")
        events_layout = QVBoxLayout(events_frame)
        events_layout.setContentsMargins(15, 15, 15, 15)
        
        title_events = QLabel("🚨 Real-Time Security Feed")
        title_events.setStyleSheet("font-size: 16px; font-weight: bold; background: transparent;")
        events_layout.addWidget(title_events)
        events_layout.addSpacing(5)
        
        # Event Controls (Filter, Search, Export, Syslog)
        controls_layout = QHBoxLayout()
        
        self.chk_select_all = QCheckBox("✅ Select All")
        self.chk_select_all.stateChanged.connect(self.toggle_select_all)
        controls_layout.addWidget(self.chk_select_all)
        
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Search logs...")
        self.search_input.textChanged.connect(self.filter_logs)
        controls_layout.addWidget(self.search_input)
        
        self.sev_filter = QComboBox()
        self.sev_filter.addItems(["All Severities", "Critical", "High", "High Risk", "Medium", "Medium Risk", "Warning", "Safe", "Low Risk"])
        self.sev_filter.currentTextChanged.connect(self.filter_logs)
        controls_layout.addWidget(self.sev_filter)
        
        self.btn_export = QPushButton("📄 Export")
        self.btn_export.clicked.connect(self.export_logs)
        controls_layout.addWidget(self.btn_export)
        
        self.btn_syslog = QPushButton("📡 Syslog")
        self.btn_syslog.clicked.connect(self.setup_syslog)
        controls_layout.addWidget(self.btn_syslog)
        
        self.btn_clear = QPushButton("🗑️ Clear")
        self.btn_clear.setObjectName("BtnDanger")
        self.btn_clear.clicked.connect(self.clear_logs)
        controls_layout.addWidget(self.btn_clear)
        
        events_layout.addLayout(controls_layout)

        self.alerts_table = QTableWidget()
        self.alerts_table.setColumnCount(4)
        self.alerts_table.setHorizontalHeaderLabels(["🕒 Time", "🧩 Source", "📝 Description", "⚠️ Threat Level"])
        self.alerts_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.alerts_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.alerts_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self.alerts_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        self.alerts_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.alerts_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.alerts_table.verticalHeader().setVisible(False)
        self.alerts_table.setShowGrid(False)
        
        # Premium Styling
        self.alerts_table.setStyleSheet("""
            QTableWidget {
                border: none;
                background: transparent;
                alternate-background-color: #2a2a2a;
            }
            QTableWidget::item {
                padding: 10px;
                border-bottom: 1px solid #333333;
            }
            QHeaderView::section {
                background-color: #1e1e1e;
                color: #aaa;
                font-weight: bold;
                border: none;
                padding-bottom: 8px;
                border-bottom: 2px solid #333;
            }
        """)
        self.alerts_table.setAlternatingRowColors(True)
        self.alerts_table.verticalHeader().setDefaultSectionSize(45)
        
        self.alerts_table.itemDoubleClicked.connect(self.show_event_details)
        self.alerts_table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.alerts_table.customContextMenuRequested.connect(self.show_context_menu)
        
        events_layout.addWidget(self.alerts_table)
        bottom_layout.addWidget(events_frame, 2)

        layout.addLayout(bottom_layout, 3)

    def create_dynamic_status_row(self, layout, name):
        row = QWidget()
        row.setStyleSheet("background: transparent;")
        l = QHBoxLayout(row)
        l.setContentsMargins(5, 12, 5, 12)
        
        lbl_name = QLabel(name)
        lbl_name.setStyleSheet("background: transparent; font-size: 13px;")
        l.addWidget(lbl_name)
        l.addStretch()
        
        stat_lbl = QLabel("Checking...")
        stat_lbl.setStyleSheet("font-weight: bold; background: transparent; font-size: 13px; padding: 4px 10px; border-radius: 4px;")
        l.addWidget(stat_lbl)
        layout.addWidget(row)
        
        sep = QFrame()
        sep.setFixedHeight(1)
        sep.setStyleSheet("background-color: #88888820; margin-left: 5px; margin-right: 5px;")
        layout.addWidget(sep)
        
        return stat_lbl

    def update_dashboard(self):
        if hasattr(self, 'worker') and self.worker.isRunning():
            return
            
        fetch_db = (self._tick_count % 3 == 0)
        db_path = self.session.get_db_path() if self.session else "nexashield.db"
        self.worker = OverviewWorker(fetch_db, db_path)
        self.worker.data_fetched.connect(self.handle_dashboard_data)
        self.worker.start()
        self._tick_count += 1
        
    def handle_dashboard_data(self, data):
        self.cpu_hist.update_value(data['cpu'])
        self.ram_hist.update_value(data['ram'])
        self.disk_hist.update_value(data['disk'])
        
        if 'net_bytes' in data:
            if hasattr(self, '_last_net_bytes'):
                delta = max(0, data['net_bytes'] - self._last_net_bytes)
                max_rate = 20 * 1024 * 1024 # Assumes ~10MB/s is 100% capacity given 2s tick
                net_pct = min(100.0, (delta / max_rate) * 100.0)
                self.net_hist.update_value(net_pct)
            else:
                self.net_hist.update_value(0)
            self._last_net_bytes = data['net_bytes']
        
        if 'security_score' in data:
            score = data['security_score']
            color = "#28a745" if score >= 80 else ("#ffc107" if score >= 50 else "#dc3545")
            self.lbl_score.setText(f"🏆 Security Score: <span style='color: {color};'>{score}/100</span>")
        
        def set_stat(lbl, val, threshold):
            if val < threshold:
                lbl.setText("Good")
                lbl.setStyleSheet("color: #28a745; font-weight: bold; background: rgba(40, 167, 69, 0.1); padding: 4px 10px; border-radius: 4px;")
            else:
                lbl.setText("Warning")
                lbl.setStyleSheet("color: #dc3545; font-weight: bold; background: rgba(220, 53, 69, 0.1); padding: 4px 10px; border-radius: 4px;")
                
        set_stat(self.lbl_cpu_stat, data['cpu'], 85)
        set_stat(self.lbl_ram_stat, data['ram'], 85)
        set_stat(self.lbl_disk_stat, data['disk'], 90)
        
        if data['net_up']:
            self.lbl_net_stat.setText("Connected")
            self.lbl_net_stat.setStyleSheet("color: #28a745; font-weight: bold; background: rgba(40, 167, 69, 0.1); padding: 4px 10px; border-radius: 4px;")
        else:
            self.lbl_net_stat.setText("Disconnected")
            self.lbl_net_stat.setStyleSheet("color: #dc3545; font-weight: bold; background: rgba(220, 53, 69, 0.1); padding: 4px 10px; border-radius: 4px;")
            
        if 'events' in data:
            events = data['events']
            
            if self._last_events != events:
                self._last_events = events
                
                stats = {"Safe": 0, "Warning": 0, "Critical": 0}
                
                # Save current selections
                selected_ids = []
                for r in range(self.alerts_table.rowCount()):
                    item = self.alerts_table.item(r, 0)
                    if item and item.checkState() == Qt.CheckState.Checked:
                        db_info = item.data(Qt.ItemDataRole.UserRole)
                        if db_info:
                            selected_ids.append(db_info)
                
                self.alerts_table.setRowCount(len(events))
                for i, event_data in enumerate(events):
                    time_str = event_data[0]
                    mod = event_data[1]
                    desc = event_data[2]
                    sev = event_data[3]
                    db_info = event_data[4] if len(event_data) > 4 else None
                    
                    if sev in ["Critical", "High", "High Risk"]:
                        stats["Critical"] += 1
                    elif sev in ["Medium", "Medium Risk", "Warning"]:
                        stats["Warning"] += 1
                    else:
                        stats["Safe"] += 1
                    
                    time_item = QTableWidgetItem(time_str)
                    time_item.setFlags(Qt.ItemFlag.ItemIsUserCheckable | Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsSelectable)
                    
                    if db_info and db_info in selected_ids:
                        time_item.setCheckState(Qt.CheckState.Checked)
                    else:
                        time_item.setCheckState(Qt.CheckState.Unchecked)
                        
                    if db_info:
                        time_item.setData(Qt.ItemDataRole.UserRole, db_info)
                    self.alerts_table.setItem(i, 0, time_item)
                    self.alerts_table.setItem(i, 1, QTableWidgetItem(mod))
                    self.alerts_table.setItem(i, 2, QTableWidgetItem(desc))
                    
                    sev_item = QTableWidgetItem(sev)
                    sev_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
                    font = sev_item.font()
                    font.setBold(True)
                    sev_item.setFont(font)
                    if sev in ["High", "Critical", "High Risk"]:
                        sev_item.setForeground(QBrush(QColor("#ff4d4d")))
                    elif sev in ["Medium", "Medium Risk", "Warning"]:
                        sev_item.setForeground(QBrush(QColor("#ffcc00")))
                    elif sev in ["Safe", "Low Risk"]:
                        sev_item.setForeground(QBrush(QColor("#00cc66")))
                    
                    self.alerts_table.setItem(i, 3, sev_item)
                self.threat_donut.update_stats(stats)
                self.filter_logs()

    def filter_logs(self):
        search_term = self.search_input.text().lower()
        sev_term = self.sev_filter.currentText()
        
        for row in range(self.alerts_table.rowCount()):
            match = True
            if sev_term != "All Severities":
                if self.alerts_table.item(row, 3).text() != sev_term: match = False
            if search_term and match:
                row_text = " ".join([self.alerts_table.item(row, c).text() for c in range(4)]).lower()
                if search_term not in row_text: match = False
            self.alerts_table.setRowHidden(row, not match)

    def toggle_select_all(self, state):
        check_state = Qt.CheckState(state)
        for row in range(self.alerts_table.rowCount()):
            item = self.alerts_table.item(row, 0)
            if item:
                item.setCheckState(check_state)

    def export_logs(self):
        path, _ = QFileDialog.getSaveFileName(self, "Export Logs", "siem_logs.csv", "CSV Files (*.csv);;PDF Files (*.pdf)")
        if not path: return
        try:
            if path.endswith('.csv'):
                with open(path, 'w', newline='', encoding='utf-8') as f:
                    writer = csv.writer(f)
                    writer.writerow(["Time", "Source", "Description", "Severity"])
                    for r in range(self.alerts_table.rowCount()):
                        if not self.alerts_table.isRowHidden(r):
                            writer.writerow([self.alerts_table.item(r, c).text() for c in range(4)])
            else:
                printer = QPrinter(QPrinter.PrinterMode.HighResolution)
                printer.setOutputFormat(QPrinter.OutputFormat.PdfFormat)
                printer.setOutputFileName(path)
                html = "<h2>SIEM Event Logs</h2><table border='1' width='100%' cellspacing='0' cellpadding='4'>"
                html += "<tr bgcolor='#f2f2f2'><th>Time</th><th>Source</th><th>Description</th><th>Severity</th></tr>"
                for r in range(self.alerts_table.rowCount()):
                    if not self.alerts_table.isRowHidden(r):
                        html += "<tr>" + "".join(f"<td>{self.alerts_table.item(r, c).text()}</td>" for c in range(4)) + "</tr>"
                html += "</table>"
                doc = QTextDocument()
                doc.setHtml(html)
                doc.print(printer)
            QMessageBox.information(self, "Success", "Logs exported successfully.")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to export: {e}")

    def setup_syslog(self):
        dlg = SyslogDialog(self)
        if dlg.exec() == QDialog.DialogCode.Accepted:
            ip = dlg.ip_input.text()
            try:
                port = int(dlg.port_input.text())
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                count = 0
                
                # Check for user-selected rows
                selected_rows = []
                for r in range(self.alerts_table.rowCount()):
                    item = self.alerts_table.item(r, 0)
                    if item and item.checkState() == Qt.CheckState.Checked:
                        selected_rows.append(r)
                        
                # If nothing is explicitly checked, fallback to processing all visible rows
                rows_to_process = selected_rows if selected_rows else range(self.alerts_table.rowCount())
                
                for r in rows_to_process:
                    # Skip hidden rows if we are processing the entire table
                    if not selected_rows and self.alerts_table.isRowHidden(r):
                        continue
                        
                    time_val = self.alerts_table.item(r, 0).text()
                    source = self.alerts_table.item(r, 1).text()
                    desc = self.alerts_table.item(r, 2).text()
                    sev = self.alerts_table.item(r, 3).text()
                    
                    # Map NexaShield Severity to Syslog PRI (Facility 1 = User-Level)
                    if sev in ["Critical", "High", "High Risk"]:
                        pri = 8 + 2  # Critical
                    elif sev in ["Medium", "Medium Risk", "Warning"]:
                        pri = 8 + 4  # Warning
                    else:
                        pri = 8 + 6  # Informational (Safe/Low Risk)
                        
                    msg = f"<{pri}>1 {time_val} {socket.gethostname()} NexaShield - - - [{sev}] {source}: {desc}"
                    sock.sendto(msg.encode('utf-8'), (ip, port))
                    count += 1
                QMessageBox.information(self, "Syslog", f"Forwarded {count} logs to {ip}:{port}")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to forward syslog: {e}")

    def clear_logs(self):
        # 1. Gather checked rows
        rows_to_delete = []
        for r in range(self.alerts_table.rowCount()):
            item = self.alerts_table.item(r, 0)
            if item and item.checkState() == Qt.CheckState.Checked:
                rows_to_delete.append(r)
                
        # 2. Fallback to selection highlight if no checkboxes are used
        if not rows_to_delete:
            selected_items = self.alerts_table.selectedItems()
            rows_to_delete = [item.row() for item in selected_items]
            
        rows_to_delete = sorted(list(set(rows_to_delete)), reverse=True)

        if not rows_to_delete:
            reply = QMessageBox.question(self, "Clear All Logs", "No rows selected. Do you want to clear ALL logs?", QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
            if reply == QMessageBox.StandardButton.Yes:
                try:
                    conn = sqlite3.connect(self.session.get_db_path() if self.session else "nexashield.db")
                    cursor = conn.cursor()
                    # Ignore missing tables gracefully 
                    for table in ["siem_events", "phishing_history", "scan_history"]:
                        try:
                            cursor.execute(f"DELETE FROM {table}")
                        except sqlite3.OperationalError:
                            pass
                    conn.commit()
                    conn.close()
                    self.alerts_table.setRowCount(0)
                    self._last_events = []
                    self.chk_select_all.setChecked(False)
                    QMessageBox.information(self, "Success", "All logs cleared.")
                except Exception as e:
                    QMessageBox.critical(self, "Error", f"Failed to clear logs: {e}")
            return
            
        reply = QMessageBox.question(self, "Clear Selected Logs", f"Do you want to clear {len(rows_to_delete)} selected log(s)?", QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        
        if reply == QMessageBox.StandardButton.Yes:
            try:
                conn = sqlite3.connect(self.session.get_db_path() if self.session else "nexashield.db")
                cursor = conn.cursor()
                for r in rows_to_delete:
                    item = self.alerts_table.item(r, 0)
                    if item:
                        db_info = item.data(Qt.ItemDataRole.UserRole)
                        if db_info:
                            table_name, record_id = db_info
                            try:
                                cursor.execute(f"DELETE FROM {table_name} WHERE id = ?", (record_id,))
                            except sqlite3.OperationalError:
                                pass
                    self.alerts_table.removeRow(r)
                conn.commit()
                conn.close()
                self._last_events = None # Force table refresh next tick
                self.chk_select_all.setChecked(False)
                QMessageBox.information(self, "Success", f"Successfully cleared {len(rows_to_delete)} log(s).")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to clear selected logs: {e}")

    def show_event_details(self, item):
        row = item.row()
        time_item = self.alerts_table.item(row, 0)
        source_item = self.alerts_table.item(row, 1)
        desc_item = self.alerts_table.item(row, 2)
        sev_item = self.alerts_table.item(row, 3)
        
        if not time_item: return
        
        db_info = time_item.data(Qt.ItemDataRole.UserRole)
        basic_info = {
            "time": time_item.text(),
            "source": source_item.text(),
            "desc": desc_item.text(),
            "severity": sev_item.text()
        }
        
        dlg = EventInspectorDialog(self, db_info, basic_info)
        dlg.exec()

    def show_context_menu(self, pos):
        item = self.alerts_table.itemAt(pos)
        if not item: return
        row = item.row()
        
        time_str = self.alerts_table.item(row, 0).text()
        source = self.alerts_table.item(row, 1).text()
        desc = self.alerts_table.item(row, 2).text()
        
        menu = QMenu(self)
        menu.setStyleSheet("QMenu { background-color: #2b2b2b; color: white; border: 1px solid #444; } QMenu::item:selected { background-color: #0078d7; }")
        
        details_act = menu.addAction("🔍 View Raw Details")
        copy_act = menu.addAction("📋 Copy Event Data")
        
        block_act = None
        extracted_ip = None
        
        # Smart Context: Network IP blocking
        if any(kw in source for kw in ["NIDS", "Network", "Firewall", "IPS"]):
            ip_match = re.search(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', desc)
            if ip_match:
                extracted_ip = ip_match.group(0)
                block_act = menu.addAction(f"🚫 Block IP: {extracted_ip}")
                
        action = menu.exec(self.alerts_table.viewport().mapToGlobal(pos))
        
        if action == details_act:
            self.show_event_details(self.alerts_table.item(row, 0))
        elif action == copy_act:
            QApplication.clipboard().setText(f"{time_str} | {source} | {desc}")
        elif block_act and action == block_act:
            self.block_ip_action(extracted_ip)

    def block_ip_action(self, ip):
        try:
            if platform.system() == "Windows":
                cmd = f'netsh advfirewall firewall add rule name="NexaShield Block {ip}" dir=in action=block remoteip={ip}'
            else:
                cmd = f'iptables -A INPUT -s {ip} -j DROP'
            subprocess.run(cmd, shell=True, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            QMessageBox.information(self, "Success", f"Successfully blocked IP {ip} at OS Firewall.")
            
            # Audit Trail
            conn = sqlite3.connect(self.session.get_db_path() if self.session else "nexashield.db")
            conn.cursor().execute("INSERT INTO siem_events (timestamp, source, description, severity) VALUES (?, ?, ?, ?)",
                           (datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "SIEM / IPS", f"Manually blocked IP via context menu: {ip}", "High"))
            conn.commit()
            conn.close()
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to block IP. Please ensure app is running as Administrator/Root.\n\n{e}")

    # Manage timers automatically to save CPU when not visible
    def showEvent(self, event):
        super().showEvent(event)
        self.update_dashboard()
        self.timer.start(2000) # Update every 2 seconds

    def hideEvent(self, event):
        super().hideEvent(event)
        self.timer.stop()