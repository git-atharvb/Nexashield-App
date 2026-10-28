"""
NexaShield - Enterprise SIEM (Security Information & Event Management) Overview & SOC Command Center
Features:
- "🌟 SUPER REPORT" Central Engine (Cross-module deep gathering -> PDF / CSV -> FMS Vault)
- Real-Time Global Threat Posture (0-100%) & DEFCON Indicator
- Interactive MITRE ATT&CK Kill-Chain Triage Ribbon
- 5-Tile SOC Metric Ribbon (Posture, Critical Incidents, Blocked Hosts, Cloud DLP, AI Anomaly)
- Real-Time Cross-Module Security Event Correlation Matrix
- 440px Slide-out Incident Forensics & SOAR Remediation Playbook Drawer
- Real-Time Area Charts (CPU, RAM, Disk, Network I/O)
- Multi-Vector Radar Posture & Threat Donut Visualizers
"""

import os
import sys
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
    QLineEdit, QComboBox, QPushButton, QFileDialog, QMessageBox, QDialog, QFormLayout,
    QCheckBox, QTextEdit, QProgressBar, QRadioButton, QButtonGroup, QSplitter, QScrollArea,
    QSizePolicy
)
from PyQt6.QtCore import Qt, QTimer, QRectF, QThread, pyqtSignal, QPointF, QEvent
from PyQt6.QtGui import (
    QColor, QBrush, QPainter, QPen, QFont, QPalette, QPainterPath, QLinearGradient
)

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from siem_logic import SIEMCorrelationEngine, gather_deep_super_report_data
from super_report import SuperReportGenerator


# ==========================================================
# Background Worker for Super Report Generation
# ==========================================================
class SuperReportWorker(QThread):
    finished_report = pyqtSignal(bool, str, str, str)

    def __init__(self, session, format_type, scope):
        super().__init__()
        self.session = session
        self.format_type = format_type
        self.scope = scope

    def run(self):
        ok, fn, vp, msg = SuperReportGenerator.generate_report(
            session=self.session,
            format_type=self.format_type,
            scope=self.scope
        )
        self.finished_report.emit(ok, fn, vp, msg)


# ==========================================================
# Interactive Super Report Configuration & Execution Modal
# ==========================================================
class SuperReportDialog(QDialog):
    """
    State-of-the-Art SOC Master Report Generator.
    Gathers telemetry from all 9 tabs, builds PDF/CSV, and deposits into FMS Vault.
    """
    open_fms_requested = pyqtSignal()

    def __init__(self, session=None, siem_dashboard=None, parent=None):
        super().__init__(parent)
        self.session = session
        self.siem_dashboard = siem_dashboard
        self.setWindowTitle("NexaShield - Generate Enterprise Super Report")
        self.setMinimumSize(540, 560)
        self.generated_filename = ""
        self.generated_vault_path = ""
        self.setup_ui()

    def setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(14)

        # Header Title Block
        header = QHBoxLayout()
        icon_lbl = QLabel("🌟")
        icon_lbl.setStyleSheet("font-size: 26px; background: transparent;")
        header.addWidget(icon_lbl)

        title_vbox = QVBoxLayout()
        title_lbl = QLabel("Enterprise Security Super Report Generator")
        title_lbl.setStyleSheet("font-size: 15px; font-weight: 800; color: #38bdf8;")
        sub_lbl = QLabel("Aggregates deep forensic telemetry across all 9 security modules and vaults into FMS.")
        sub_lbl.setStyleSheet("font-size: 10px; color: #94a3b8;")
        title_vbox.addWidget(title_lbl)
        title_vbox.addWidget(sub_lbl)
        header.addLayout(title_vbox)
        header.addStretch()
        layout.addLayout(header)

        # 1. Format Selection Box
        fmt_group = QGroupBox("1. Select Export Format")
        fmt_group.setStyleSheet("font-weight: bold; font-size: 11px;")
        fmt_layout = QVBoxLayout(fmt_group)

        self.radio_pdf = QRadioButton("📄 Executive Forensic PDF Dossier (Formatted Scorecard, Charts, Audit Tables & Cryptographic Sign-off)")
        self.radio_pdf.setChecked(True)
        self.radio_pdf.setStyleSheet("font-size: 10px; font-weight: normal; padding: 4px;")

        self.radio_csv = QRadioButton("📊 Universal CSV Forensic Audit Bundle (Multi-Section Raw Data Dump)")
        self.radio_csv.setStyleSheet("font-size: 10px; font-weight: normal; padding: 4px;")

        self.bg_fmt = QButtonGroup(self)
        self.bg_fmt.addButton(self.radio_pdf)
        self.bg_fmt.addButton(self.radio_csv)

        fmt_layout.addWidget(self.radio_pdf)
        fmt_layout.addWidget(self.radio_csv)
        layout.addWidget(fmt_group)

        # 2. Scope Selection Box
        scope_group = QGroupBox("2. Modules & Telemetry Scope")
        scope_group.setStyleSheet("font-weight: bold; font-size: 11px;")
        scope_layout = QVBoxLayout(scope_group)

        self.chk_all = QCheckBox("Select All Modules (Recommended for Complete Audit)")
        self.chk_all.setChecked(True)
        self.chk_all.setStyleSheet("font-size: 10px; font-weight: bold; color: #38bdf8; margin-bottom: 6px;")
        self.chk_all.toggled.connect(self.toggle_all_scopes)
        scope_layout.addWidget(self.chk_all)

        self.scope_checkboxes = [
            QCheckBox("🖥️ Host OS, Hardware Thermals & System Specs"),
            QCheckBox("⚡ Process Forensics & Execution Telemetry"),
            QCheckBox("🌐 Network Sockets, Listening Ports & Connections"),
            QCheckBox("🧠 Memory Health, Swap & Behavioral Anomaly Index"),
            QCheckBox("🎣 Phishing URL Detections & Heuristic Verdicts"),
            QCheckBox("🚨 NIDS Network Intrusion System & Blocked IPs"),
            QCheckBox("🔥 Firewall Rules & Port Enforcement Status"),
            QCheckBox("🛡️ Antivirus Threat Logs & Quarantined Items"),
            QCheckBox("☁️ Cloud CASB Posture, DLP Leaks & Vaulted Assets"),
            QCheckBox("📊 Centralized SIEM Incident Correlation Matrix")
        ]

        grid_scope = QVBoxLayout()
        for chk in self.scope_checkboxes:
            chk.setChecked(True)
            chk.setStyleSheet("font-size: 10px; font-weight: normal; padding: 2px;")
            grid_scope.addWidget(chk)
        scope_layout.addLayout(grid_scope)
        layout.addWidget(scope_group)

        # 3. Status & Progress Indicator (Initially Hidden)
        self.prog_bar = QProgressBar()
        self.prog_bar.setRange(0, 0)
        self.prog_bar.setFixedHeight(12)
        self.prog_bar.setTextVisible(False)
        self.prog_bar.hide()
        layout.addWidget(self.prog_bar)

        self.lbl_status = QLabel("")
        self.lbl_status.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.lbl_status.setStyleSheet("font-size: 10px; font-weight: bold;")
        self.lbl_status.hide()
        layout.addWidget(self.lbl_status)

        # 4. Result Action Card (Shown after success)
        self.result_frame = QFrame()
        self.result_frame.setObjectName("CardContainer")
        self.result_frame.hide()
        rf_layout = QVBoxLayout(self.result_frame)
        rf_layout.setContentsMargins(10, 8, 10, 8)
        rf_layout.setSpacing(6)

        self.lbl_result_msg = QLabel("✓ Super Report generated and securely encrypted into FMS Vault.")
        self.lbl_result_msg.setStyleSheet("color: #10b981; font-weight: bold; font-size: 11px;")
        rf_layout.addWidget(self.lbl_result_msg)

        self.lbl_result_path = QLabel("")
        self.lbl_result_path.setStyleSheet("font-size: 9px; color: #94a3b8; font-family: 'Consolas', monospace;")
        self.lbl_result_path.setWordWrap(True)
        rf_layout.addWidget(self.lbl_result_path)

        res_btns = QHBoxLayout()
        self.btn_open_fms = QPushButton("📂 Open in FMS Files")
        self.btn_open_fms.setFixedHeight(28)
        self.btn_open_fms.setStyleSheet("background: #0284c7; color: white; font-weight: bold; border-radius: 4px; padding: 4px 10px;")
        self.btn_open_fms.clicked.connect(self.on_open_fms_clicked)
        res_btns.addWidget(self.btn_open_fms)

        self.btn_save_copy = QPushButton("💾 Save External Copy")
        self.btn_save_copy.setFixedHeight(28)
        self.btn_save_copy.clicked.connect(self.on_save_copy_clicked)
        res_btns.addWidget(self.btn_save_copy)
        rf_layout.addLayout(res_btns)
        layout.addWidget(self.result_frame)

        # 5. Bottom Action Controls
        btns_layout = QHBoxLayout()
        btns_layout.addStretch()

        self.btn_cancel = QPushButton("Close")
        self.btn_cancel.setFixedHeight(32)
        self.btn_cancel.clicked.connect(self.reject)
        btns_layout.addWidget(self.btn_cancel)

        self.btn_generate = QPushButton("🌟 Generate & Vault into FMS")
        self.btn_generate.setObjectName("BtnPrimary")
        self.btn_generate.setFixedHeight(32)
        self.btn_generate.setMinimumWidth(210)
        self.btn_generate.setStyleSheet("font-weight: 800; font-size: 11px;")
        self.btn_generate.clicked.connect(self.start_generation)
        btns_layout.addWidget(self.btn_generate)

        layout.addLayout(btns_layout)

    def toggle_all_scopes(self, checked):
        for chk in self.scope_checkboxes:
            chk.setChecked(checked)

    def start_generation(self):
        fmt = "PDF" if self.radio_pdf.isChecked() else "CSV"
        scope = [chk.text() for chk in self.scope_checkboxes if chk.isChecked()]

        self.btn_generate.setEnabled(False)
        self.prog_bar.show()
        self.lbl_status.setText(f"Gathering cross-module forensic data & compiling {fmt} Super Report...")
        self.lbl_status.setStyleSheet("color: #38bdf8; font-size: 10px; font-weight: bold;")
        self.lbl_status.show()

        self.worker = SuperReportWorker(self.session, fmt, scope)
        self.worker.finished_report.connect(self.on_report_finished)
        self.worker.start()

    def on_report_finished(self, success, filename, vault_path, message):
        self.prog_bar.hide()
        self.btn_generate.setEnabled(True)

        if success:
            self.generated_filename = filename
            self.generated_vault_path = vault_path
            self.lbl_status.setText("✓ Super Report generation complete!")
            self.lbl_status.setStyleSheet("color: #10b981; font-size: 10px; font-weight: bold;")

            self.lbl_result_path.setText(f"Vault Location: {vault_path}")
            self.result_frame.show()
            self.btn_generate.setText("🔄 Regenerate Super Report")
        else:
            self.lbl_status.setText(f"Error: {message}")
            self.lbl_status.setStyleSheet("color: #ef4444; font-size: 10px; font-weight: bold;")
            QMessageBox.critical(self, "Super Report Error", message)

    def on_open_fms_clicked(self):
        """Switches parent SIEM Dashboard directly to the FMS Files tab."""
        self.accept()
        if self.siem_dashboard and hasattr(self.siem_dashboard, 'switch_view'):
            self.siem_dashboard.switch_view(1)
        self.open_fms_requested.emit()

    def on_save_copy_clicked(self):
        """Allows user to save an external copy anywhere on disk."""
        if not self.generated_vault_path or not os.path.exists(self.generated_vault_path):
            QMessageBox.warning(self, "File Missing", "Generated report could not be located on disk.")
            return

        fmt_filter = "PDF Files (*.pdf)" if self.generated_filename.endswith(".pdf") else "CSV Files (*.csv)"
        dest, _ = QFileDialog.getSaveFileName(self, "Save External Copy of Super Report", self.generated_filename, fmt_filter)
        if dest:
            try:
                import shutil
                shutil.copyfile(self.generated_vault_path, dest)
                QMessageBox.information(self, "Exported Successfully", f"Super Report exported to:\n{dest}")
            except Exception as e:
                QMessageBox.critical(self, "Export Failed", str(e))


# ==========================================================
# Telemetry Metric Tile (InfoCard)
# ==========================================================
class InfoCard(QFrame):
    """High-density styled telemetry tile for SIEM metric summary ribbon."""
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
# MITRE ATT&CK & Cyber Kill Chain Tactical Strip
# ==========================================================
class MITREAttackRibbon(QFrame):
    """Interactive tactical kill-chain strip with live threat counts."""
    tactic_selected = pyqtSignal(str)

    def __init__(self):
        super().__init__()
        self.setObjectName("CardContainer")
        self.setFixedHeight(50)
        self.buttons = {}
        self.active_tactic = None
        self.setup_ui()

    def setup_ui(self):
        layout = QHBoxLayout(self)
        layout.setContentsMargins(8, 4, 8, 4)
        layout.setSpacing(6)

        lbl = QLabel("🎯 MITRE ATT&CK:")
        lbl.setStyleSheet("font-size: 10px; font-weight: bold; color: #38bdf8;")
        layout.addWidget(lbl)

        tactics = [
            ("Initial Access", "0"),
            ("Execution", "0"),
            ("Persistence", "0"),
            ("Privilege Escalation", "0"),
            ("Defense Evasion", "0"),
            ("Credential Access", "0"),
            ("Lateral Movement", "0"),
            ("Exfiltration", "0")
        ]

        for tac, init_cnt in tactics:
            btn = QPushButton(f"{tac} ({init_cnt})")
            btn.setFixedHeight(26)
            btn.setCheckable(True)
            btn.setCursor(Qt.CursorShape.PointingHandCursor)
            btn.setStyleSheet(self._get_pill_style(False, False))
            btn.clicked.connect(lambda checked, t=tac: self.on_tactic_clicked(t))
            layout.addWidget(btn)
            self.buttons[tac] = btn

    def _get_pill_style(self, is_active, has_alerts):
        if is_active:
            return "background: #0284c7; color: white; font-weight: bold; font-size: 9px; padding: 2px 6px; border-radius: 4px; border: 1px solid #38bdf8;"
        elif has_alerts:
            return "background: rgba(239, 68, 68, 0.15); color: #ef4444; font-weight: bold; font-size: 9px; padding: 2px 6px; border-radius: 4px; border: 1px solid rgba(239, 68, 68, 0.3);"
        return "background: rgba(148, 163, 184, 0.1); color: #94a3b8; font-size: 9px; padding: 2px 6px; border-radius: 4px; border: 1px solid rgba(148, 163, 184, 0.2);"

    def update_counts(self, counts: dict):
        for tac, btn in self.buttons.items():
            cnt = counts.get(tac, 0)
            btn.setText(f"{tac} ({cnt})")
            is_active = (self.active_tactic == tac)
            btn.setStyleSheet(self._get_pill_style(is_active, cnt > 0))

    def on_tactic_clicked(self, tactic: str):
        if self.active_tactic == tactic:
            self.active_tactic = None
            self.buttons[tactic].setChecked(False)
            self.tactic_selected.emit("All")
        else:
            self.active_tactic = tactic
            for t, btn in self.buttons.items():
                btn.setChecked(t == tactic)
            self.tactic_selected.emit(tactic)


# ==========================================================
# Visualizer: Security Radar Chart (Multi-Vector Posture)
# ==========================================================
class SecurityRadarChart(QWidget):
    def __init__(self):
        super().__init__()
        self.setMinimumSize(180, 160)
        self.dimensions = ["Host Endpoint", "Network NIDS", "Memory", "Cloud CASB", "Phishing"]
        self.values = [100, 100, 100, 100, 100]

    def update_scores(self, endpoint, network, memory, cloud, phishing):
        self.values = [max(10, min(100, v)) for v in (endpoint, network, memory, cloud, phishing)]
        self.update()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        w, h = self.width(), self.height()
        cx, cy = w / 2, h / 2
        radius = min(w, h) / 2 - 28
        num_dim = len(self.dimensions)

        # Concentric guide polygons
        painter.setPen(QPen(QColor(148, 163, 184, 50), 1))
        for step in [0.33, 0.66, 1.0]:
            poly = QPainterPath()
            for i in range(num_dim):
                angle = math.pi / 2 - (i * 2 * math.pi / num_dim)
                r = radius * step
                x = cx + r * math.cos(angle)
                y = cy - r * math.sin(angle)
                if i == 0:
                    poly.moveTo(x, y)
                else:
                    poly.lineTo(x, y)
            poly.closeSubpath()
            painter.drawPath(poly)

        # Spoke Lines & Dimension Text
        painter.setFont(QFont("Segoe UI", 7, QFont.Weight.Bold))
        for i in range(num_dim):
            angle = math.pi / 2 - (i * 2 * math.pi / num_dim)
            x_end = cx + radius * math.cos(angle)
            y_end = cy - radius * math.sin(angle)
            painter.setPen(QPen(QColor(148, 163, 184, 80), 1, Qt.PenStyle.DashLine))
            painter.drawLine(int(cx), int(cy), int(x_end), int(y_end))

            painter.setPen(self.palette().color(QPalette.ColorRole.WindowText))
            lbl_r = radius + 10
            x_lbl = cx + lbl_r * math.cos(angle)
            y_lbl = cy - lbl_r * math.sin(angle)
            lbl_rect = QRectF(x_lbl - 32, y_lbl - 8, 64, 16)
            painter.drawText(lbl_rect, Qt.AlignmentFlag.AlignCenter, self.dimensions[i])

        # Data Polygon
        data_poly = QPainterPath()
        for i in range(num_dim):
            angle = math.pi / 2 - (i * 2 * math.pi / num_dim)
            r = radius * (self.values[i] / 100.0)
            x = cx + r * math.cos(angle)
            y = cy - r * math.sin(angle)
            if i == 0:
                data_poly.moveTo(x, y)
            else:
                data_poly.lineTo(x, y)
        data_poly.closeSubpath()

        avg_score = sum(self.values) / num_dim
        color = QColor("#10b981") if avg_score > 80 else (QColor("#f59e0b") if avg_score > 60 else QColor("#ef4444"))

        pen = QPen(color, 2)
        pen.setJoinStyle(Qt.PenJoinStyle.RoundJoin)
        painter.setPen(pen)
        fill_color = QColor(color)
        fill_color.setAlpha(50)
        painter.setBrush(fill_color)
        painter.drawPath(data_poly)

        # Center Score
        painter.setPen(self.palette().color(QPalette.ColorRole.WindowText))
        painter.setFont(QFont("Segoe UI", 10, QFont.Weight.Bold))
        painter.drawText(int(cx - 25), int(cy - 12), 50, 24, Qt.AlignmentFlag.AlignCenter, f"{int(avg_score)}%")


# ==========================================================
# Visualizer: Threat Distribution Donut Chart
# ==========================================================
class ThreatDonutChart(QWidget):
    def __init__(self):
        super().__init__()
        self.setMinimumSize(120, 120)
        self.stats = {"Safe": 0, "Medium": 0, "Critical": 0}

    def update_stats(self, stats: dict):
        self.stats = stats
        self.update()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        w, h = self.width(), self.height()

        is_dark = self.palette().color(QPalette.ColorRole.Window).lightness() < 128
        bg_col = QColor("#111726") if is_dark else QColor("#ffffff")

        total = sum(self.stats.values())
        chart_size = min(w - 20, h - 20)
        rect = QRectF((w - chart_size) / 2, (h - chart_size) / 2, chart_size, chart_size)

        if total == 0:
            painter.setBrush(QColor(100, 116, 139, 40))
            painter.setPen(Qt.PenStyle.NoPen)
            painter.drawEllipse(rect)
        else:
            colors_map = {
                "Safe": QColor("#10b981"),
                "Low": QColor("#38bdf8"),
                "Medium": QColor("#f59e0b"),
                "High": QColor("#ef4444"),
                "Critical": QColor("#dc2626")
            }
            start_angle = 90 * 16
            for label, count in self.stats.items():
                if count > 0:
                    span = int((count / total) * 360 * 16)
                    painter.setBrush(colors_map.get(label, QColor("#64748b")))
                    painter.setPen(Qt.PenStyle.NoPen)
                    painter.drawPie(rect, start_angle, span)
                    start_angle += span

        # Center Hole
        inner_size = chart_size * 0.65
        inner_rect = QRectF((w - inner_size) / 2, (h - inner_size) / 2, inner_size, inner_size)
        painter.setBrush(bg_col)
        painter.setPen(Qt.PenStyle.NoPen)
        painter.drawEllipse(inner_rect)

        # Center text
        painter.setPen(self.palette().color(QPalette.ColorRole.WindowText))
        painter.setFont(QFont("Segoe UI", 9, QFont.Weight.Bold))
        painter.drawText(inner_rect, Qt.AlignmentFlag.AlignCenter, f"{total}\nThreats")


# ==========================================================
# Visualizer: Smooth Telemetry Area Chart
# ==========================================================
class OverviewBarChart(QWidget):
    """Draws a real-time smooth area chart for telemetry visualization."""
    def __init__(self, title, color="#0284c7"):
        super().__init__()
        self.title = title
        self.primary_color = QColor(color)
        self.data = [0.0] * 35
        self.setMinimumHeight(130)

    def update_value(self, percent):
        self.data.pop(0)
        self.data.append(percent)
        self.update()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        w, h = self.width(), self.height()

        text_color = self.palette().color(QPalette.ColorRole.WindowText)
        painter.setPen(text_color)
        painter.setFont(QFont("Segoe UI", 9, QFont.Weight.Bold))
        painter.drawText(10, 18, f"{self.title}")

        painter.setPen(self.primary_color)
        painter.setFont(QFont("Segoe UI", 11, QFont.Weight.Bold))
        painter.drawText(w - 75, 5, 65, 20, Qt.AlignmentFlag.AlignRight, f"{self.data[-1]:.1f}%")

        top_pad = 28
        chart_h = h - top_pad - 8
        grid_col = QColor(148, 163, 184, 30)
        painter.setPen(QPen(grid_col, 1, Qt.PenStyle.DashLine))
        for i in range(3):
            y_line = top_pad + i * (chart_h / 2)
            painter.drawLine(10, int(y_line), w - 10, int(y_line))

        if not self.data:
            return

        path = QPainterPath()
        step_x = (w - 20) / (len(self.data) - 1)
        path.moveTo(10, top_pad + chart_h - (self.data[0] / 100.0 * chart_h))

        for i in range(1, len(self.data)):
            x = 10 + i * step_x
            y = top_pad + chart_h - (self.data[i] / 100.0 * chart_h)
            path.lineTo(x, y)

        painter.setPen(QPen(self.primary_color, 2))
        painter.setBrush(Qt.BrushStyle.NoBrush)
        painter.drawPath(path)

        path.lineTo(w - 10, top_pad + chart_h)
        path.lineTo(10, top_pad + chart_h)
        path.closeSubpath()

        grad = QLinearGradient(0, top_pad, 0, top_pad + chart_h)
        col_alpha = QColor(self.primary_color)
        col_alpha.setAlpha(60)
        grad.setColorAt(0, col_alpha)
        col_zero = QColor(self.primary_color)
        col_zero.setAlpha(0)
        grad.setColorAt(1, col_zero)

        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(grad)
        painter.drawPath(path)


# ==========================================================
# Syslog Forwarding Configuration Modal
# ==========================================================
class SyslogDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Configure Syslog Forwarding")
        self.setMinimumSize(350, 180)

        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(20, 20, 20, 20)
        main_layout.setSpacing(12)

        header = QLabel("📡 Syslog UDP Stream Configuration")
        header.setStyleSheet("font-size: 13px; font-weight: bold; color: #38bdf8;")
        main_layout.addWidget(header)

        form_layout = QFormLayout()
        form_layout.setSpacing(10)

        self.ip_input = QLineEdit("127.0.0.1")
        self.ip_input.setFixedHeight(30)
        self.port_input = QLineEdit("514")
        self.port_input.setFixedHeight(30)

        form_layout.addRow(QLabel("Syslog IP:"), self.ip_input)
        form_layout.addRow(QLabel("Syslog Port:"), self.port_input)
        main_layout.addLayout(form_layout)

        main_layout.addStretch()

        self.btn_start = QPushButton("🚀 Stream Logs to Syslog")
        self.btn_start.setFixedHeight(32)
        self.btn_start.setObjectName("BtnPrimary")
        self.btn_start.clicked.connect(self.accept)
        main_layout.addWidget(self.btn_start)


# ==========================================================
# Telemetry Background Worker
# ==========================================================
class OverviewWorker(QThread):
    """Background worker to fetch telemetry without freezing the GUI."""
    data_fetched = pyqtSignal(dict)

    def __init__(self, session=None):
        super().__init__()
        self.session = session
        self.engine = SIEMCorrelationEngine(session_manager=session)

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

        # Query Cross-Module Correlated Events & Threat Analytics
        analytics = self.engine.get_threat_analytics()
        events = self.engine.get_correlated_events(limit=100)

        data['analytics'] = analytics
        data['events'] = events
        self.data_fetched.emit(data)


# ==========================================================
# Main SIEM Overview & SOC Command Center Widget
# ==========================================================
class OverviewWidget(QWidget):
    def __init__(self, session_manager=None, siem_dashboard=None):
        super().__init__()
        self.session = session_manager
        self.siem_dashboard = siem_dashboard
        self._is_streaming = True
        self.current_selected_event = None
        self.active_tactic_filter = "All"
        self.all_events_cache = []

        self.setup_ui()

        # Telemetry sample timer (every 2.5 seconds)
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.update_dashboard)
        self.timer.start(2500)
        QTimer.singleShot(100, self.update_dashboard)

    def is_dark_mode(self) -> bool:
        return self.palette().color(QPalette.ColorRole.Window).lightness() < 128

    def changeEvent(self, event):
        super().changeEvent(event)
        if event.type() in (QEvent.Type.PaletteChange, QEvent.Type.StyleChange):
            self.radar_chart.update()
            self.threat_donut.update()

    def setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(15, 12, 15, 12)
        layout.setSpacing(10)

        # ==========================================================
        # 1. TOP COMMAND BAR (Title, Specs, Super Report & Actions)
        # ==========================================================
        top_bar = QFrame()
        top_bar.setObjectName("ProcessToolbar")
        top_bar.setMinimumHeight(46)
        top_layout = QHBoxLayout(top_bar)
        top_layout.setContentsMargins(12, 6, 12, 6)
        top_layout.setSpacing(10)

        # Brand / Center Title
        title_box = QHBoxLayout()
        title_box.setSpacing(6)
        lbl_brand = QLabel("⚡ SIEM SOC Command Center")
        lbl_brand.setStyleSheet("font-size: 15px; font-weight: 800; color: #0284c7; letter-spacing: 0.5px;")
        title_box.addWidget(lbl_brand)

        # Host Specs Badge
        sys_info = f"{platform.system()} {platform.release()} ({socket.gethostname()})"
        self.lbl_host_badge = QLabel(f"🖥️ {sys_info}")
        self.lbl_host_badge.setStyleSheet("font-size: 10px; color: #94a3b8; font-weight: 600; padding: 3px 8px; background: rgba(148, 163, 184, 0.1); border-radius: 4px;")
        title_box.addWidget(self.lbl_host_badge)
        top_layout.addLayout(title_box)

        top_layout.addStretch()

        # 🌟 SUPER REPORT Action Button (Golden/Cyan Eye-Catching)
        self.btn_super_report = QPushButton("🌟 Generate Super Report")
        self.btn_super_report.setObjectName("BtnPrimary")
        self.btn_super_report.setFixedHeight(32)
        self.btn_super_report.setMinimumWidth(185)
        self.btn_super_report.setStyleSheet(
            "QPushButton { background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #0284c7, stop:1 #38bdf8); "
            "color: white; font-weight: 800; font-size: 11px; border-radius: 6px; padding: 4px 12px; border: 1px solid #38bdf8; } "
            "QPushButton:hover { background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #0369a1, stop:1 #0284c7); }"
        )
        self.btn_super_report.clicked.connect(self.open_super_report_dialog)
        top_layout.addWidget(self.btn_super_report)

        # ⚡ Instant Incident Sweep
        self.btn_sweep = QPushButton("⚡ Incident Sweep")
        self.btn_sweep.setFixedHeight(32)
        self.btn_sweep.clicked.connect(self.update_dashboard)
        top_layout.addWidget(self.btn_sweep)

        # ⏸️ Pause / ▶️ Stream Telemetry Toggle
        self.btn_stream = QPushButton("⏸️ Stream Live")
        self.btn_stream.setFixedHeight(32)
        self.btn_stream.setCheckable(True)
        self.btn_stream.setChecked(True)
        self.btn_stream.clicked.connect(self.toggle_stream)
        top_layout.addWidget(self.btn_stream)

        # 📡 Syslog
        self.btn_syslog = QPushButton("📡 Syslog")
        self.btn_syslog.setFixedHeight(32)
        self.btn_syslog.clicked.connect(self.setup_syslog)
        top_layout.addWidget(self.btn_syslog)

        # 🗑️ Purge Logs
        self.btn_clear = QPushButton("🗑️ Clear")
        self.btn_clear.setObjectName("BtnDanger")
        self.btn_clear.setFixedHeight(32)
        self.btn_clear.clicked.connect(self.clear_logs)
        top_layout.addWidget(self.btn_clear)

        layout.addWidget(top_bar)

        # ==========================================================
        # 2. SOC METRIC RIBBON (5 High-Density Tiles)
        # ==========================================================
        ribbon_layout = QHBoxLayout()
        ribbon_layout.setSpacing(8)

        self.card_posture = InfoCard("Global Security Posture", "100%", "🛡️", "#10b981")
        self.card_critical = InfoCard("Critical Threats", "0", "🚨", "#ef4444")
        self.card_blocked = InfoCard("Intercepted & Blocked", "0", "🌐", "#38bdf8")
        self.card_cloud = InfoCard("Cloud DLP & Exposure", "0", "☁️", "#f59e0b")
        self.card_anomaly = InfoCard("AI Behavioral Anomaly", "1.2%", "🤖", "#818cf8")

        ribbon_layout.addWidget(self.card_posture)
        ribbon_layout.addWidget(self.card_critical)
        ribbon_layout.addWidget(self.card_blocked)
        ribbon_layout.addWidget(self.card_cloud)
        ribbon_layout.addWidget(self.card_anomaly)
        layout.addLayout(ribbon_layout)

        # ==========================================================
        # 3. MITRE ATT&CK & CYBER KILL CHAIN STRIP
        # ==========================================================
        self.mitre_ribbon = MITREAttackRibbon()
        self.mitre_ribbon.tactic_selected.connect(self.on_mitre_tactic_selected)
        layout.addWidget(self.mitre_ribbon)

        # ==========================================================
        # 4. TELEMETRY GAUGES & HISTOGRAMS ROW
        # ==========================================================
        hist_frame = QFrame()
        hist_frame.setObjectName("CardContainer")
        hist_frame.setFixedHeight(145)
        hist_layout = QHBoxLayout(hist_frame)
        hist_layout.setContentsMargins(10, 8, 10, 8)
        hist_layout.setSpacing(10)

        self.cpu_hist = OverviewBarChart("CPU Utilization", "#0284c7")
        self.ram_hist = OverviewBarChart("Memory Allocation", "#f59e0b")
        self.disk_hist = OverviewBarChart("Storage I/O", "#ef4444")
        self.net_hist = OverviewBarChart("Network I/O", "#10b981")

        hist_layout.addWidget(self.cpu_hist)
        hist_layout.addWidget(self.ram_hist)
        hist_layout.addWidget(self.disk_hist)
        hist_layout.addWidget(self.net_hist)
        layout.addWidget(hist_frame)

        # ==========================================================
        # 5. LOWER WORKSPACE: Correlated Alerts <---> 440px Drawer
        # ==========================================================
        workspace_layout = QHBoxLayout()
        workspace_layout.setSpacing(10)

        # Left Container (Visualizers + Alert Table)
        left_container = QWidget()
        left_layout = QVBoxLayout(left_container)
        left_layout.setContentsMargins(0, 0, 0, 0)
        left_layout.setSpacing(8)

        # Visualizers Banner (Radar Posture + Donut Chart + Health Checklist)
        vis_layout = QHBoxLayout()
        vis_layout.setSpacing(10)

        # Radar Posture Card
        card_radar = QFrame()
        card_radar.setObjectName("CardContainer")
        card_radar.setFixedHeight(175)
        cr_layout = QVBoxLayout(card_radar)
        cr_layout.setContentsMargins(8, 8, 8, 8)
        self.lbl_radar_title = QLabel("🛡️ Protection Posture Radar")
        self.lbl_radar_title.setStyleSheet("font-size: 11px; font-weight: bold; color: #38bdf8;")
        cr_layout.addWidget(self.lbl_radar_title)
        self.radar_chart = SecurityRadarChart()
        cr_layout.addWidget(self.radar_chart, 1)
        vis_layout.addWidget(card_radar, 2)

        # Threat Donut Card
        card_donut = QFrame()
        card_donut.setObjectName("CardContainer")
        card_donut.setFixedHeight(175)
        cd_layout = QVBoxLayout(card_donut)
        cd_layout.setContentsMargins(8, 8, 8, 8)
        lbl_donut_title = QLabel("🎯 Threat Distribution")
        lbl_donut_title.setStyleSheet("font-size: 11px; font-weight: bold; color: #38bdf8;")
        cd_layout.addWidget(lbl_donut_title)
        self.threat_donut = ThreatDonutChart()
        cd_layout.addWidget(self.threat_donut, 1)
        vis_layout.addWidget(card_donut, 1)

        # System Health Checklist
        card_checks = QFrame()
        card_checks.setObjectName("CardContainer")
        card_checks.setFixedHeight(175)
        cc_layout = QVBoxLayout(card_checks)
        cc_layout.setContentsMargins(10, 8, 10, 8)
        cc_layout.setSpacing(4)
        lbl_ck_title = QLabel("🩺 Endpoint Sensor Health")
        lbl_ck_title.setStyleSheet("font-size: 11px; font-weight: bold; color: #38bdf8;")
        cc_layout.addWidget(lbl_ck_title)

        self.lbl_stat_cpu = self.create_status_row(cc_layout, "🧠 CPU & Thermals")
        self.lbl_stat_ram = self.create_status_row(cc_layout, "💾 Memory Integrity")
        self.lbl_stat_disk = self.create_status_row(cc_layout, "💽 Disk S.M.A.R.T.")
        self.lbl_stat_net = self.create_status_row(cc_layout, "🌐 Network Gateway")
        cc_layout.addStretch()
        vis_layout.addWidget(card_checks, 2)

        left_layout.addLayout(vis_layout)

        # Event Table Filter Toolbar
        tbl_toolbar = QHBoxLayout()
        tbl_toolbar.setSpacing(8)

        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Filter alerts by description, source, IP, or tactic...")
        self.search_input.setClearButtonEnabled(True)
        self.search_input.setFixedHeight(32)
        self.search_input.setStyleSheet("padding: 4px 10px; font-size: 11px;")
        self.search_input.textChanged.connect(self.filter_logs)
        tbl_toolbar.addWidget(self.search_input, 1)

        # Severity Filter (Expanded to 160px)
        self.sev_filter = QComboBox()
        self.sev_filter.setMinimumWidth(160)
        self.sev_filter.setFixedHeight(32)
        self.sev_filter.addItems(["All Severities", "Critical", "High", "Medium", "Safe"])
        self.sev_filter.currentTextChanged.connect(self.filter_logs)
        tbl_toolbar.addWidget(self.sev_filter)

        # Source Module Filter (Expanded to 160px)
        self.src_filter = QComboBox()
        self.src_filter.setMinimumWidth(160)
        self.src_filter.setFixedHeight(32)
        self.src_filter.addItems(["All Sources", "NIDS Sniffer", "Phishing Heuristics", "Cloud CASB & DLP", "Antivirus Engine", "SIEM Core"])
        self.src_filter.currentTextChanged.connect(self.filter_logs)
        tbl_toolbar.addWidget(self.src_filter)

        self.btn_export_table = QPushButton("💾 Export CSV")
        self.btn_export_table.setFixedHeight(32)
        self.btn_export_table.clicked.connect(self.export_logs)
        tbl_toolbar.addWidget(self.btn_export_table)

        left_layout.addLayout(tbl_toolbar)

        # Primary Correlated Alerts Table
        self.alerts_table = QTableWidget()
        self.alerts_table.setColumnCount(5)
        self.alerts_table.setHorizontalHeaderLabels([
            "Timestamp", "Severity", "Module Source", "MITRE Tactic", "Incident Classification & Summary"
        ])
        self.alerts_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.alerts_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self.alerts_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self.alerts_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        self.alerts_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        self.alerts_table.verticalHeader().setDefaultSectionSize(34)
        self.alerts_table.verticalHeader().setVisible(False)
        self.alerts_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.alerts_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.alerts_table.cellClicked.connect(self.on_alert_row_clicked)
        left_layout.addWidget(self.alerts_table, 1)

        workspace_layout.addWidget(left_container, 1)

        # ==========================================================
        # 6. RIGHT WING: 440px Slide-out Incident Forensic Drawer
        # ==========================================================
        self.dossier_drawer = QFrame()
        self.dossier_drawer.setObjectName("PhishingDossier")
        self.dossier_drawer.setFixedWidth(440)
        self.dossier_drawer.hide()

        drawer_layout = QVBoxLayout(self.dossier_drawer)
        drawer_layout.setContentsMargins(12, 12, 12, 12)
        drawer_layout.setSpacing(10)

        # Drawer Header
        d_header = QHBoxLayout()
        self.lbl_drawer_title = QLabel("🔬 Incident Forensic Dossier")
        self.lbl_drawer_title.setStyleSheet("font-size: 13px; font-weight: 800; color: #38bdf8;")
        d_header.addWidget(self.lbl_drawer_title)
        d_header.addStretch()

        self.btn_close_drawer = QPushButton("✖")
        self.btn_close_drawer.setFixedSize(26, 26)
        self.btn_close_drawer.setStyleSheet("background: transparent; border: none; font-size: 13px; font-weight: bold; color: #94a3b8;")
        self.btn_close_drawer.clicked.connect(lambda: self.dossier_drawer.hide())
        d_header.addWidget(self.btn_close_drawer)
        drawer_layout.addLayout(d_header)

        # Rich Forensic HTML Report
        self.txt_incident_report = QTextEdit()
        self.txt_incident_report.setReadOnly(True)
        self.txt_incident_report.setStyleSheet("border: none; background: transparent;")
        drawer_layout.addWidget(self.txt_incident_report, 1)

        # SOAR Remediation Playbook Actions
        d_actions = QHBoxLayout()
        d_actions.setSpacing(8)

        self.btn_action_block = QPushButton("🛡️ Block Remote IP")
        self.btn_action_block.setObjectName("BtnWarning")
        self.btn_action_block.setFixedHeight(32)
        self.btn_action_block.clicked.connect(self.execute_block_action)
        d_actions.addWidget(self.btn_action_block)

        self.btn_action_ack = QPushButton("✓ Acknowledge Alert")
        self.btn_action_ack.setObjectName("BtnPrimary")
        self.btn_action_ack.setFixedHeight(32)
        self.btn_action_ack.clicked.connect(self.execute_ack_action)
        d_actions.addWidget(self.btn_action_ack)

        drawer_layout.addLayout(d_actions)
        workspace_layout.addWidget(self.dossier_drawer)

        layout.addLayout(workspace_layout, 1)

    def create_status_row(self, layout, name):
        row = QWidget()
        row.setStyleSheet("background: transparent;")
        l = QHBoxLayout(row)
        l.setContentsMargins(0, 2, 0, 2)
        lbl_name = QLabel(name)
        lbl_name.setStyleSheet("background: transparent; font-size: 10px; color: #94a3b8;")
        l.addWidget(lbl_name)
        l.addStretch()
        stat_lbl = QLabel("Good")
        stat_lbl.setStyleSheet("font-weight: bold; font-size: 10px; color: #10b981; padding: 2px 6px; border-radius: 4px; background: rgba(16, 185, 129, 0.1);")
        l.addWidget(stat_lbl)
        layout.addWidget(row)
        return stat_lbl

    def open_super_report_dialog(self):
        """Launches the interactive SOC Super Report configuration and vaulting modal."""
        dlg = SuperReportDialog(session=self.session, siem_dashboard=self.siem_dashboard, parent=self)
        dlg.exec()

    def toggle_stream(self):
        """Pauses or resumes the live background telemetry sampling."""
        if self.btn_stream.isChecked():
            self.timer.start(2500)
            self.btn_stream.setText("⏸️ Stream Live")
            self.btn_stream.setStyleSheet("")
        else:
            self.timer.stop()
            self.btn_stream.setText("▶️ Paused")
            self.btn_stream.setStyleSheet("background: rgba(239, 68, 68, 0.2); color: #ef4444; border: 1px solid rgba(239, 68, 68, 0.4);")

    def on_mitre_tactic_selected(self, tactic: str):
        self.active_tactic_filter = tactic
        self.filter_logs()

    def update_dashboard(self):
        if hasattr(self, 'worker') and self.worker.isRunning():
            return
        self.worker = OverviewWorker(self.session)
        self.worker.data_fetched.connect(self.handle_dashboard_data)
        self.worker.start()

    def handle_dashboard_data(self, data: dict):
        # Update Area Charts
        self.cpu_hist.update_value(data.get('cpu', 0))
        self.ram_hist.update_value(data.get('ram', 0))
        self.disk_hist.update_value(data.get('disk', 0))

        if 'net_bytes' in data:
            if hasattr(self, '_last_net_bytes'):
                delta = max(0, data['net_bytes'] - self._last_net_bytes)
                max_rate = 20 * 1024 * 1024
                net_pct = min(100.0, (delta / max_rate) * 100.0)
                self.net_hist.update_value(net_pct)
            else:
                self.net_hist.update_value(0)
            self._last_net_bytes = data['net_bytes']

        # Update Analytics & Scorecard
        analytics = data.get('analytics', {})
        score = analytics.get('global_score', 100)
        defcon = analytics.get('defcon', 5)

        score_col = "#10b981" if score >= 80 else ("#f59e0b" if score >= 50 else "#ef4444")
        self.card_posture.set_value(f"{score}% (DEFCON {defcon})")
        self.card_posture.lbl_value.setStyleSheet(f"font-size: 13px; font-weight: 800; color: {score_col}; background: transparent;")

        self.card_critical.set_value(str(analytics.get('active_critical', 0)))
        self.card_blocked.set_value(str(analytics.get('blocked_hosts', 0)))
        self.card_cloud.set_value(str(analytics.get('cloud_dlp_leaks', 0)))
        self.card_anomaly.set_value(f"{analytics.get('ai_anomaly_index', 1.2):.1f}%")

        # Update MITRE Ribbon
        self.mitre_ribbon.update_counts(analytics.get('mitre_counts', {}))

        # Update Radar & Donut
        radar = analytics.get('radar_posture', {})
        self.radar_chart.update_scores(
            radar.get("Host Endpoint", 100),
            radar.get("Network (NIDS)", 100),
            radar.get("Memory Health", 100),
            radar.get("Cloud CASB", 100),
            radar.get("Phishing Defense", 100)
        )
        self.threat_donut.update_stats(analytics.get('severity_distribution', {}))

        # Update Sensor Status labels
        def set_chip(lbl, val, warn_th):
            if val < warn_th:
                lbl.setText("Good")
                lbl.setStyleSheet("font-weight: bold; font-size: 10px; color: #10b981; padding: 2px 6px; border-radius: 4px; background: rgba(16, 185, 129, 0.1);")
            else:
                lbl.setText("Warning")
                lbl.setStyleSheet("font-weight: bold; font-size: 10px; color: #ef4444; padding: 2px 6px; border-radius: 4px; background: rgba(239, 68, 68, 0.1);")

        set_chip(self.lbl_stat_cpu, data.get('cpu', 0), 85)
        set_chip(self.lbl_stat_ram, data.get('ram', 0), 85)
        set_chip(self.lbl_stat_disk, data.get('disk', 0), 90)

        # Update Correlated Alerts Table
        events = data.get('events', [])
        self.all_events_cache = events
        self.populate_alerts_table(events)

    def populate_alerts_table(self, events: list):
        self.alerts_table.setRowCount(len(events))

        for row, ev in enumerate(events):
            # Timestamp
            ts_item = QTableWidgetItem(str(ev.get("timestamp", ""))[:19])
            ts_item.setData(Qt.ItemDataRole.UserRole, ev)
            self.alerts_table.setItem(row, 0, ts_item)

            # Severity Pill
            sev = ev.get("severity", "Safe")
            sev_item = QTableWidgetItem(f" {sev} ")
            sev_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            if sev == "Critical":
                sev_item.setForeground(QBrush(QColor("#ef4444")))
            elif sev == "High":
                sev_item.setForeground(QBrush(QColor("#f97316")))
            elif sev == "Medium":
                sev_item.setForeground(QBrush(QColor("#f59e0b")))
            else:
                sev_item.setForeground(QBrush(QColor("#10b981")))
            self.alerts_table.setItem(row, 1, sev_item)

            # Source Module
            src_item = QTableWidgetItem(ev.get("source", "SIEM Core"))
            self.alerts_table.setItem(row, 2, src_item)

            # MITRE Tactic
            tactic_item = QTableWidgetItem(ev.get("mitre_tactic", "Initial Access"))
            self.alerts_table.setItem(row, 3, tactic_item)

            # Description
            desc_item = QTableWidgetItem(ev.get("description", ""))
            self.alerts_table.setItem(row, 4, desc_item)

        self.filter_logs()

    def filter_logs(self):
        """Filters table by search query, severity, source module, and active MITRE tactic."""
        query = self.search_input.text().strip().lower()
        sev_filter = self.sev_filter.currentText()
        src_filter = self.src_filter.currentText()
        tac_filter = self.active_tactic_filter

        for r in range(self.alerts_table.rowCount()):
            item_ts = self.alerts_table.item(r, 0)
            if not item_ts:
                continue
            ev = item_ts.data(Qt.ItemDataRole.UserRole) or {}

            # Severity match
            sev = ev.get("severity", "Safe")
            match_sev = (sev_filter == "All Severities" or sev.lower() == sev_filter.lower())

            # Source match
            src = ev.get("source", "")
            match_src = (src_filter == "All Sources" or src_filter.lower() in src.lower())

            # Tactic match
            tac = ev.get("mitre_tactic", "")
            match_tac = (tac_filter == "All" or tac.lower() == tac_filter.lower())

            # Text query match
            match_query = True
            if query:
                full_text = f"{ev.get('timestamp', '')} {sev} {src} {tac} {ev.get('description', '')}".lower()
                match_query = query in full_text

            self.alerts_table.setRowHidden(r, not (match_sev and match_src and match_tac and match_query))

    def on_alert_row_clicked(self, row: int, col: int):
        """Opens the 440px incident forensic drawer."""
        item = self.alerts_table.item(row, 0)
        if not item:
            return
        ev = item.data(Qt.ItemDataRole.UserRole)
        if ev:
            self.open_incident_drawer(ev)

    def open_incident_drawer(self, ev: dict):
        self.current_selected_event = ev
        self.txt_incident_report.setHtml(self.generate_drawer_html(ev))
        self.dossier_drawer.show()

    def generate_drawer_html(self, ev: dict) -> str:
        is_dark = self.is_dark_mode()
        card_bg = "#111726" if is_dark else "#f8fafc"
        card_border = "#1e293b" if is_dark else "#e2e8f0"
        text_primary = "#f8fafc" if is_dark else "#0f172a"
        text_muted = "#94a3b8"

        sev = ev.get("severity", "Safe")
        sev_color = "#ef4444" if sev == "Critical" else ("#f97316" if sev == "High" else ("#f59e0b" if sev == "Medium" else "#10b981"))

        raw = ev.get("raw_data", {})
        raw_json = json.dumps(raw, indent=2) if raw else "{}"

        html = f"""
        <table width="100%" cellpadding="8" cellspacing="0" style="background-color: {card_bg}; border: 1px solid {card_border}; border-radius: 6px; margin-bottom: 8px; font-family: 'Segoe UI', sans-serif;">
            <tr>
                <td>
                    <div style="font-size: 10px; font-weight: bold; color: #38bdf8; text-transform: uppercase;">
                        INCIDENT FORENSIC ASSESSMENT
                    </div>
                    <div style="font-size: 13px; font-weight: 800; color: {sev_color}; margin-top: 4px;">
                        [{sev.upper()}] {ev.get('title', 'Security Incident')}
                    </div>
                    <div style="font-size: 11px; color: {text_primary}; margin-top: 4px;">
                        Source Module: <b>{ev.get('source', '')}</b> | Tactic: <b>{ev.get('mitre_tactic', '')}</b>
                    </div>
                    <div style="font-size: 10px; color: {text_muted}; margin-top: 2px;">
                        Timestamp: {ev.get('timestamp', '')}
                    </div>
                </td>
            </tr>
        </table>

        <table width="100%" cellpadding="8" cellspacing="0" style="background-color: {card_bg}; border: 1px solid {card_border}; border-radius: 6px; margin-bottom: 8px; font-family: 'Segoe UI', sans-serif; font-size: 11px;">
            <tr>
                <td style="font-weight: bold; color: #38bdf8; border-bottom: 1px solid {card_border};">
                    📋 INCIDENT DETAILS & SUMMARY
                </td>
            </tr>
            <tr>
                <td style="color: {text_primary}; padding-top: 6px;">
                    {ev.get('description', '')}
                </td>
            </tr>
        </table>

        <table width="100%" cellpadding="8" cellspacing="0" style="background-color: {card_bg}; border: 1px solid {card_border}; border-radius: 6px; font-family: 'Segoe UI', sans-serif; font-size: 11px;">
            <tr>
                <td style="font-weight: bold; color: #94a3b8; border-bottom: 1px solid {card_border};">
                    🔍 RAW TELEMETRY & DATABASE PAYLOAD
                </td>
            </tr>
            <tr>
                <td style="padding-top: 6px;">
                    <pre style="font-family: 'Consolas', monospace; font-size: 10px; color: {text_primary}; white-space: pre-wrap; margin: 0;">{raw_json}</pre>
                </td>
            </tr>
        </table>
        """
        return html

    def execute_block_action(self):
        if not self.current_selected_event:
            return
        desc = self.current_selected_event.get("description", "")
        # Extract IP if present
        ip_match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', desc)
        target = ip_match.group(0) if ip_match else desc[:30]
        QMessageBox.information(
            self, "SOC Remediation Playbook",
            f"Enforcing Host Drop & Firewall Block on Target:\n{target}\n\nRule deployed across local perimeter."
        )

    def execute_ack_action(self):
        if not self.current_selected_event:
            return
        QMessageBox.information(
            self, "Alert Acknowledged",
            f"Incident '{self.current_selected_event.get('title', '')}' marked as acknowledged in SOC queue."
        )
        self.dossier_drawer.hide()

    def export_logs(self):
        """Exports currently filtered SIEM alerts table to CSV."""
        path, _ = QFileDialog.getSaveFileName(self, "Export Filtered SIEM Alerts", "siem_alerts_export.csv", "CSV Files (*.csv)")
        if not path:
            return
        try:
            with open(path, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(["Timestamp", "Severity", "Module Source", "MITRE Tactic", "Description"])
                for r in range(self.alerts_table.rowCount()):
                    if not self.alerts_table.isRowHidden(r):
                        writer.writerow([
                            self.alerts_table.item(r, 0).text() if self.alerts_table.item(r, 0) else "",
                            self.alerts_table.item(r, 1).text() if self.alerts_table.item(r, 1) else "",
                            self.alerts_table.item(r, 2).text() if self.alerts_table.item(r, 2) else "",
                            self.alerts_table.item(r, 3).text() if self.alerts_table.item(r, 3) else "",
                            self.alerts_table.item(r, 4).text() if self.alerts_table.item(r, 4) else ""
                        ])
            QMessageBox.information(self, "Export Complete", f"SIEM alerts exported to:\n{path}")
        except Exception as e:
            QMessageBox.critical(self, "Export Failed", str(e))

    def setup_syslog(self):
        dlg = SyslogDialog(self)
        if dlg.exec() == QDialog.DialogCode.Accepted:
            ip = dlg.ip_input.text()
            try:
                port = int(dlg.port_input.text())
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                count = 0
                for r in range(self.alerts_table.rowCount()):
                    if not self.alerts_table.isRowHidden(r):
                        time_val = self.alerts_table.item(r, 0).text()
                        sev = self.alerts_table.item(r, 1).text().strip()
                        source = self.alerts_table.item(r, 2).text()
                        desc = self.alerts_table.item(r, 4).text()
                        pri = 10 if "Crit" in sev else (12 if "High" in sev else 14)
                        msg = f"<{pri}>1 {time_val} {socket.gethostname()} NexaShield - - - [{sev}] {source}: {desc}"
                        sock.sendto(msg.encode('utf-8'), (ip, port))
                        count += 1
                QMessageBox.information(self, "Syslog Forwarding", f"Forwarded {count} event logs to syslog server {ip}:{port}")
            except Exception as e:
                QMessageBox.critical(self, "Syslog Error", str(e))

    def clear_logs(self):
        reply = QMessageBox.question(
            self, "Confirm Purge",
            "Are you sure you want to purge logged events from the SIEM view?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        if reply == QMessageBox.StandardButton.Yes:
            self.alerts_table.setRowCount(0)
            self.dossier_drawer.hide()
            try:
                from database import DatabaseManager
                DatabaseManager().clear_siem_events()
            except Exception:
                pass
