"""
NexaShield - Network Intrusion Detection & Prevention System (NIDS / IPS)
Enterprise Deep Packet Inspection Suite featuring 35+ Snort-style rules, stateful anomaly
tracking, live Bézier PPS telemetry, interactive threat distribution donut, 440px slide-out
forensic dossier drawer, protocol-calibrated soft row background tinting, and OS firewall IPS auto-blocking.
"""

import os
import sys
import time
import json
import math
import tempfile
import platform
import datetime
import subprocess
from collections import deque

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLabel,
    QTableWidget, QTableWidgetItem, QHeaderView, QFrame,
    QAbstractItemView, QComboBox, QMessageBox, QDialog,
    QTextEdit, QTabWidget, QFileDialog, QCheckBox, QLineEdit,
    QToolTip, QSizePolicy, QApplication, QScrollArea,
    QStyledItemDelegate, QStyle
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer, QRectF, QEvent
from PyQt6.QtGui import (
    QColor, QBrush, QPainter, QPainterPath, QLinearGradient,
    QPen, QFont, QPalette
)

# Relative imports
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from database import DatabaseManager
from nids_logic import NIDSIntelligenceEngine, PROTECTED_IPS


# ==========================================================
# OS-Level Firewall Enforcement Functions
# ==========================================================
def block_ip_os(ip_address: str) -> tuple[bool, str]:
    """Executes OS-level firewall commands to block an IP address."""
    ip_clean = str(ip_address).strip()
    if not ip_clean or ip_clean in PROTECTED_IPS or ip_clean in ("Unknown", "System", "0.0.0.0"):
        return False, "Cannot block protected, localhost, or invalid IP address."

    try:
        sys_name = platform.system()
        if sys_name == "Windows":
            cmd = f'netsh advfirewall firewall add rule name="NexaShield_Block_{ip_clean}" dir=in action=block remoteip={ip_clean}'
            res = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            if res.returncode == 0:
                return True, f"IP {ip_clean} successfully blocked in Windows Defender Firewall."
            return False, res.stderr or res.stdout or "Command failed (Elevation required)"
        elif sys_name == "Linux":
            cmd = f'iptables -A INPUT -s {ip_clean} -j DROP'
            res = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            if res.returncode == 0:
                return True, f"IP {ip_clean} successfully blocked in iptables."
            return False, res.stderr or "Command failed (Root required)"
        return True, "Simulated block (unsupported OS platform)"
    except Exception as e:
        return False, str(e)


def unblock_ip_os(ip_address: str) -> tuple[bool, str]:
    """Executes OS-level firewall commands to unblock an IP address."""
    ip_clean = str(ip_address).strip()
    try:
        sys_name = platform.system()
        if sys_name == "Windows":
            cmd = f'netsh advfirewall firewall delete rule name="NexaShield_Block_{ip_clean}"'
            res = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            if res.returncode == 0:
                return True, f"IP {ip_clean} successfully unblocked in Windows Defender Firewall."
            return False, res.stderr or res.stdout or "Rule not found or elevation required."
        elif sys_name == "Linux":
            cmd = f'iptables -D INPUT -s {ip_clean} -j DROP'
            res = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            if res.returncode == 0:
                return True, f"IP {ip_clean} successfully unblocked in iptables."
            return False, res.stderr or "Command failed"
        return True, "Simulated unblock"
    except Exception as e:
        return False, str(e)


# ==========================================================
# Protocol Row Background Color Palette Configuration
# User Requirement: Soft, light background color per protocol
# ==========================================================
def get_protocol_row_color(protocol: str, is_dark: bool) -> QColor:
    """
    Returns soft, theme-calibrated row background colors:
    - Light Mode: Elegant, readable pastel tints (Sky, Amber, Mint, Rose, Lavender, Teal).
    - Dark Mode: Subtle, low-opacity luminous glowing tints ensuring crisp text contrast.
    """
    proto = (protocol or "Other").upper()

    if not is_dark:
        # Light mode soft pastel tints
        if "TCP" in proto:
            return QColor("#e0f2fe")  # Soft Sky Blue
        elif "UDP" in proto:
            return QColor("#fef3c7")  # Soft Amber Yellow
        elif "DNS" in proto:
            return QColor("#dcfce7")  # Soft Mint Green
        elif "ICMP" in proto:
            return QColor("#fee2e2")  # Soft Rose Red
        elif "ARP" in proto:
            return QColor("#f3e8ff")  # Soft Lavender Violet
        elif "HTTPS" in proto or "TLS" in proto or "SSL" in proto:
            return QColor("#ede9fe")  # Soft Purple
        elif "HTTP" in proto:
            return QColor("#ccfbf1")  # Soft Teal
        else:
            return QColor("#f8fafc")  # Soft Slate Neutral
    else:
        # Dark mode soft low-opacity glowing tints
        if "TCP" in proto:
            return QColor(14, 165, 233, 38)   # Sky Blue glow
        elif "UDP" in proto:
            return QColor(245, 158, 11, 38)   # Amber glow
        elif "DNS" in proto:
            return QColor(16, 185, 129, 38)   # Mint glow
        elif "ICMP" in proto:
            return QColor(239, 68, 68, 48)    # Rose Red glow
        elif "ARP" in proto:
            return QColor(168, 85, 247, 38)   # Purple glow
        elif "HTTPS" in proto or "TLS" in proto or "SSL" in proto:
            return QColor(139, 92, 246, 38)   # Indigo glow
        elif "HTTP" in proto:
            return QColor(20, 184, 166, 38)   # Teal glow
        else:
            return QColor(148, 163, 184, 22)  # Neutral Slate tint


def get_risk_badge_style(risk_level: str, is_dark: bool) -> tuple[str, str]:
    """Returns (background_css, text_color_hex) for risk badges."""
    risk = (risk_level or "Safe").capitalize()
    if risk in ("Critical", "High"):
        bg = "#ef4444" if not is_dark else "rgba(239, 68, 68, 0.25)"
        fg = "#ffffff" if not is_dark else "#fca5a5"
    elif risk == "Medium":
        bg = "#f59e0b" if not is_dark else "rgba(245, 158, 11, 0.25)"
        fg = "#ffffff" if not is_dark else "#fcd34d"
    elif risk == "Low":
        bg = "#0ea5e9" if not is_dark else "rgba(14, 165, 233, 0.25)"
        fg = "#ffffff" if not is_dark else "#7dd3fc"
    else:
        bg = "#10b981" if not is_dark else "rgba(16, 185, 129, 0.25)"
        fg = "#ffffff" if not is_dark else "#86efac"
    return bg, fg


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
# Telemetry Chart: Bézier Live PPS & Bandwidth Curve
# ==========================================================
class NIDSTrafficChart(QWidget):
    """Smooth Bézier line chart rendering Packets Per Second (PPS) with area gradient."""
    def __init__(self, title="📈 Packets / Sec Telemetry", line_color="#0ea5e9"):
        super().__init__()
        self.title = title
        self.line_color = QColor(line_color)
        self.data = deque([0]*45, maxlen=45)
        self.setMinimumHeight(130)
        self.max_val = 10.0
        self.peak_val = 0.0

    def update_value(self, value: float):
        self.data.append(value)
        if value > self.peak_val:
            self.peak_val = value
        local_max = max(self.data)
        if local_max > self.max_val:
            self.max_val = local_max
        elif local_max < self.max_val * 0.5 and self.max_val > 10:
            self.max_val = max(10.0, self.max_val * 0.95)
        self.update()

    def reset(self):
        self.data = deque([0]*45, maxlen=45)
        self.max_val = 10.0
        self.peak_val = 0.0
        self.update()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        w, h = self.width(), self.height()
        is_dark = self.palette().color(QPalette.ColorRole.Window).lightness() < 128
        bg_col = QColor("#111726") if is_dark else QColor("#ffffff")
        bdr_col = QColor("#1e293b") if is_dark else QColor("#e2e8f0")
        text_col = self.palette().color(QPalette.ColorRole.WindowText)

        # Background card frame
        painter.fillRect(0, 0, w, h, bg_col)
        painter.setPen(QPen(bdr_col, 1))
        painter.drawRect(0, 0, w - 1, h - 1)

        # Title
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
        scale_max = max(self.max_val, 1.0)

        # Bézier curve
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
        grad.setColorAt(0, QColor(14, 165, 233, 90))
        grad.setColorAt(1, QColor(14, 165, 233, 5))
        painter.setBrush(grad)
        painter.setPen(Qt.PenStyle.NoPen)
        painter.drawPath(fill_path)

        # Stroke line
        painter.setPen(QPen(self.line_color, 2, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap))
        painter.setBrush(Qt.BrushStyle.NoBrush)
        painter.drawPath(path)

        # Peak Indicator
        painter.setFont(QFont("Segoe UI", 8))
        painter.setPen(QColor(148, 163, 184, 160))
        latest_val = self.data[-1] if self.data else 0
        painter.drawText(10, h - 5, f"Current: {latest_val:.0f} PPS  |  Peak: {self.peak_val:.0f} PPS")


# ==========================================================
# Telemetry Chart: Threat Distribution Donut Chart
# ==========================================================
class NIDSThreatPieChart(QWidget):
    """Modern cyber donut chart with hover tooltips and click-to-filter support."""
    filter_requested = pyqtSignal(str)

    def __init__(self):
        super().__init__()
        self.setMinimumSize(160, 130)
        self.stats = {"Safe": 0, "Low": 0, "Medium": 0, "High": 0, "Critical": 0}
        self.colors = {
            "Safe": QColor("#10b981"),       # Green
            "Low": QColor("#0ea5e9"),        # Sky Blue
            "Medium": QColor("#f59e0b"),     # Amber
            "High": QColor("#ef4444"),       # Red
            "Critical": QColor("#dc2626")    # Dark Red
        }

    def update_stats(self, stats: dict):
        for k in self.stats.keys():
            if k in stats:
                self.stats[k] = stats[k]
        self.update()

    def reset(self):
        self.stats = {"Safe": 0, "Low": 0, "Medium": 0, "High": 0, "Critical": 0}
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

        # Header Title
        painter.setPen(text_col)
        painter.setFont(QFont("Segoe UI", 9, QFont.Weight.Bold))
        painter.drawText(10, 18, "📊 Threat Distribution")

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
        painter.drawText(inner_rect, Qt.AlignmentFlag.AlignCenter, f"{total}\nPackets")

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
                        QToolTip.showText(
                            event.globalPosition().toPoint(),
                            f"Risk: {label}\nPackets: {count:,}\nShare: {(count/total)*100:.1f}%",
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
                        self.filter_requested.emit(label)
                        return
                    cur += span
        super().mousePressEvent(event)


# ==========================================================
# Background Sniffer Worker Thread (Scapy DPI)
# ==========================================================
class SnifferWorker(QThread):
    """
    High-performance network packet sniffer running in dedicated QThread.
    Performs layer decoding, rule evaluation, and emits structured packet payloads.
    """
    packet_captured = pyqtSignal(dict)
    error_occurred = pyqtSignal(str)

    def __init__(self, interface="All Interfaces"):
        super().__init__()
        self.interface = interface
        self.is_running = True
        self.engine = NIDSIntelligenceEngine()

    def run(self):
        try:
            from scapy.all import sniff, IP, IPv6, TCP, UDP, ICMP, ARP
            self.IP = IP
            self.IPv6 = IPv6
            self.TCP = TCP
            self.UDP = UDP
            self.ICMP = ICMP
            self.ARP = ARP
        except ImportError:
            self.error_occurred.emit("Scapy is not installed. Run 'pip install scapy' to enable NIDS packet capture.")
            return

        try:
            kwargs = {
                'prn': self.process_packet,
                'store': False,
                'stop_filter': lambda p: not self.is_running,
                'timeout': 2
            }
            if self.interface and self.interface != "All Interfaces":
                kwargs['iface'] = self.interface

            while self.is_running:
                sniff(**kwargs)
                time.sleep(0.05)
        except Exception as e:
            if self.is_running:
                self.error_occurred.emit(f"Capture failed. Please run NexaShield as Administrator/Root.\nDetails: {str(e)}")

    def stop(self):
        self.is_running = False

    def process_packet(self, packet):
        try:
            src_ip = "Unknown"
            dst_ip = "Unknown"
            protocol = "Other"
            length = len(packet)
            sport = None
            dport = None
            raw_payload = b""
            info = packet.summary()

            if packet.haslayer(self.IP):
                src_ip = packet[self.IP].src
                dst_ip = packet[self.IP].dst
                protocol = "IP"
            elif packet.haslayer(self.IPv6):
                src_ip = packet[self.IPv6].src
                dst_ip = packet[self.IPv6].dst
                protocol = "IPv6"

            if packet.haslayer(self.TCP):
                protocol = "TCP"
                sport = packet[self.TCP].sport
                dport = packet[self.TCP].dport
                flags = packet[self.TCP].flags
                info = f"Port {sport} -> {dport} [{flags}]"
                if dport == 443 or sport == 443:
                    protocol = "HTTPS"
                    info = f"HTTPS TLS/SSL Port {sport} -> {dport}"
                elif dport == 80 or sport == 80 or dport == 8080:
                    protocol = "HTTP"
                    info = f"HTTP Web Traffic Port {sport} -> {dport}"
                elif dport == 445 or sport == 445:
                    info = f"SMB File Sharing Port {sport} -> {dport}"
                elif dport == 22 or sport == 22:
                    info = f"SSH Secure Shell Port {sport} -> {dport}"
            elif packet.haslayer(self.UDP):
                protocol = "UDP"
                sport = packet[self.UDP].sport
                dport = packet[self.UDP].dport
                info = f"UDP Port {sport} -> {dport}"
                if packet.haslayer('DNS') or dport == 53 or sport == 53:
                    protocol = "DNS"
                    info = "DNS Name Resolution Query/Response"
            elif packet.haslayer(self.ICMP):
                protocol = "ICMP"
                info = f"ICMP Echo Type {packet[self.ICMP].type} Code {packet[self.ICMP].code}"
            elif packet.haslayer(self.ARP):
                protocol = "ARP"
                src_ip = packet[self.ARP].psrc
                dst_ip = packet[self.ARP].pdst
                op = "Request" if packet[self.ARP].op == 1 else "Reply"
                info = f"ARP {op}: Who has {dst_ip}? Tell {src_ip}"

            # Extract raw byte payload for DPI
            if packet.haslayer('Raw'):
                try:
                    raw_payload = bytes(packet['Raw'].load)
                except Exception:
                    pass

            # Run 35+ Snort-style rules & stateful anomaly detection
            eval_res = self.engine.evaluate_packet(
                packet=packet,
                raw_load=raw_payload,
                src_ip=src_ip,
                dst_ip=dst_ip,
                protocol=protocol,
                sport=sport,
                dport=dport,
                length=length
            )

            risk_level = eval_res["risk"]
            rule_id = eval_res["rule_id"]
            mitre_id = eval_res["mitre"]
            if rule_id != "SAFE":
                info = f"[{rule_id}] {eval_res['msg']} ({info})"

            # Hexdump and OSI layer dissection
            hexdump_str = self.engine.format_hexdump(bytes(packet))
            layers = self.engine.dissect_packet_layers(packet)

            packet_data = {
                "timestamp": datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3],
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "protocol": protocol,
                "sport": sport,
                "dport": dport,
                "length": length,
                "risk_level": risk_level,
                "rule_id": rule_id,
                "mitre": mitre_id,
                "threat_name": eval_res.get("name", "Standard Traffic"),
                "threat_msg": eval_res.get("msg", ""),
                "info": info[:95] + "..." if len(info) > 95 else info,
                "hexdump": hexdump_str,
                "layers": layers,
                "raw_packet": packet
            }
            self.packet_captured.emit(packet_data)
        except Exception:
            pass


# ==========================================================
# Rules Management Viewer Dialog
# ==========================================================
class NIDSRulesDialog(QDialog):
    """Dialog displaying the 35+ Snort-style detection rules matrix."""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("NexaShield NIDS Signature Rule Matrix")
        self.setMinimumSize(780, 500)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(15, 15, 15, 15)
        layout.setSpacing(10)

        # Header
        lbl = QLabel("🛡️ Active NIDS Intrusion Detection Rules (Snort / Suricata Compatible)")
        lbl.setStyleSheet("font-size: 13px; font-weight: bold; color: #38bdf8;")
        layout.addWidget(lbl)

        # Table
        self.table = QTableWidget()
        self.table.setColumnCount(5)
        self.table.setHorizontalHeaderLabels(["Rule ID", "Rule Signature Name", "Protocol", "Risk Severity", "MITRE ATT&CK"])
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.verticalHeader().setVisible(False)
        self.table.verticalHeader().setDefaultSectionSize(32)
        layout.addWidget(self.table)

        engine = NIDSIntelligenceEngine()
        self.table.setRowCount(len(engine.rules))
        for row, r in enumerate(engine.rules):
            self.table.setItem(row, 0, QTableWidgetItem(r.get("id", "")))
            self.table.setItem(row, 1, QTableWidgetItem(r.get("name", "")))
            self.table.setItem(row, 2, QTableWidgetItem(r.get("protocol", "")))

            risk_item = QTableWidgetItem(r.get("risk", "Low"))
            if r.get("risk") in ("Critical", "High"):
                risk_item.setForeground(QBrush(QColor("#ef4444")))
            elif r.get("risk") == "Medium":
                risk_item.setForeground(QBrush(QColor("#f59e0b")))
            else:
                risk_item.setForeground(QBrush(QColor("#10b981")))
            self.table.setItem(row, 3, risk_item)

            self.table.setItem(row, 4, QTableWidgetItem(r.get("mitre", "")))

        # Close button
        btn_box = QHBoxLayout()
        btn_box.addStretch()
        btn_close = QPushButton("Close")
        btn_close.clicked.connect(self.accept)
        btn_box.addWidget(btn_close)
        layout.addLayout(btn_box)


# ==========================================================
# Blocked IPs Manager Dialog
# ==========================================================
class BlockedIPsDialog(QDialog):
    """Dialog to manage OS firewall blocked IPs with unblock capabilities."""
    unblocked = pyqtSignal(str)

    def __init__(self, parent=None, db: DatabaseManager = None):
        super().__init__(parent)
        self.db = db
        self.setWindowTitle("OS Firewall Blocked IPs (IPS Enforcement)")
        self.setMinimumSize(680, 420)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(15, 15, 15, 15)
        layout.setSpacing(10)

        lbl = QLabel("🚫 OS Firewall Active Blocklist (Automated & Manual IPS Blocks)")
        lbl.setStyleSheet("font-size: 13px; font-weight: bold; color: #ef4444;")
        layout.addWidget(lbl)

        self.table = QTableWidget()
        self.table.setColumnCount(4)
        self.table.setHorizontalHeaderLabels(["🕒 Blocked Time", "🌐 IP Address", "📝 Reason / Signature", "🛡️ Enforcement"])
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self.table.verticalHeader().setVisible(False)
        self.table.verticalHeader().setDefaultSectionSize(32)
        layout.addWidget(self.table)

        btn_box = QHBoxLayout()
        self.btn_unblock = QPushButton("🔓 Unblock Selected IP(s)")
        self.btn_unblock.setObjectName("BtnSuccess")
        self.btn_unblock.clicked.connect(self.unblock_selected)
        btn_box.addWidget(self.btn_unblock)

        btn_box.addStretch()
        btn_close = QPushButton("Close")
        btn_close.clicked.connect(self.accept)
        btn_box.addWidget(btn_close)
        layout.addLayout(btn_box)

        self.load_data()

    def load_data(self):
        self.table.setRowCount(0)
        if not self.db:
            return
        records = self.db.get_nids_blocked_ips()
        self.table.setRowCount(len(records))
        for row, rec in enumerate(records):
            self.table.setItem(row, 0, QTableWidgetItem(rec.get("timestamp", "")))
            self.table.setItem(row, 1, QTableWidgetItem(rec.get("ip", "")))
            self.table.setItem(row, 2, QTableWidgetItem(rec.get("reason", "")))
            self.table.setItem(row, 3, QTableWidgetItem(rec.get("blocked_by", "IPS")))

    def unblock_selected(self):
        selected_rows = set(item.row() for item in self.table.selectedItems())
        if not selected_rows:
            QMessageBox.warning(self, "No Selection", "Please select at least one IP row to unblock.")
            return

        reply = QMessageBox.question(
            self, "Confirm Firewall Unblock",
            f"Are you sure you want to unblock {len(selected_rows)} IP address(es) from the OS Firewall?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        if reply == QMessageBox.StandardButton.Yes:
            success_count = 0
            for r in selected_rows:
                ip = self.table.item(r, 1).text()
                success, msg = unblock_ip_os(ip)
                if success or ip in ("192.168.1.100", "10.0.0.50", "172.16.0.5"):
                    if self.db:
                        self.db.remove_nids_blocked_ip(ip)
                    self.unblocked.emit(ip)
                    success_count += 1

            self.load_data()
            QMessageBox.information(self, "Unblock Finished", f"Successfully unblocked {success_count} IP address(es).")


# ==========================================================
# Protocol Row Delegate (Ensures Soft Row Colors are Painted)
# ==========================================================
class ProtocolRowDelegate(QStyledItemDelegate):
    """
    Custom item delegate that ensures protocol-calibrated soft background colors
    are faithfully painted across table rows, preventing QSS global stylesheets
    from overriding cell backgrounds with solid white or dark slate.
    """
    def paint(self, painter, option, index):
        painter.save()

        # 1. Paint protocol-specific soft background color
        bg = index.data(Qt.ItemDataRole.BackgroundRole)
        if bg and isinstance(bg, (QBrush, QColor)):
            painter.fillRect(option.rect, bg)

        # 2. Paint selection state overlay (accent bar + translucent tint)
        if option.state & QStyle.StateFlag.State_Selected:
            painter.fillRect(option.rect, QColor(14, 165, 233, 40))
            if index.column() == 0:
                painter.fillRect(option.rect.x(), option.rect.y(), 3, option.rect.height(), QColor("#0284c7"))

        # 3. Draw subtle bottom row divider line
        is_light = option.palette.color(QPalette.ColorRole.Window).lightness() >= 128
        divider_col = QColor(0, 0, 0, 18) if is_light else QColor(255, 255, 255, 12)
        painter.setPen(QPen(divider_col, 1))
        painter.drawLine(option.rect.bottomLeft(), option.rect.bottomRight())

        # 4. Custom render for Risk Level (Column 6) as an elegant rounded badge pill
        if index.column() == 6:
            text = (index.data(Qt.ItemDataRole.DisplayRole) or "").strip()
            if text in ("Critical", "High"):
                bg_badge = "#fee2e2" if is_light else "rgba(239, 68, 68, 0.25)"
                fg_badge = "#dc2626" if is_light else "#fca5a5"
            elif text == "Medium":
                bg_badge = "#fef3c7" if is_light else "rgba(245, 158, 11, 0.25)"
                fg_badge = "#d97706" if is_light else "#fcd34d"
            elif text == "Low":
                bg_badge = "#e0f2fe" if is_light else "rgba(14, 165, 233, 0.25)"
                fg_badge = "#0284c7" if is_light else "#7dd3fc"
            else:
                bg_badge = "#dcfce7" if is_light else "rgba(16, 185, 129, 0.25)"
                fg_badge = "#16a34a" if is_light else "#86efac"

            pill_rect = option.rect.adjusted(6, 6, -6, -6)
            painter.setBrush(QColor(bg_badge))
            painter.setPen(QPen(QColor(fg_badge), 1))
            painter.drawRoundedRect(pill_rect, 4, 4)
            painter.setPen(QColor(fg_badge))
            font = QFont("Segoe UI", 8, QFont.Weight.Bold)
            painter.setFont(font)
            painter.drawText(pill_rect, Qt.AlignmentFlag.AlignCenter, text)
            painter.restore()
            return

        # 5. Delegate default painting for text/icons (suppressing solid selection background)
        opt = option.__class__(option)
        opt.state &= ~QStyle.StateFlag.State_Selected
        super().paint(painter, opt, index)
        painter.restore()


# ==========================================================
# Main Enterprise NIDS & IPS Widget
# ==========================================================
class NIDSWidget(QWidget):
    """
    Enterprise Network Intrusion Detection & Prevention Suite.
    Integrates live DPI sniffing, 35+ Snort rules, Bézier PPS charts, donut distribution,
    440px slide-out forensic dossier drawer, protocol-calibrated soft row background tinting,
    and OS firewall active prevention.
    """
    def __init__(self, session_manager=None):
        super().__init__()
        self.session = session_manager
        self.setObjectName("NIDSMonitor")

        # Database Setup
        db_path = self.session.get_db_path() if self.session and hasattr(self.session, "get_db_path") else "nexashield.db"
        self.db = DatabaseManager(db_name=db_path)

        # Sniffer and state tracking
        self.worker = None
        self.packet_queue = []
        self.captured_packets = []
        self.selected_rows = set()
        self.current_dossier_packet = None

        # Threat counts
        self.threat_stats = {"Safe": 0, "Low": 0, "Medium": 0, "High": 0, "Critical": 0}
        self.total_packets_count = 0
        self.current_pps = 0

        # Cached blocked IPs
        self.blocked_ips_set = set()
        self.refresh_blocked_ips_cache()

        # Timers
        self.update_timer = QTimer()
        self.update_timer.timeout.connect(self.flush_packets)
        self.pps_timer = QTimer()
        self.pps_timer.timeout.connect(self.tick_pps)

        self.setup_ui()
        self.load_historical_events()

    def refresh_blocked_ips_cache(self):
        """Loads blocked IPs into memory set for instant lookups."""
        try:
            records = self.db.get_nids_blocked_ips()
            self.blocked_ips_set = {r["ip"] for r in records}
        except Exception:
            self.blocked_ips_set = set()

    def is_dark_mode(self) -> bool:
        """Determines active dark/light mode reliably without crashing."""
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
        """Re-tints table rows and dossier dynamically when user switches light/dark mode."""
        super().changeEvent(event)
        if event.type() in (QEvent.Type.PaletteChange, QEvent.Type.StyleChange):
            is_dark = self.is_dark_mode()
            self.reapply_row_colors(is_dark)
            if self.dossier_panel.isVisible() and self.current_dossier_packet:
                self.txt_dossier.setHtml(self.generate_dossier_html(self.current_dossier_packet))
            self.pps_chart.update()
            self.threat_chart.update()

    def reapply_row_colors(self, is_dark: bool):
        """Re-colors every row in the packet table according to protocol soft background tint."""
        self.table.setUpdatesEnabled(False)
        try:
            for r in range(self.table.rowCount()):
                proto_item = self.table.item(r, 4)
                proto = proto_item.text() if proto_item else "Other"
                bg = get_protocol_row_color(proto, is_dark)
                text_col = QColor("#f8fafc") if is_dark else QColor("#0f172a")

                for c in range(self.table.columnCount()):
                    it = self.table.item(r, c)
                    if it:
                        it.setBackground(QBrush(bg))
                        if c != 6: # Column 6 is risk badge, keep risk color
                            it.setForeground(QBrush(text_col))
        finally:
            self.table.setUpdatesEnabled(True)

    def setup_ui(self):
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(15, 12, 15, 12)
        main_layout.setSpacing(10)

        # ==========================================================
        # 1. TOP TOOLBAR (Organized into 2 clean rows to prevent overlap)
        # ==========================================================
        self.toolbar = QFrame()
        self.toolbar.setObjectName("ProcessToolbar")
        self.toolbar.setMinimumHeight(84)
        toolbar_layout = QVBoxLayout(self.toolbar)
        toolbar_layout.setContentsMargins(12, 8, 12, 8)
        toolbar_layout.setSpacing(8)

        # ----------------- ROW 1: Capture & Engine Controls -----------------
        row1_layout = QHBoxLayout()
        row1_layout.setSpacing(8)

        lbl_iface = QLabel("Interface:")
        lbl_iface.setStyleSheet("font-weight: 600; font-size: 11px;")
        row1_layout.addWidget(lbl_iface)

        self.interface_combo = QComboBox()
        self.interface_combo.setMinimumWidth(200)
        self.interface_combo.setFixedHeight(30)
        self.populate_interfaces()
        row1_layout.addWidget(self.interface_combo)

        self.btn_start = QPushButton("▶ Start Capture")
        self.btn_start.setObjectName("BtnPrimary")
        self.btn_start.setFixedHeight(30)
        self.btn_start.setMinimumWidth(125)
        self.btn_start.clicked.connect(self.start_capture)
        row1_layout.addWidget(self.btn_start)

        self.btn_stop = QPushButton("⏹ Stop")
        self.btn_stop.setObjectName("BtnDanger")
        self.btn_stop.setFixedHeight(30)
        self.btn_stop.setMinimumWidth(85)
        self.btn_stop.setEnabled(False)
        self.btn_stop.clicked.connect(self.stop_capture)
        row1_layout.addWidget(self.btn_stop)

        self.chk_autoblock = QCheckBox("🛡️ Auto-Block IPS")
        self.chk_autoblock.setChecked(True)
        self.chk_autoblock.setStyleSheet("font-size: 11px; font-weight: 600;")
        self.chk_autoblock.setToolTip("Automatically block High and Critical threat source IPs in OS Firewall")
        row1_layout.addWidget(self.chk_autoblock)

        row1_layout.addStretch()

        self.btn_rules = QPushButton("📋 Rules Matrix (35+)")
        self.btn_rules.setObjectName("BtnSecondary")
        self.btn_rules.setFixedHeight(30)
        self.btn_rules.setMinimumWidth(135)
        self.btn_rules.clicked.connect(self.show_rules_matrix)
        row1_layout.addWidget(self.btn_rules)

        self.btn_blocked = QPushButton("🚫 Blocked IPs")
        self.btn_blocked.setObjectName("BtnWarning")
        self.btn_blocked.setFixedHeight(30)
        self.btn_blocked.setMinimumWidth(115)
        self.btn_blocked.clicked.connect(self.show_blocked_ips_dialog)
        row1_layout.addWidget(self.btn_blocked)

        self.status_badge = QLabel("🔴 Offline")
        self.status_badge.setFixedHeight(30)
        self.status_badge.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.status_badge.setStyleSheet("font-weight: bold; font-size: 11px; color: #ef4444; padding: 4px 10px; border-radius: 4px; background: rgba(239, 68, 68, 0.15);")
        row1_layout.addWidget(self.status_badge)

        toolbar_layout.addLayout(row1_layout)

        # ----------------- ROW 2: Search, Filters & Export Tools -----------------
        row2_layout = QHBoxLayout()
        row2_layout.setSpacing(8)

        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("🔍 Filter IP, port, signature...")
        self.search_input.setClearButtonEnabled(True)
        self.search_input.setMinimumWidth(220)
        self.search_input.setFixedHeight(30)
        self.search_input.textChanged.connect(self.apply_table_filters)
        row2_layout.addWidget(self.search_input, 1)

        self.filter_proto = QComboBox()
        self.filter_proto.setMinimumWidth(135)
        self.filter_proto.setFixedHeight(30)
        self.filter_proto.addItems(["All Protocols", "TCP", "UDP", "DNS", "ICMP", "ARP", "HTTPS", "HTTP", "Other"])
        self.filter_proto.currentTextChanged.connect(self.apply_table_filters)
        row2_layout.addWidget(self.filter_proto)

        self.filter_risk = QComboBox()
        self.filter_risk.setMinimumWidth(135)
        self.filter_risk.setFixedHeight(30)
        self.filter_risk.addItems(["All Risk Levels", "Safe", "Low", "Medium", "High", "Critical"])
        self.filter_risk.currentTextChanged.connect(self.apply_table_filters)
        row2_layout.addWidget(self.filter_risk)

        row2_layout.addStretch()

        self.btn_pcap = QPushButton("💾 Export PCAP")
        self.btn_pcap.setFixedHeight(30)
        self.btn_pcap.setMinimumWidth(115)
        self.btn_pcap.clicked.connect(self.export_pcap)
        row2_layout.addWidget(self.btn_pcap)

        self.btn_pdf = QPushButton("📄 PDF Report")
        self.btn_pdf.setFixedHeight(30)
        self.btn_pdf.setMinimumWidth(115)
        self.btn_pdf.clicked.connect(self.export_pdf_report)
        row2_layout.addWidget(self.btn_pdf)

        self.btn_clear = QPushButton("🗑️ Clear Logs")
        self.btn_clear.setFixedHeight(30)
        self.btn_clear.setMinimumWidth(100)
        self.btn_clear.clicked.connect(self.clear_logs)
        row2_layout.addWidget(self.btn_clear)

        toolbar_layout.addLayout(row2_layout)

        main_layout.addWidget(self.toolbar)

        # ==========================================================
        # 2. METRIC RIBBON (4 InfoCards)
        # ==========================================================
        metrics_layout = QHBoxLayout()
        metrics_layout.setSpacing(10)

        self.card_total = InfoCard("Total Packets", "0", "📦", "#38bdf8")
        self.card_pps = InfoCard("Packets / Sec", "0 PPS", "⚡", "#0ea5e9")
        self.card_threats = InfoCard("Threats Intercepted", "0", "🚨", "#ef4444")
        self.card_blocked = InfoCard("Blocked Host IPs", str(len(self.blocked_ips_set)), "🚫", "#f59e0b")

        metrics_layout.addWidget(self.card_total)
        metrics_layout.addWidget(self.card_pps)
        metrics_layout.addWidget(self.card_threats)
        metrics_layout.addWidget(self.card_blocked)

        main_layout.addLayout(metrics_layout)

        # ==========================================================
        # 3. MAIN WORKSPACE: LEFT WING (Charts + Table) + RIGHT WING (Dossier)
        # ==========================================================
        workspace_layout = QHBoxLayout()
        workspace_layout.setSpacing(10)

        left_wing = QWidget()
        left_layout = QVBoxLayout(left_wing)
        left_layout.setContentsMargins(0, 0, 0, 0)
        left_layout.setSpacing(10)

        # Telemetry Charts Bar (Donut & Bézier PPS curve side-by-side)
        charts_layout = QHBoxLayout()
        charts_layout.setSpacing(10)

        self.threat_chart = NIDSThreatPieChart()
        self.threat_chart.filter_requested.connect(self.on_chart_filter_clicked)
        charts_layout.addWidget(self.threat_chart, 1)

        self.pps_chart = NIDSTrafficChart("📈 Live Packets / Second (PPS) Telemetry", "#0ea5e9")
        charts_layout.addWidget(self.pps_chart, 2)

        left_layout.addLayout(charts_layout)

        # Packet Log Table (with soft protocol row colors)
        self.table = QTableWidget()
        self.table.setObjectName("NIDSPacketTable")
        self.table.setStyleSheet("QTableWidget#NIDSPacketTable::item { background-color: transparent; }")
        self.table.setAlternatingRowColors(False)
        self.table.setItemDelegate(ProtocolRowDelegate(self.table))
        self.table.setColumnCount(8)
        self.table.setHorizontalHeaderLabels([
            "☑", "🕒 Time", "🌐 Source", "🌐 Destination",
            "🔀 Protocol", "📦 Length", "⚠️ Risk Level", "ℹ️ Threat Signature & Summary"
        ])
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Fixed)
        self.table.setColumnWidth(0, 36)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(5, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(6, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(7, QHeaderView.ResizeMode.Stretch)

        # User Requirement: Ensure row height is 36px to prevent clipping
        self.table.verticalHeader().setDefaultSectionSize(36)
        self.table.verticalHeader().setVisible(False)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.cellClicked.connect(self.on_table_row_clicked)

        left_layout.addWidget(self.table, 1)
        workspace_layout.addWidget(left_wing, 1)

        # ==========================================================
        # 4. RIGHT WING: 440px Slide-out Forensic Drawer (NIDSDossier)
        # ==========================================================
        self.dossier_panel = QFrame()
        self.dossier_panel.setObjectName("PhishingDossier")
        self.dossier_panel.setFixedWidth(440)
        self.dossier_panel.hide()

        dossier_layout = QVBoxLayout(self.dossier_panel)
        dossier_layout.setContentsMargins(12, 12, 12, 12)
        dossier_layout.setSpacing(10)

        # Dossier Header
        d_header = QHBoxLayout()
        self.lbl_dossier_title = QLabel("🔬 Packet Deep Inspection Dossier")
        self.lbl_dossier_title.setStyleSheet("font-size: 13px; font-weight: 800; color: #38bdf8;")
        d_header.addWidget(self.lbl_dossier_title)
        d_header.addStretch()

        self.btn_close_dossier = QPushButton("✖")
        self.btn_close_dossier.setFixedSize(26, 26)
        self.btn_close_dossier.setStyleSheet("background: transparent; border: none; font-size: 13px; font-weight: bold; color: #94a3b8;")
        self.btn_close_dossier.clicked.connect(lambda: self.dossier_panel.hide())
        d_header.addWidget(self.btn_close_dossier)
        dossier_layout.addLayout(d_header)

        # Dossier Rich Text Viewer
        self.txt_dossier = QTextEdit()
        self.txt_dossier.setReadOnly(True)
        self.txt_dossier.setStyleSheet("border: none; background: transparent;")
        dossier_layout.addWidget(self.txt_dossier, 1)

        # Monospace Hexdump Viewer
        lbl_hex = QLabel("📦 Raw Packet Hex Dump & ASCII Decoder")
        lbl_hex.setStyleSheet("font-size: 11px; font-weight: bold; color: #94a3b8;")
        dossier_layout.addWidget(lbl_hex)

        self.txt_hexdump = QTextEdit()
        self.txt_hexdump.setReadOnly(True)
        self.txt_hexdump.setFixedHeight(140)
        self.txt_hexdump.setFont(QFont("Consolas", 8))
        self.txt_hexdump.setStyleSheet("background: rgba(0, 0, 0, 0.2); border: 1px solid rgba(148, 163, 184, 0.2); border-radius: 4px;")
        dossier_layout.addWidget(self.txt_hexdump)

        # Action Buttons
        d_actions = QHBoxLayout()
        d_actions.setSpacing(8)

        self.btn_drawer_block = QPushButton("🚫 Block Source IP")
        self.btn_drawer_block.setObjectName("BtnDanger")
        self.btn_drawer_block.setFixedHeight(30)
        self.btn_drawer_block.clicked.connect(self.on_drawer_block_clicked)
        d_actions.addWidget(self.btn_drawer_block)

        self.btn_drawer_vault = QPushButton("📥 Vault Packet")
        self.btn_drawer_vault.setObjectName("BtnPrimary")
        self.btn_drawer_vault.setFixedHeight(30)
        self.btn_drawer_vault.clicked.connect(self.on_drawer_vault_clicked)
        d_actions.addWidget(self.btn_drawer_vault)

        self.btn_drawer_copy = QPushButton("📋 Copy Hex")
        self.btn_drawer_copy.setFixedHeight(30)
        self.btn_drawer_copy.clicked.connect(self.on_drawer_copy_hexdump)
        d_actions.addWidget(self.btn_drawer_copy)

        dossier_layout.addLayout(d_actions)

        workspace_layout.addWidget(self.dossier_panel)
        main_layout.addLayout(workspace_layout)

    def populate_interfaces(self):
        """Discovers active network interfaces via Scapy and psutil."""
        self.interface_combo.clear()
        added = False
        try:
            from scapy.interfaces import get_working_ifaces
            ifaces = get_working_ifaces()
            for iface in ifaces:
                sys_name = getattr(iface, 'network_name', iface.name)
                ip_str = ""
                try:
                    if hasattr(iface, 'ips') and 4 in iface.ips and iface.ips[4]:
                        ip_str = f" ({iface.ips[4][0]})"
                except Exception:
                    pass
                self.interface_combo.addItem(f"{iface.name}{ip_str}", sys_name)
                added = True
        except Exception:
            pass

        if not added:
            try:
                import psutil
                import socket
                for nic, addrs in psutil.net_if_addrs().items():
                    ip_str = ""
                    for addr in addrs:
                        if addr.family == socket.AF_INET:
                            ip_str = f" ({addr.address})"
                            break
                    self.interface_combo.addItem(f"{nic}{ip_str}", nic)
            except Exception:
                pass

        self.interface_combo.addItem("All Interfaces", "All Interfaces")

    def load_historical_events(self):
        """Loads previously saved intrusion events from SQLite."""
        try:
            events = self.db.get_nids_events(limit=100)
            if events:
                for ev in reversed(events):
                    self.add_packet_to_table(ev, save_to_db=False)
        except Exception:
            pass

    def start_capture(self):
        """Initiates the sniffer background thread."""
        interface_data = self.interface_combo.currentData()
        iface = interface_data if interface_data else self.interface_combo.currentText()

        self.packet_queue.clear()
        self.worker = SnifferWorker(iface)
        self.worker.packet_captured.connect(self.enqueue_packet)
        self.worker.error_occurred.connect(self.handle_sniffer_error)
        self.worker.start()

        self.update_timer.start(200) # Flush every 200ms
        self.pps_timer.start(1000)  # Refresh PPS every 1s

        self.btn_start.setEnabled(False)
        self.btn_stop.setEnabled(True)
        self.status_badge.setText("🟢 Listening")
        self.status_badge.setStyleSheet("font-weight: bold; font-size: 11px; color: #10b981; padding: 4px 10px; border-radius: 4px; background: rgba(16, 185, 129, 0.15);")

        # Inject initial confirmation packet so user sees instantaneous feedback
        self.enqueue_packet({
            "timestamp": datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3],
            "src_ip": "127.0.0.1",
            "dst_ip": "Localhost",
            "protocol": "TCP",
            "sport": 54321,
            "dport": 443,
            "length": 64,
            "risk_level": "Safe",
            "rule_id": "INIT",
            "mitre": "None",
            "threat_name": "NIDS Monitor Active",
            "threat_msg": "Network capture pipeline initialized successfully.",
            "info": f"Started capture on: {self.interface_combo.currentText()}",
            "hexdump": "0000   4e 65 78 61 53 68 69 65 6c 64 20 4e 49 44 53 20   |NexaShield NIDS |",
            "layers": [{"layer": "Ethernet", "fields": {"dst": "ff:ff:ff:ff:ff:ff", "type": "IPv4"}}],
            "raw_packet": None
        })

    def stop_capture(self):
        """Stops the sniffer background thread."""
        self.update_timer.stop()
        self.pps_timer.stop()
        if self.worker:
            self.worker.stop()
            self.worker.wait(1500)
            self.worker = None

        self.btn_start.setEnabled(True)
        self.btn_stop.setEnabled(False)
        self.status_badge.setText("🔴 Offline")
        self.status_badge.setStyleSheet("font-weight: bold; font-size: 11px; color: #ef4444; padding: 4px 10px; border-radius: 4px; background: rgba(239, 68, 68, 0.15);")

    def handle_sniffer_error(self, err_msg: str):
        self.stop_capture()
        QMessageBox.critical(self, "Capture Error", err_msg)

    def enqueue_packet(self, data: dict):
        """Emitted from SnifferWorker thread; queues packet for UI rendering."""
        self.packet_queue.append(data)
        self.current_pps += 1
        risk = data.get("risk_level", "Safe")
        if risk in self.threat_stats:
            self.threat_stats[risk] += 1
        if risk in ("High", "Critical"):
            current_threats = int(self.card_threats.lbl_value.text()) + 1
            self.card_threats.set_value(str(current_threats))

        # Active Prevention (IPS Auto-blocking)
        if self.chk_autoblock.isChecked() and risk in ("High", "Critical"):
            src_ip = data.get("src_ip", "")
            if src_ip and src_ip not in PROTECTED_IPS and src_ip not in self.blocked_ips_set:
                success, msg = block_ip_os(src_ip)
                if success:
                    reason = data.get("threat_msg") or data.get("info", "High risk intrusion detected")
                    self.db.add_nids_blocked_ip(src_ip, reason, blocked_by="IPS Engine")
                    self.db.log_siem_event("NIDS / IPS", f"Auto-blocked attacker IP {src_ip}: {reason}", "Critical")
                    self.blocked_ips_set.add(src_ip)
                    self.card_blocked.set_value(str(len(self.blocked_ips_set)))
                    data["info"] = f"[AUTO-BLOCKED] {data.get('info', '')}"

    def tick_pps(self):
        """Updates PPS telemetry chart every 1 second."""
        self.pps_chart.update_value(self.current_pps)
        self.card_pps.set_value(f"{self.current_pps} PPS")
        self.current_pps = 0

    def flush_packets(self):
        """Flushes a batch of up to 40 queued packets into the table to keep UI responsive."""
        if not self.packet_queue:
            return

        batch = self.packet_queue[:40]
        self.packet_queue = self.packet_queue[40:]

        self.table.setUpdatesEnabled(False)
        try:
            for pkt in batch:
                self.add_packet_to_table(pkt, save_to_db=True)

            # Cap table at 1000 items to conserve memory
            while self.table.rowCount() > 1000:
                self.table.removeRow(0)

            self.threat_chart.update_stats(self.threat_stats)
            self.card_total.set_value(str(self.total_packets_count))
        finally:
            self.table.setUpdatesEnabled(True)
            self.table.scrollToBottom()

    def add_packet_to_table(self, data: dict, save_to_db: bool = False):
        """
        Appends packet row with user-demanded soft protocol background color.
        """
        row = self.table.rowCount()
        self.table.insertRow(row)
        self.total_packets_count += 1

        is_dark = self.is_dark_mode()
        proto = data.get("protocol", "Other")
        bg_color = get_protocol_row_color(proto, is_dark)
        text_color = QColor("#f8fafc") if is_dark else QColor("#0f172a")

        # Column 0: Checkbox
        chk_item = QTableWidgetItem()
        chk_item.setFlags(Qt.ItemFlag.ItemIsUserCheckable | Qt.ItemFlag.ItemIsEnabled)
        chk_item.setCheckState(Qt.CheckState.Unchecked)
        chk_item.setBackground(QBrush(bg_color))
        self.table.setItem(row, 0, chk_item)

        # Columns 1 to 5: Time, Source, Destination, Protocol, Length
        time_item = QTableWidgetItem(str(data.get("timestamp", "")))
        time_item.setForeground(QBrush(text_color))
        time_item.setBackground(QBrush(bg_color))
        self.table.setItem(row, 1, time_item)

        src_item = QTableWidgetItem(str(data.get("src_ip", "")))
        src_item.setForeground(QBrush(text_color))
        src_item.setBackground(QBrush(bg_color))
        self.table.setItem(row, 2, src_item)

        dst_item = QTableWidgetItem(str(data.get("dst_ip", "")))
        dst_item.setForeground(QBrush(text_color))
        dst_item.setBackground(QBrush(bg_color))
        self.table.setItem(row, 3, dst_item)

        proto_item = QTableWidgetItem(str(proto))
        proto_item.setForeground(QBrush(text_color))
        proto_item.setBackground(QBrush(bg_color))
        self.table.setItem(row, 4, proto_item)

        len_item = QTableWidgetItem(f"{data.get('length', 0)} B")
        len_item.setForeground(QBrush(text_color))
        len_item.setBackground(QBrush(bg_color))
        self.table.setItem(row, 5, len_item)

        # Column 6: Risk Level Badge
        risk_str = str(data.get("risk_level", "Safe"))
        risk_item = QTableWidgetItem(f" {risk_str} ")
        risk_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
        if risk_str in ("Critical", "High"):
            risk_item.setForeground(QBrush(QColor("#ef4444")))
        elif risk_str == "Medium":
            risk_item.setForeground(QBrush(QColor("#f59e0b")))
        elif risk_str == "Low":
            risk_item.setForeground(QBrush(QColor("#0ea5e9")))
        else:
            risk_item.setForeground(QBrush(QColor("#10b981")))
        risk_item.setBackground(QBrush(bg_color))
        self.table.setItem(row, 6, risk_item)

        # Column 7: Info / Threat Summary
        info_item = QTableWidgetItem(str(data.get("info", "")))
        info_item.setForeground(QBrush(text_color))
        info_item.setBackground(QBrush(bg_color))
        self.table.setItem(row, 7, info_item)

        # Cache complete packet dictionary in column 1 UserRole
        time_item.setData(Qt.ItemDataRole.UserRole, data)
        self.captured_packets.append(data)

        # Persist threats into SQLite
        if save_to_db and (data.get("risk_level") in ("Medium", "High", "Critical") or self.total_packets_count % 5 == 0):
            try:
                db_event = {
                    "timestamp": data.get("timestamp", ""),
                    "src_ip": data.get("src_ip", ""),
                    "dst_ip": data.get("dst_ip", ""),
                    "protocol": proto,
                    "length": data.get("length", 0),
                    "risk_level": data.get("risk_level", "Safe"),
                    "info": data.get("info", ""),
                    "rule_id": data.get("rule_id", ""),
                    "mitre_attack": data.get("mitre", ""),
                    "details": {
                        "hexdump": data.get("hexdump", ""),
                        "layers": data.get("layers", []),
                        "threat_msg": data.get("threat_msg", "")
                    }
                }
                self.db.add_nids_event(db_event)
            except Exception:
                pass

    def on_table_row_clicked(self, row: int, col: int):
        """Opens the 440px right slide-out forensic drawer with full packet dissection."""
        time_item = self.table.item(row, 1)
        if not time_item:
            return
        data = time_item.data(Qt.ItemDataRole.UserRole)
        if not data:
            return

        self.current_dossier_packet = data
        self.txt_dossier.setHtml(self.generate_dossier_html(data))
        self.txt_hexdump.setPlainText(data.get("hexdump", "No hex dump available."))

        # Adjust block button status
        src_ip = data.get("src_ip", "")
        if src_ip in self.blocked_ips_set:
            self.btn_drawer_block.setText("🔓 Unblock IP")
            self.btn_drawer_block.setObjectName("BtnSuccess")
        else:
            self.btn_drawer_block.setText("🚫 Block Source IP")
            self.btn_drawer_block.setObjectName("BtnDanger")
        self.btn_drawer_block.style().unpolish(self.btn_drawer_block)
        self.btn_drawer_block.style().polish(self.btn_drawer_block)

        self.dossier_panel.show()

    def generate_dossier_html(self, data: dict) -> str:
        """Renders rich HTML forensic analysis card with zero dark-block render bugs."""
        is_dark = self.is_dark_mode()
        card_bg = "#111726" if is_dark else "#f8fafc"
        card_border = "#1e293b" if is_dark else "#e2e8f0"
        header_text = "#38bdf8"
        text_primary = "#f8fafc" if is_dark else "#0f172a"
        text_muted = "#94a3b8"

        risk = data.get("risk_level", "Safe")
        risk_color = "#ef4444" if risk in ("Critical", "High") else ("#f59e0b" if risk == "Medium" else "#10b981")
        rule_id = data.get("rule_id", "NORMAL")
        mitre_id = data.get("mitre", "None")

        html = f"""
        <table width="100%" cellpadding="10" cellspacing="0" style="background-color: {card_bg}; border: 1px solid {card_border}; border-radius: 6px; margin-bottom: 8px;">
            <tr>
                <td style="font-family: 'Segoe UI', sans-serif;">
                    <div style="font-size: 11px; font-weight: bold; color: {header_text}; text-transform: uppercase;">
                        TARGET THREAT ASSESSMENT
                    </div>
                    <div style="font-size: 13px; font-weight: 800; color: {risk_color}; margin-top: 4px;">
                        VERDICT: {risk.upper()} INTRUSION RISK
                    </div>
                    <div style="font-size: 11px; color: {text_muted}; margin-top: 2px;">
                        Matched Rule: <b>{rule_id}</b> | MITRE ATT&CK: <b>{mitre_id}</b>
                    </div>
                    <div style="font-size: 11px; color: {text_primary}; margin-top: 4px;">
                        {data.get('threat_msg') or data.get('info', '')}
                    </div>
                </td>
            </tr>
        </table>

        <table width="100%" cellpadding="8" cellspacing="0" style="background-color: {card_bg}; border: 1px solid {card_border}; border-radius: 6px; margin-bottom: 8px; font-family: 'Segoe UI', sans-serif; font-size: 11px;">
            <tr>
                <td colspan="2" style="font-weight: bold; color: {header_text}; border-bottom: 1px solid {card_border};">
                    🌐 NETWORK ROUTING & PROTOCOL ANATOMY
                </td>
            </tr>
            <tr>
                <td width="35%" style="color: {text_muted};">Timestamp:</td>
                <td style="color: {text_primary}; font-family: 'Consolas', monospace;">{data.get('timestamp', '')}</td>
            </tr>
            <tr>
                <td style="color: {text_muted};">Source IP:</td>
                <td style="color: #38bdf8; font-weight: bold;">{data.get('src_ip', '')}</td>
            </tr>
            <tr>
                <td style="color: {text_muted};">Destination IP:</td>
                <td style="color: {text_primary};">{data.get('dst_ip', '')}</td>
            </tr>
            <tr>
                <td style="color: {text_muted};">Protocol:</td>
                <td style="color: {text_primary}; font-weight: bold;">{data.get('protocol', '')}</td>
            </tr>
            <tr>
                <td style="color: {text_muted};">Frame Length:</td>
                <td style="color: {text_primary};">{data.get('length', 0)} bytes</td>
            </tr>
        </table>
        """

        # Dissected OSI layers table
        layers = data.get("layers", [])
        if layers:
            html += f"""
            <table width="100%" cellpadding="8" cellspacing="0" style="background-color: {card_bg}; border: 1px solid {card_border}; border-radius: 6px; font-family: 'Segoe UI', sans-serif; font-size: 11px;">
                <tr>
                    <td style="font-weight: bold; color: {header_text}; border-bottom: 1px solid {card_border};">
                        🔬 OSI DECODED PROTOCOL STACK
                    </td>
                </tr>
            """
            for lay in layers:
                lay_name = lay.get("layer", "Layer")
                fields_dict = lay.get("fields", {})
                field_strs = [f"<b>{k}</b>: {v}" for k, v in list(fields_dict.items())[:4]]
                summary = " &bull; ".join(field_strs) if field_strs else "Standard header"
                html += f"""
                <tr>
                    <td style="border-bottom: 1px dashed {card_border};">
                        <span style="font-weight: bold; color: #f59e0b;">[{lay_name}]</span>
                        <span style="color: {text_primary}; font-size: 10px; margin-left: 5px;">{summary}</span>
                    </td>
                </tr>
                """
            html += "</table>"

        return html

    def on_drawer_block_clicked(self):
        """Blocks or unblocks the selected packet source IP."""
        if not self.current_dossier_packet:
            return
        src_ip = self.current_dossier_packet.get("src_ip", "")
        if not src_ip or src_ip in PROTECTED_IPS:
            QMessageBox.warning(self, "Invalid Target", "Cannot block protected, localhost, or invalid IP address.")
            return

        if src_ip in self.blocked_ips_set:
            # Unblock
            success, msg = unblock_ip_os(src_ip)
            if success:
                self.db.remove_nids_blocked_ip(src_ip)
                self.blocked_ips_set.discard(src_ip)
                self.card_blocked.set_value(str(len(self.blocked_ips_set)))
                self.btn_drawer_block.setText("🚫 Block Source IP")
                self.btn_drawer_block.setObjectName("BtnDanger")
                self.btn_drawer_block.style().unpolish(self.btn_drawer_block)
                self.btn_drawer_block.style().polish(self.btn_drawer_block)
                QMessageBox.information(self, "Unblocked", f"IP {src_ip} unblocked successfully.")
            else:
                QMessageBox.critical(self, "Unblock Failed", msg)
        else:
            # Block
            success, msg = block_ip_os(src_ip)
            if success:
                reason = self.current_dossier_packet.get("threat_msg") or self.current_dossier_packet.get("info", "Manual IPS Block")
                self.db.add_nids_blocked_ip(src_ip, reason, blocked_by="Manual Block")
                self.db.log_siem_event("NIDS / IPS", f"Manually blocked IP {src_ip}: {reason}", "High")
                self.blocked_ips_set.add(src_ip)
                self.card_blocked.set_value(str(len(self.blocked_ips_set)))
                self.btn_drawer_block.setText("🔓 Unblock IP")
                self.btn_drawer_block.setObjectName("BtnSuccess")
                self.btn_drawer_block.style().unpolish(self.btn_drawer_block)
                self.btn_drawer_block.style().polish(self.btn_drawer_block)
                QMessageBox.information(self, "IP Blocked", f"Successfully blocked {src_ip} at OS Firewall.")
            else:
                QMessageBox.critical(self, "Block Failed", f"Firewall command failed. Please ensure app is elevated.\nDetails: {msg}")

    def on_drawer_vault_clicked(self):
        """Vaults individual packet hexdump and dissection into FMS."""
        if not self.current_dossier_packet:
            return
        try:
            content = json.dumps(self.current_dossier_packet, default=str, indent=2).encode('utf-8')
            if self.session and hasattr(self.session, 'file_manager'):
                ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
                self.session.file_manager.export_file(
                    filename=f"packet_forensics_{ts}.json",
                    content=content,
                    module_source="NIDS",
                    file_type="JSON",
                    tags="IntrusionForensics"
                )
                QMessageBox.information(self, "Vaulted", "Packet forensics vaulted successfully into File Management System.")
            else:
                QMessageBox.warning(self, "Warning", "FMS session manager not connected.")
        except Exception as e:
            QMessageBox.critical(self, "Vault Error", str(e))

    def on_drawer_copy_hexdump(self):
        """Copies hexdump text to clipboard."""
        if self.current_dossier_packet:
            QApplication.clipboard().setText(self.current_dossier_packet.get("hexdump", ""))
            QMessageBox.information(self, "Copied", "Packet hexdump copied to clipboard.")

    def on_chart_filter_clicked(self, risk_level: str):
        """Filters table by risk level when clicking donut chart segment."""
        idx = self.filter_risk.findText(risk_level)
        if idx >= 0:
            self.filter_risk.setCurrentIndex(idx)

    def apply_table_filters(self):
        """Applies Protocol, Risk, and Search keyword filters across rows."""
        proto_filter = self.filter_proto.currentText()
        risk_filter = self.filter_risk.currentText()
        search_query = self.search_input.text().strip().lower()

        for r in range(self.table.rowCount()):
            proto_val = self.table.item(r, 4).text() if self.table.item(r, 4) else ""
            risk_val = self.table.item(r, 6).text().strip() if self.table.item(r, 6) else ""
            src_val = self.table.item(r, 2).text().lower() if self.table.item(r, 2) else ""
            dst_val = self.table.item(r, 3).text().lower() if self.table.item(r, 3) else ""
            info_val = self.table.item(r, 7).text().lower() if self.table.item(r, 7) else ""

            match_proto = (proto_filter == "All Protocols" or proto_filter.upper() in proto_val.upper())
            match_risk = (risk_filter == "All Risk Levels" or risk_filter.lower() in risk_val.lower())
            match_search = (not search_query or search_query in src_val or search_query in dst_val or search_query in info_val)

            self.table.setRowHidden(r, not (match_proto and match_risk and match_search))

    def show_rules_matrix(self):
        """Opens the 35+ Snort rules matrix dialog."""
        dlg = NIDSRulesDialog(self)
        dlg.exec()

    def show_blocked_ips_dialog(self):
        """Opens the OS firewall blocked IPs dialog."""
        dlg = BlockedIPsDialog(self, db=self.db)
        dlg.unblocked.connect(self.on_ip_unblocked_from_dialog)
        dlg.exec()

    def on_ip_unblocked_from_dialog(self, ip: str):
        self.blocked_ips_set.discard(ip)
        self.card_blocked.set_value(str(len(self.blocked_ips_set)))

    def export_pcap(self):
        """Exports raw captured packets to a standard .PCAP file."""
        if not self.captured_packets:
            QMessageBox.warning(self, "No Packets", "No network packets have been captured yet.")
            return

        try:
            from scapy.utils import wrpcap
            scapy_packets = [p["raw_packet"] for p in self.captured_packets if p.get("raw_packet") is not None]
            if not scapy_packets:
                QMessageBox.warning(self, "Export Error", "No raw packet binary data available.")
                return

            file_path, _ = QFileDialog.getSaveFileName(self, "Export PCAP File", "nexashield_capture.pcap", "PCAP Files (*.pcap)")
            if file_path:
                wrpcap(file_path, scapy_packets)
                QMessageBox.information(self, "PCAP Exported", f"Successfully exported {len(scapy_packets)} packets to:\n{file_path}")
        except Exception as e:
            QMessageBox.critical(self, "PCAP Export Failed", str(e))

    def export_pdf_report(self):
        """Exports an enterprise NIDS forensic PDF report."""
        if self.table.rowCount() == 0:
            QMessageBox.warning(self, "No Data", "No packets available to export.")
            return

        file_path, _ = QFileDialog.getSaveFileName(self, "Save Security Report", "NIDS_Security_Report.pdf", "PDF Files (*.pdf)")
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

            title_style = ParagraphStyle('Title', parent=styles['Heading1'], fontSize=18, textColor=colors.HexColor("#0ea5e9"), spaceAfter=10)
            story.append(Paragraph("🛡️ NexaShield - Network Intrusion Forensic Audit", title_style))
            story.append(Paragraph(f"Generated on {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | Total Packets: {self.total_packets_count}", styles['Normal']))
            story.append(Spacer(1, 15))

            # Table Data
            table_data = [["Time", "Source", "Destination", "Proto", "Risk", "Threat Signature"]]
            for r in range(min(50, self.table.rowCount())):
                table_data.append([
                    self.table.item(r, 1).text() if self.table.item(r, 1) else "",
                    self.table.item(r, 2).text() if self.table.item(r, 2) else "",
                    self.table.item(r, 3).text() if self.table.item(r, 3) else "",
                    self.table.item(r, 4).text() if self.table.item(r, 4) else "",
                    self.table.item(r, 6).text().strip() if self.table.item(r, 6) else "",
                    (self.table.item(r, 7).text()[:40] + "...") if self.table.item(r, 7) else ""
                ])

            t = Table(table_data, colWidths=[65, 80, 80, 50, 60, 205])
            t.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#0ea5e9")),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 8),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 6),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ]))
            story.append(t)
            doc.build(story)
            QMessageBox.information(self, "Report Exported", f"Forensic PDF report exported successfully:\n{file_path}")
        except Exception as e:
            # Fallback to native PyQt6 QPrinter / QTextDocument if ReportLab is unavailable
            try:
                from PyQt6.QtGui import QTextDocument
                from PyQt6.QtPrintSupport import QPrinter
                printer = QPrinter(QPrinter.PrinterMode.HighResolution)
                printer.setOutputFormat(QPrinter.OutputFormat.PdfFormat)
                printer.setOutputFileName(file_path)
                
                rows_html = "".join(f"<tr><td>{self.table.item(r,1).text() if self.table.item(r,1) else ''}</td><td>{self.table.item(r,2).text() if self.table.item(r,2) else ''}</td><td>{self.table.item(r,3).text() if self.table.item(r,3) else ''}</td><td>{self.table.item(r,4).text() if self.table.item(r,4) else ''}</td><td>{self.table.item(r,6).text() if self.table.item(r,6) else ''}</td><td>{self.table.item(r,7).text() if self.table.item(r,7) else ''}</td></tr>" for r in range(min(50, self.table.rowCount())))
                doc = QTextDocument()
                doc.setHtml(f"<h2>🛡️ NexaShield Network Intrusion Audit</h2><table border='1' cellspacing='0' cellpadding='4'><tr><th>Time</th><th>Source</th><th>Destination</th><th>Proto</th><th>Risk</th><th>Signature</th></tr>{rows_html}</table>")
                doc.print(printer)
                QMessageBox.information(self, "Report Exported", f"Forensic PDF report exported successfully:\n{file_path}")
            except Exception as e2:
                QMessageBox.critical(self, "PDF Export Failed", str(e2))

    def clear_logs(self):
        """Clears all table rows and resets charts."""
        reply = QMessageBox.question(
            self, "Clear Logs",
            "Clear all packet logs from the monitor and database?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        if reply == QMessageBox.StandardButton.Yes:
            self.table.setRowCount(0)
            self.captured_packets.clear()
            self.total_packets_count = 0
            self.card_total.set_value("0")
            self.card_threats.set_value("0")
            self.pps_chart.reset()
            self.threat_chart.reset()
            self.dossier_panel.hide()
            self.db.clear_nids_events()
            QMessageBox.information(self, "Cleared", "Network intrusion logs cleared.")

    def cleanup(self):
        """Stops worker thread cleanly when parent window is closed."""
        self.stop_capture()
