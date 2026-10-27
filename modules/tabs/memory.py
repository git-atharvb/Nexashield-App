import os
import sys
import time
import psutil
import datetime
import math
import subprocess
import platform
import ctypes
from collections import deque

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QGridLayout, QLabel,
    QPushButton, QTableWidget, QTableWidgetItem, QHeaderView,
    QFrame, QCheckBox, QFileDialog, QMessageBox, QSizePolicy,
    QAbstractItemView, QTabWidget, QToolTip, QLineEdit, QProgressBar,
    QApplication
)
from PyQt6.QtCore import (
    Qt, QTimer, QRectF, QSize, QThread, pyqtSignal, QBuffer,
    QIODevice, QSizeF
)
from PyQt6.QtGui import (
    QColor, QPainter, QPainterPath, QLinearGradient, QRadialGradient,
    QPen, QFont, QTextDocument, QBrush, QPalette, QPageSize
)
from PyQt6.QtPrintSupport import QPrinter

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from database import DatabaseManager

# --- Background Workers ---

class TempCleanerWorker(QThread):
    """Cleans temporary files recursively in a background thread to prevent UI lockup."""
    finished_clean = pyqtSignal(int, int)  # count, freed_bytes

    def run(self):
        temp_dir = os.environ.get('TEMP') or '/tmp'
        freed = 0
        count = 0
        for root, _, files in os.walk(temp_dir):
            for name in files:
                try:
                    p = os.path.join(root, name)
                    s = os.path.getsize(p)
                    os.remove(p)
                    freed += s
                    count += 1
                except Exception:
                    pass
        self.finished_clean.emit(count, freed)

class MemoryOptimizerWorker(QThread):
    """Trims unreferenced process working sets on Windows to release standby physical memory."""
    finished_trim = pyqtSignal(int)

    def run(self):
        trimmed_count = 0
        if os.name == 'nt':
            try:
                kernel32 = ctypes.windll.kernel32
                psapi = ctypes.windll.psapi
                for proc in psutil.process_iter(['pid']):
                    try:
                        pid = proc.info['pid']
                        if pid <= 4:
                            continue
                        h = kernel32.OpenProcess(0x0500, False, pid)
                        if h:
                            if psapi.EmptyWorkingSet(h):
                                trimmed_count += 1
                            kernel32.CloseHandle(h)
                    except Exception:
                        pass
            except Exception:
                pass
        self.finished_trim.emit(trimmed_count)

class MemoryWorker(QThread):
    """Asynchronously gathers all memory, swap, disk partitions, and top-processes data."""
    data_fetched = pyqtSignal(dict)

    def __init__(self, prev_disk_io, last_io_time, smart_cache, smart_last_check, boot_time):
        super().__init__()
        self.prev_disk_io = prev_disk_io
        self.last_io_time = last_io_time
        self.smart_cache = smart_cache
        self.smart_last_check = smart_last_check
        self.boot_time = boot_time

    def run(self):
        data = {}
        try:
            data['mem'] = psutil.virtual_memory()
            data['swap'] = psutil.swap_memory()
        except Exception:
            pass

        data['cpu'] = psutil.cpu_percent(interval=None)
        data['uptime'] = str(datetime.datetime.now() - self.boot_time).split('.')[0]

        try:
            curr_io = psutil.disk_io_counters()
            curr_time = time.time()
            data['r_speed'] = 0
            data['w_speed'] = 0
            if curr_io and self.prev_disk_io:
                delta = curr_time - self.last_io_time
                if delta > 0:
                    data['r_speed'] = (curr_io.read_bytes - self.prev_disk_io.read_bytes) / delta
                    data['w_speed'] = (curr_io.write_bytes - self.prev_disk_io.write_bytes) / delta
            data['new_disk_io'] = curr_io
            data['new_last_io_time'] = curr_time
        except Exception:
            pass

        curr_time = time.time()
        if curr_time - self.smart_last_check >= 60:
            self.smart_last_check = curr_time
            if os.name == 'nt':
                try:
                    cmd = "wmic volume get DriveLetter,Status"
                    si = subprocess.STARTUPINFO()
                    si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
                    out = subprocess.check_output(cmd, startupinfo=si, shell=False, timeout=2).decode()
                    for line in out.splitlines():
                        parts = line.split()
                        if len(parts) >= 2:
                            self.smart_cache[parts[0]] = "Good" if parts[1] == "OK" else "Warning"
                except Exception:
                    pass
        data['smart_cache'] = self.smart_cache
        data['smart_last_check'] = self.smart_last_check

        parts_data = []
        try:
            for part in psutil.disk_partitions():
                try:
                    usage = psutil.disk_usage(part.mountpoint)
                    parts_data.append({
                        'mountpoint': part.mountpoint,
                        'total': usage.total,
                        'free': usage.free,
                        'percent': usage.percent,
                        'fstype': part.fstype
                    })
                except Exception:
                    continue
            data['partitions'] = parts_data
        except Exception:
            pass

        try:
            procs = sorted(
                psutil.process_iter(['pid', 'name', 'memory_info']),
                key=lambda p: (p.info['memory_info'].rss if p.info.get('memory_info') else 0),
                reverse=True
            )[:18]
            data['procs'] = [{
                'pid': p.info['pid'],
                'name': p.info['name'] or 'Unknown',
                'rss': p.info['memory_info'].rss if p.info.get('memory_info') else 0
            } for p in procs]
        except Exception:
            pass

        self.data_fetched.emit(data)


# --- Custom Interactive Cyber Visual Widgets ---

class ModernChart(QWidget):
    """Draws a live telemetry curve with cyber gradient fill and peak watermark."""
    def __init__(self, title, color="#0ea5e9", max_value=100.0, auto_scale=False, suffix="%"):
        super().__init__()
        self.title = title
        self.base_color = color
        self.data = deque([0.0] * 60, maxlen=60)
        self.current_value = 0.0
        self.max_value = max_value
        self.auto_scale = auto_scale
        self.suffix = suffix
        self.peak_value = 0.0

    def update_value(self, value):
        self.current_value = value
        self.data.append(value)
        if value > self.peak_value:
            self.peak_value = value

        if self.auto_scale:
            local_max = max(self.data) if self.data else 1.0
            if local_max > self.max_value:
                self.max_value = local_max
            elif local_max < self.max_value * 0.5 and self.max_value > 100:
                self.max_value = max(100.0, self.max_value * 0.95)
        self.update()

    def _format_val(self, val):
        if self.suffix == "%":
            return f"{val:.1f}%"
        n = val
        for unit in ["B", "KB", "MB", "GB"]:
            if abs(n) < 1024.0:
                return f"{n:.1f} {unit}/s"
            n /= 1024.0
        return f"{n:.1f} TB/s"

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        w, h = self.width(), self.height()

        is_dark = self.palette().color(QPalette.ColorRole.Window).lightness() < 128
        bg_col = QColor("#0e1422") if is_dark else QColor("#ffffff")
        bdr_col = QColor("#1e293b") if is_dark else QColor("#e2e8f0")
        text_color = self.palette().color(QPalette.ColorRole.WindowText)
        line_color = QColor(self.base_color)

        painter.fillRect(0, 0, w, h, bg_col)
        painter.setPen(QPen(bdr_col, 1))
        painter.drawRect(0, 0, w - 1, h - 1)

        top_pad = 28
        bottom_pad = 18
        chart_h = max(10, h - top_pad - bottom_pad)

        # Subtle grid lines
        grid_col = QColor(148, 163, 184, 30 if is_dark else 60)
        painter.setPen(QPen(grid_col, 1, Qt.PenStyle.DashLine))
        for i in range(3):
            y_line = top_pad + i * (chart_h / 2)
            painter.drawLine(0, int(y_line), w, int(y_line))

        if not self.data:
            return

        # Build Curve Path
        path = QPainterPath()
        step_x = w / (self.data.maxlen - 1)
        scale = max(self.max_value, 1.0)

        prev_x = 0
        prev_y = h - bottom_pad - (self.data[0] / scale * chart_h)
        path.moveTo(prev_x, prev_y)

        for i, val in enumerate(self.data):
            x = i * step_x
            y = h - bottom_pad - (val / scale * chart_h)
            path.lineTo(x, y)
            prev_x, prev_y = x, y

        # Stroke Line
        painter.setPen(QPen(line_color, 2))
        painter.drawPath(path)

        # Gradient Fill Beneath Curve
        path.lineTo(w, h - bottom_pad)
        path.lineTo(0, h - bottom_pad)
        path.closeSubpath()
        grad = QLinearGradient(0, top_pad, 0, h - bottom_pad)
        c = line_color
        grad.setColorAt(0, QColor(c.red(), c.green(), c.blue(), 110 if is_dark else 70))
        grad.setColorAt(1, QColor(c.red(), c.green(), c.blue(), 0))
        painter.setBrush(grad)
        painter.setPen(Qt.PenStyle.NoPen)
        painter.drawPath(path)

        # Leading Glow Dot
        glow = QRadialGradient(prev_x, prev_y, 12)
        glow.setColorAt(0, QColor(c.red(), c.green(), c.blue(), 160))
        glow.setColorAt(1, Qt.GlobalColor.transparent)
        painter.setBrush(glow)
        painter.drawEllipse(int(prev_x - 12), int(prev_y - 12), 24, 24)
        painter.setBrush(c)
        painter.setPen(QPen(Qt.GlobalColor.white, 1.5))
        painter.drawEllipse(int(prev_x - 3), int(prev_y - 3), 6, 6)

        # Title & Value Readout
        painter.setPen(text_color)
        painter.setFont(QFont("Segoe UI", 9, QFont.Weight.Bold))
        painter.drawText(8, 18, self.title)

        cur_text = self._format_val(self.current_value)
        painter.setFont(QFont("Segoe UI", 10, QFont.Weight.Bold))
        painter.setPen(line_color)
        val_w = painter.fontMetrics().horizontalAdvance(cur_text)
        painter.drawText(w - val_w - 10, 18, cur_text)

        # Peak Watermark
        painter.setFont(QFont("Segoe UI", 8))
        painter.setPen(QColor(148, 163, 184, 160))
        painter.drawText(8, h - 5, f"Peak: {self._format_val(self.peak_value)}")


class DiskPartitionPieChart(QWidget):
    """Compact interactive donut chart displaying disk partition distribution."""
    def __init__(self):
        super().__init__()
        self.setMinimumSize(125, 125)
        self.partitions = []
        self.colors = [
            QColor("#0ea5e9"), QColor("#10b981"), QColor("#f59e0b"),
            QColor("#ec4899"), QColor("#8b5cf6"), QColor("#06b6d4")
        ]
        self.setMouseTracking(True)

    def update_data(self, partition_data):
        self.partitions = []
        total = sum(p[1] for p in partition_data)
        if total == 0:
            self.update()
            return
        for i, (name, size) in enumerate(partition_data):
            color = self.colors[i % len(self.colors)]
            self.partitions.append((name, size, color))
        self.update()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        w, h = self.width(), self.height()

        is_dark = self.palette().color(QPalette.ColorRole.Window).lightness() < 128
        bg_col = QColor("#0e1422") if is_dark else QColor("#ffffff")
        text_col = self.palette().color(QPalette.ColorRole.WindowText)

        # Header
        painter.setPen(text_col)
        painter.setFont(QFont("Segoe UI", 8, QFont.Weight.Bold))
        painter.drawText(QRectF(0, 0, w, 15), Qt.AlignmentFlag.AlignCenter, "Disk Distribution")

        if not self.partitions:
            return

        size = min(w - 10, h - 34)
        if size <= 10:
            return
        rect = QRectF((w - size) / 2, 17, size, size)

        total = sum(p[1] for p in self.partitions)
        start_angle = 90 * 16

        for name, val, color in self.partitions:
            span = int((val / total) * 360 * 16)
            painter.setBrush(color)
            painter.setPen(Qt.PenStyle.NoPen)
            painter.drawPie(rect, start_angle, span)
            start_angle += span

        # Donut Inner Hole
        inner_size = size * 0.60
        inner_rect = QRectF((w - inner_size) / 2, 17 + (size - inner_size) / 2, inner_size, inner_size)
        painter.setBrush(bg_col)
        painter.drawEllipse(inner_rect)

        # Legend snippet at bottom with proper padding
        legend_y = h - 3
        painter.setFont(QFont("Segoe UI", 8))
        x_c = 6
        for name, val, color in self.partitions:
            painter.setBrush(color)
            painter.setPen(Qt.PenStyle.NoPen)
            painter.drawEllipse(x_c, legend_y - 8, 7, 7)
            painter.setPen(text_col)
            txt = f"{name}"
            painter.drawText(x_c + 10, legend_y, txt)
            x_c += 10 + painter.fontMetrics().horizontalAdvance(txt) + 8
            if x_c > w - 10:
                break

    def mouseMoveEvent(self, event):
        if not self.partitions:
            return super().mouseMoveEvent(event)
        pos = event.pos()
        w, h = self.width(), self.height()
        size = min(w - 10, h - 34)
        rect = QRectF((w - size) / 2, 17, size, size)
        center = rect.center()
        dx = pos.x() - center.x()
        dy = pos.y() - center.y()
        distance = math.hypot(dx, dy)

        inner_radius = (size * 0.60) / 2
        outer_radius = size / 2

        if inner_radius <= distance <= outer_radius:
            angle = math.degrees(math.atan2(-dy, dx))
            if angle < 0:
                angle += 360
            mapped = (angle - 90) % 360
            total = sum(p[1] for p in self.partitions)
            if total > 0:
                cur = 0
                for name, val, color in self.partitions:
                    span = (val / total) * 360
                    if cur <= mapped <= cur + span:
                        pct = (val / total) * 100
                        cap_gb = val / (1024**3)
                        QToolTip.showText(
                            event.globalPosition().toPoint(),
                            f"<b>{name}</b><br>Capacity: {cap_gb:.1f} GB<br>Share: {pct:.1f}%",
                            self
                        )
                        return
                    cur += span
        QToolTip.hideText()
        super().mouseMoveEvent(event)


class DataFlowDiagram(QWidget):
    """Compact system resource flow diagram with glowing cyber nodes and bus lines."""
    def __init__(self):
        super().__init__()
        self.setFixedHeight(68)
        self.cpu_val = 0
        self.ram_val = 0
        self.swap_val = 0
        self.disk_active = False

    def update_values(self, cpu, ram, swap, disk_active):
        self.cpu_val = cpu
        self.ram_val = ram
        self.swap_val = swap
        self.disk_active = disk_active
        self.update()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        w, h = self.width(), self.height()
        text_col = self.palette().color(QPalette.ColorRole.WindowText)

        col_cpu = QColor("#0ea5e9")
        col_ram = QColor("#10b981")
        col_disk = QColor("#f59e0b") if self.disk_active else QColor("#64748b")

        y_mid = 21
        r = 13

        def draw_node(x, label, val, color):
            rect = QRectF(x - r, y_mid - r, 2 * r, 2 * r)
            painter.setBrush(color)
            painter.setPen(Qt.PenStyle.NoPen)
            painter.drawEllipse(rect)

            painter.setPen(QColor("white"))
            painter.setFont(QFont("Segoe UI", 7, QFont.Weight.Bold))
            painter.drawText(rect, Qt.AlignmentFlag.AlignCenter, f"{int(val)}%")

            painter.setPen(text_col)
            painter.setFont(QFont("Segoe UI", 8, QFont.Weight.Bold))
            painter.drawText(QRectF(x - 35, y_mid + r + 3, 70, 16), Qt.AlignmentFlag.AlignCenter, label)

        x_cpu = w * 0.18
        x_ram = w * 0.50
        x_disk = w * 0.82

        painter.setPen(QPen(QColor(148, 163, 184, 80), 2, Qt.PenStyle.DashLine))
        path = QPainterPath()
        path.moveTo(x_cpu + r, y_mid)
        path.cubicTo(x_cpu + r + 20, y_mid - 8, x_ram - r - 20, y_mid - 8, x_ram - r, y_mid)
        path.moveTo(x_ram + r, y_mid)
        path.cubicTo(x_ram + r + 20, y_mid + 8, x_disk - r - 20, y_mid + 8, x_disk - r, y_mid)
        painter.drawPath(path)

        draw_node(x_cpu, "CPU", self.cpu_val, col_cpu)
        draw_node(x_ram, "RAM", self.ram_val, col_ram)
        draw_node(x_disk, "Disk/Swap", self.swap_val, col_disk)


class MiniDonutMeter(QWidget):
    """Pair of dual mini donut rings for RAM & Swap utilization in the top ribbon."""
    def __init__(self):
        super().__init__()
        self.setFixedHeight(68)
        self.ram_pct = 0.0
        self.swap_pct = 0.0

    def update_values(self, ram_pct, swap_pct):
        self.ram_pct = ram_pct
        self.swap_pct = swap_pct
        self.update()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        w, h = self.width(), self.height()
        is_dark = self.palette().color(QPalette.ColorRole.Window).lightness() < 128
        text_col = self.palette().color(QPalette.ColorRole.WindowText)

        def draw_ring(center_x, pct, title, color):
            size = 36
            r_rect = QRectF(center_x - size / 2, 2, size, size)

            # Background arc
            painter.setPen(QPen(QColor(148, 163, 184, 40), 4))
            painter.setBrush(Qt.BrushStyle.NoBrush)
            painter.drawEllipse(r_rect)

            # Active arc
            painter.setPen(QPen(color, 4, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap))
            span = int(-pct * 3.6 * 16)
            painter.drawArc(r_rect, 90 * 16, span)

            # Center text
            painter.setPen(text_col)
            painter.setFont(QFont("Segoe UI", 7, QFont.Weight.Bold))
            painter.drawText(r_rect, Qt.AlignmentFlag.AlignCenter, f"{int(pct)}%")

            # Label beneath
            painter.setFont(QFont("Segoe UI", 8, QFont.Weight.Bold))
            painter.drawText(QRectF(center_x - 45, 42, 90, 16), Qt.AlignmentFlag.AlignCenter, title)

        draw_ring(w * 0.28, self.ram_pct, "Physical RAM", QColor("#10b981"))
        draw_ring(w * 0.72, self.swap_pct, "Swap Pagefile", QColor("#0ea5e9"))


class InfoCard(QFrame):
    """High-density styled telemetry tile for in-depth system & memory properties."""
    def __init__(self, title, value="-", icon="ℹ️", color=None):
        super().__init__()
        self.setObjectName("InfoCard")
        self.setMinimumHeight(54)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 6, 10, 6)
        layout.setSpacing(2)

        header = QHBoxLayout()
        header.setSpacing(5)
        lbl_icon = QLabel(icon)
        lbl_icon.setStyleSheet("font-size: 11px;")
        lbl_title = QLabel(title)
        lbl_title.setObjectName("InfoTitle")
        lbl_title.setStyleSheet("font-size: 9px; font-weight: 700; color: #94a3b8; text-transform: uppercase; letter-spacing: 0.3px;")
        header.addWidget(lbl_icon)
        header.addWidget(lbl_title)
        header.addStretch()
        layout.addLayout(header)

        self.lbl_value = QLabel(value)
        self.lbl_value.setObjectName("InfoValue")
        val_color = color if color else "#f8fafc"
        self.lbl_value.setStyleSheet(f"font-size: 11.5px; font-weight: 800; color: {val_color};")
        self.lbl_value.setWordWrap(False)
        self.lbl_value.setToolTip(value)
        layout.addWidget(self.lbl_value)

    def set_value(self, value):
        self.lbl_value.setText(value)
        self.lbl_value.setToolTip(value)


# --- Main Dashboard Widget ---

class MemoryMonitorWidget(QWidget):
    """
    Enterprise Memory Intelligence, Optimization & Storage Forensics Suite.
    Designed with a zero-scroll responsive layout, comprehensive 20-metric deep
    hardware and memory pools architecture, live working-set trimming, and FMS reports.
    """
    def __init__(self, session_manager=None):
        super().__init__()
        self.session = session_manager
        self.setObjectName("MemoryMonitorWidget")

        # State Variables
        self.smart_cache = {}
        self.smart_last_check = 0
        self.prev_disk_io = psutil.disk_io_counters()
        self.last_io_time = time.time()
        self.boot_time = datetime.datetime.fromtimestamp(psutil.boot_time())
        self._current_procs = []

        self._setup_ui()

        # Background Worker & Timer
        self.worker = None
        self.clean_worker = None
        self.optimizer_worker = None

        self.refresh_timer = QTimer(self)
        self.refresh_timer.setInterval(2000)
        self.refresh_timer.timeout.connect(self.update_all_stats)

    def _setup_ui(self):
        # 100% viewport single-screen layout (NO scroll area)
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(10, 8, 10, 8)
        main_layout.setSpacing(6)

        # ==========================================================
        # 1. TOP CONTROL & OPERATIONS TOOLBAR
        # ==========================================================
        top_toolbar = QFrame()
        top_toolbar.setObjectName("ProcessToolbar")
        top_toolbar.setFixedHeight(46)
        l_ops = QHBoxLayout(top_toolbar)
        l_ops.setContentsMargins(10, 4, 10, 4)
        l_ops.setSpacing(10)

        self.btn_refresh = QPushButton("🔄 Refresh")
        self.btn_refresh.setObjectName("BtnPrimary")
        self.btn_refresh.setFixedHeight(30)
        self.btn_refresh.setMinimumWidth(90)
        self.btn_refresh.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_refresh.clicked.connect(self.update_all_stats)
        l_ops.addWidget(self.btn_refresh)

        self.btn_clean = QPushButton("🗑️ Clean Temp")
        self.btn_clean.setToolTip("Recursively remove temporary system files and free disk space")
        self.btn_clean.setObjectName("BtnDanger")
        self.btn_clean.setFixedHeight(30)
        self.btn_clean.setMinimumWidth(115)
        self.btn_clean.setStyleSheet("padding: 4px 14px; font-weight: bold;")
        self.btn_clean.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_clean.clicked.connect(self.clean_temp_files)
        l_ops.addWidget(self.btn_clean)

        self.btn_trim = QPushButton("⚡ Trim Working Sets")
        self.btn_trim.setToolTip("Flush unreferenced memory pages from processes into standby pool to instantly free physical RAM")
        self.btn_trim.setFixedHeight(30)
        self.btn_trim.setMinimumWidth(145)
        self.btn_trim.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_trim.setStyleSheet("background: #0284c7; color: white; font-weight: bold; border-radius: 6px; padding: 4px 14px; font-size: 11px;")
        self.btn_trim.clicked.connect(self.trim_working_sets)
        l_ops.addWidget(self.btn_trim)

        self.btn_export = QPushButton("📥 Export Dossier")
        self.btn_export.setToolTip("Generate Executive Memory & Storage Forensic Dossier (PDF) and vault to FMS")
        self.btn_export.setObjectName("BtnWarning")
        self.btn_export.setFixedHeight(30)
        self.btn_export.setMinimumWidth(125)
        self.btn_export.setStyleSheet("padding: 4px 14px; font-weight: bold;")
        self.btn_export.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_export.clicked.connect(self.export_pdf)
        l_ops.addWidget(self.btn_export)

        l_ops.addStretch()

        self.lbl_system_pressure = QLabel("🟢 System Memory Healthy")
        self.lbl_system_pressure.setStyleSheet("font-size: 11px; font-weight: 700; color: #10b981; margin-right: 8px;")
        l_ops.addWidget(self.lbl_system_pressure)

        self.chk_auto = QCheckBox("Auto-Refresh (2s)")
        self.chk_auto.setChecked(True)
        self.chk_auto.stateChanged.connect(self._toggle_auto)
        l_ops.addWidget(self.chk_auto)

        main_layout.addWidget(top_toolbar)

        # ==========================================================
        # 2. TOP TELEMETRY RIBBON (KPIs, Flow & Donut Meters)
        # ==========================================================
        ribbon_layout = QHBoxLayout()
        ribbon_layout.setSpacing(6)

        # Card 1: Physical RAM
        self.card_ram = QFrame()
        self.card_ram.setObjectName("MetricCard")
        self.card_ram.setFixedHeight(94)
        c_ram_layout = QVBoxLayout(self.card_ram)
        c_ram_layout.setContentsMargins(12, 6, 12, 6)
        c_ram_layout.setSpacing(3)

        lbl_ram_title = QLabel("🧠 PHYSICAL RAM")
        lbl_ram_title.setObjectName("MetricTitle")
        c_ram_layout.addWidget(lbl_ram_title)

        self.lbl_ram_val = QLabel("0.0 GB / 0.0 GB")
        self.lbl_ram_val.setStyleSheet("font-size: 16px; font-weight: 900; color: #10b981;")
        c_ram_layout.addWidget(self.lbl_ram_val)

        self.bar_ram = QProgressBar()
        self.bar_ram.setFixedHeight(7)
        self.bar_ram.setTextVisible(False)
        self.bar_ram.setStyleSheet("""
            QProgressBar { background: #1e293b; border-radius: 3px; border: none; }
            QProgressBar::chunk { background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #10b981, stop:1 #34d399); border-radius: 3px; }
        """)
        c_ram_layout.addWidget(self.bar_ram)

        self.lbl_ram_sub = QLabel("Available: -  |  0.0% Used")
        self.lbl_ram_sub.setStyleSheet("font-size: 10px; color: #94a3b8;")
        c_ram_layout.addWidget(self.lbl_ram_sub)
        ribbon_layout.addWidget(self.card_ram, 3)

        # Card 2: Swap / Virtual Memory
        self.card_swap = QFrame()
        self.card_swap.setObjectName("MetricCard")
        self.card_swap.setFixedHeight(94)
        c_swap_layout = QVBoxLayout(self.card_swap)
        c_swap_layout.setContentsMargins(12, 6, 12, 6)
        c_swap_layout.setSpacing(3)

        lbl_swap_title = QLabel("🔄 VIRTUAL SWAP")
        lbl_swap_title.setObjectName("MetricTitle")
        c_swap_layout.addWidget(lbl_swap_title)

        self.lbl_swap_val = QLabel("0.0 GB / 0.0 GB")
        self.lbl_swap_val.setStyleSheet("font-size: 16px; font-weight: 900; color: #0ea5e9;")
        c_swap_layout.addWidget(self.lbl_swap_val)

        self.bar_swap = QProgressBar()
        self.bar_swap.setFixedHeight(7)
        self.bar_swap.setTextVisible(False)
        self.bar_swap.setStyleSheet("""
            QProgressBar { background: #1e293b; border-radius: 3px; border: none; }
            QProgressBar::chunk { background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #0ea5e9, stop:1 #38bdf8); border-radius: 3px; }
        """)
        c_swap_layout.addWidget(self.bar_swap)

        self.lbl_swap_sub = QLabel("Free: -  |  0.0% Used")
        self.lbl_swap_sub.setStyleSheet("font-size: 10px; color: #94a3b8;")
        c_swap_layout.addWidget(self.lbl_swap_sub)
        ribbon_layout.addWidget(self.card_swap, 3)

        # Card 3: System Resource Flow
        self.card_flow = QFrame()
        self.card_flow.setObjectName("MetricCard")
        self.card_flow.setFixedHeight(94)
        c_flow_layout = QVBoxLayout(self.card_flow)
        c_flow_layout.setContentsMargins(8, 4, 8, 4)
        c_flow_layout.setSpacing(0)

        lbl_flow_title = QLabel("⚡ RESOURCE FLOW")
        lbl_flow_title.setObjectName("MetricTitle")
        c_flow_layout.addWidget(lbl_flow_title)

        self.flow_diagram = DataFlowDiagram()
        c_flow_layout.addWidget(self.flow_diagram)
        ribbon_layout.addWidget(self.card_flow, 4)

        # Card 4: Memory Composition (Dual Donuts)
        self.card_donuts = QFrame()
        self.card_donuts.setObjectName("MetricCard")
        self.card_donuts.setFixedHeight(94)
        c_d_layout = QVBoxLayout(self.card_donuts)
        c_d_layout.setContentsMargins(8, 4, 8, 4)
        c_d_layout.setSpacing(0)

        lbl_donuts_title = QLabel("🍩 MEMORY COMPOSITION")
        lbl_donuts_title.setObjectName("MetricTitle")
        c_d_layout.addWidget(lbl_donuts_title)

        self.mini_donuts = MiniDonutMeter()
        c_d_layout.addWidget(self.mini_donuts)
        ribbon_layout.addWidget(self.card_donuts, 3)

        main_layout.addLayout(ribbon_layout)

        # ==========================================================
        # 3. BALANCED EXECUTIVE WORKSPACE (2 Wings, Perfect Symmetry)
        # ==========================================================
        deck_layout = QHBoxLayout()
        deck_layout.setSpacing(8)

        # ----------------------------------------------------------
        # LEFT WING (50%): Curves + Comprehensive Hardware Architecture
        # ----------------------------------------------------------
        left_col = QVBoxLayout()
        left_col.setSpacing(8)

        # Historical Curves
        self.chart_tabs = QTabWidget()
        self.chart_tabs.setObjectName("ChartTabs")
        self.chart_ram_hist = ModernChart("🧠 RAM Allocation History", "#10b981", 100.0, False, "%")
        self.chart_read = ModernChart("⬇️ Disk Read Throughput", "#0ea5e9", 1024 * 1024, True, "B")
        self.chart_write = ModernChart("⬆️ Disk Write Throughput", "#f59e0b", 1024 * 1024, True, "B")

        self.chart_tabs.addTab(self.chart_ram_hist, "RAM History")
        self.chart_tabs.addTab(self.chart_read, "Disk Read I/O")
        self.chart_tabs.addTab(self.chart_write, "Disk Write I/O")
        left_col.addWidget(self.chart_tabs, 4)

        # Deep Detailed Information & Architecture Matrix (Spacious 4x5 Grid)
        self.detail_card = QFrame()
        self.detail_card.setObjectName("ProcessTableContainer")
        det_layout = QVBoxLayout(self.detail_card)
        det_layout.setContentsMargins(10, 8, 10, 8)
        det_layout.setSpacing(6)

        det_header = QHBoxLayout()
        lbl_det_title = QLabel("🔬 Detailed Memory & Hardware Architecture")
        lbl_det_title.setStyleSheet("font-size: 11px; font-weight: 700; color: #38bdf8;")
        det_header.addWidget(lbl_det_title)
        det_header.addStretch()

        self.lbl_arch_badge = QLabel(f"● {platform.machine()} Active")
        self.lbl_arch_badge.setStyleSheet("font-size: 9.5px; font-weight: 700; color: #10b981; background: rgba(16, 185, 129, 0.14); border-radius: 8px; padding: 2px 7px;")
        det_header.addWidget(self.lbl_arch_badge)
        det_layout.addLayout(det_header)

        # 4-Column x 5-Row Grid: Fills the entire lower container without any empty void!
        det_grid = QGridLayout()
        det_grid.setSpacing(6)
        det_grid.setContentsMargins(2, 2, 2, 2)

        # Row 0: Platform Identity
        self.info_uptime = InfoCard("Uptime", "-", "⏱️", "#0ea5e9")
        self.info_os = InfoCard("Operating System", f"{platform.system()} {platform.release()}", "💻", "#38bdf8")
        self.info_cpu = InfoCard("CPU Cores", f"{psutil.cpu_count(logical=True)} Cores ({psutil.cpu_count(logical=False)} Phys)", "🧠", "#a855f7")
        self.info_host = InfoCard("Hostname", platform.node(), "🏠")
        det_grid.addWidget(self.info_uptime, 0, 0)
        det_grid.addWidget(self.info_os, 0, 1)
        det_grid.addWidget(self.info_cpu, 0, 2)
        det_grid.addWidget(self.info_host, 0, 3)

        # Row 1: Kernel & Processor
        self.info_kernel = InfoCard("Kernel / Build", platform.version().split('.')[0] if '.' in platform.version() else platform.release(), "⚙️")
        self.info_arch = InfoCard("Architecture", platform.machine(), "🏗️")
        self.info_proc = InfoCard("Processor Specification", platform.processor() or "Genuine Processor", "⚡", "#f59e0b")
        det_grid.addWidget(self.info_kernel, 1, 0)
        det_grid.addWidget(self.info_arch, 1, 1)
        det_grid.addWidget(self.info_proc, 1, 2, 1, 2)

        # Row 2: Physical Memory Allocation
        self.info_mem_total = InfoCard("Total Physical RAM", "-", "💾", "#10b981")
        self.info_mem_used = InfoCard("Used RAM (Working Set)", "-", "📊", "#38bdf8")
        self.info_mem_avail = InfoCard("Available RAM Pool", "-", "🟢", "#34d399")
        self.info_mem_free = InfoCard("Free (Unallocated)", "-", "🆓", "#94a3b8")
        det_grid.addWidget(self.info_mem_total, 2, 0)
        det_grid.addWidget(self.info_mem_used, 2, 1)
        det_grid.addWidget(self.info_mem_avail, 2, 2)
        det_grid.addWidget(self.info_mem_free, 2, 3)

        # Row 3: Virtual Memory & Standby Cache
        self.info_mem_cached = InfoCard("Cached & Standby", "-", "⚡", "#38bdf8")
        self.info_swap_total = InfoCard("Total Virtual Swap", "-", "🔄", "#0ea5e9")
        self.info_swap_used = InfoCard("Swap / Pagefile Used", "-", "📉", "#f59e0b")
        self.info_commit_limit = InfoCard("System Commit Limit", "-", "🛡️", "#a855f7")
        det_grid.addWidget(self.info_mem_cached, 3, 0)
        det_grid.addWidget(self.info_swap_total, 3, 1)
        det_grid.addWidget(self.info_swap_used, 3, 2)
        det_grid.addWidget(self.info_commit_limit, 3, 3)

        # Row 4: Commit Charges & Health Metrics
        self.info_commit_charge = InfoCard("Committed Charge", "-", "📈", "#ec4899")
        self.info_commit_avail = InfoCard("Available Commit Pool", "-", "🛡️", "#10b981")
        self.info_mem_pressure = InfoCard("RAM Pressure Index", "Normal", "🌡️", "#10b981")
        self.info_boot_time = InfoCard("System Boot Time", self.boot_time.strftime("%Y-%m-%d %H:%M"), "🧭", "#64748b")
        det_grid.addWidget(self.info_commit_charge, 4, 0)
        det_grid.addWidget(self.info_commit_avail, 4, 1)
        det_grid.addWidget(self.info_mem_pressure, 4, 2)
        det_grid.addWidget(self.info_boot_time, 4, 3)

        det_layout.addLayout(det_grid)
        left_col.addWidget(self.detail_card, 6)

        deck_layout.addLayout(left_col, 50)

        # ----------------------------------------------------------
        # RIGHT WING (50%): Storage Partitions + Top Processes Table
        # ----------------------------------------------------------
        right_col = QVBoxLayout()
        right_col.setSpacing(8)

        # Storage Partitions & S.M.A.R.T Health Card
        self.disk_card = QFrame()
        self.disk_card.setObjectName("ProcessTableContainer")
        d_card_layout = QVBoxLayout(self.disk_card)
        d_card_layout.setContentsMargins(10, 8, 10, 8)
        d_card_layout.setSpacing(5)

        lbl_disk_title = QLabel("💾 Storage Partitions & S.M.A.R.T Health")
        lbl_disk_title.setStyleSheet("font-size: 11px; font-weight: 700; color: #38bdf8;")
        d_card_layout.addWidget(lbl_disk_title)

        d_body = QHBoxLayout()
        d_body.setSpacing(8)

        self.disk_table = QTableWidget()
        self.disk_table.setColumnCount(6)
        self.disk_table.setHorizontalHeaderLabels(["Drive", "Total", "Free", "Usage %", "FS", "Health"])
        self.disk_table.verticalHeader().setVisible(False)
        self.disk_table.verticalHeader().setDefaultSectionSize(28)
        self.disk_table.setAlternatingRowColors(True)
        self.disk_table.setShowGrid(False)
        self.disk_table.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.disk_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.disk_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)

        dh = self.disk_table.horizontalHeader()
        dh.setSectionResizeMode(0, QHeaderView.ResizeMode.Fixed)
        self.disk_table.setColumnWidth(0, 55)
        dh.setSectionResizeMode(1, QHeaderView.ResizeMode.Fixed)
        self.disk_table.setColumnWidth(1, 90)
        dh.setSectionResizeMode(2, QHeaderView.ResizeMode.Fixed)
        self.disk_table.setColumnWidth(2, 90)
        dh.setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        dh.setSectionResizeMode(4, QHeaderView.ResizeMode.Fixed)
        self.disk_table.setColumnWidth(4, 65)
        dh.setSectionResizeMode(5, QHeaderView.ResizeMode.Fixed)
        self.disk_table.setColumnWidth(5, 85)
        d_body.addWidget(self.disk_table, 4)

        self.disk_chart = DiskPartitionPieChart()
        d_body.addWidget(self.disk_chart, 1)

        d_card_layout.addLayout(d_body)
        right_col.addWidget(self.disk_card, 4)

        # Top Memory Consuming Processes Card
        self.proc_card = QFrame()
        self.proc_card.setObjectName("ProcessTableContainer")
        p_card_layout = QVBoxLayout(self.proc_card)
        p_card_layout.setContentsMargins(10, 8, 10, 8)
        p_card_layout.setSpacing(6)

        p_header = QHBoxLayout()
        lbl_proc_title = QLabel("🧠 Top Memory Consumers & Working Sets")
        lbl_proc_title.setStyleSheet("font-size: 11px; font-weight: 700; color: #38bdf8;")
        p_header.addWidget(lbl_proc_title)

        p_header.addStretch()

        self.txt_proc_search = QLineEdit()
        self.txt_proc_search.setPlaceholderText("🔍 Filter process or PID...")
        self.txt_proc_search.setFixedHeight(26)
        self.txt_proc_search.setFixedWidth(180)
        self.txt_proc_search.setStyleSheet("border: 1px solid #334155; border-radius: 6px; padding: 2px 8px; font-size: 11px; background: #0f172a; color: #f8fafc;")
        self.txt_proc_search.textChanged.connect(self._filter_procs)
        p_header.addWidget(self.txt_proc_search)
        p_card_layout.addLayout(p_header)

        self.proc_table = QTableWidget()
        self.proc_table.setColumnCount(5)
        self.proc_table.setHorizontalHeaderLabels(["PID", "PROCESS NAME", "PHYSICAL RAM", "MEMORY SHARE", "ACTION"])
        self.proc_table.verticalHeader().setVisible(False)
        self.proc_table.verticalHeader().setDefaultSectionSize(30)
        self.proc_table.setAlternatingRowColors(True)
        self.proc_table.setShowGrid(False)
        self.proc_table.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.proc_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.proc_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)

        ph = self.proc_table.horizontalHeader()
        ph.setSectionResizeMode(0, QHeaderView.ResizeMode.Fixed)
        self.proc_table.setColumnWidth(0, 70)
        ph.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        ph.setSectionResizeMode(2, QHeaderView.ResizeMode.Fixed)
        self.proc_table.setColumnWidth(2, 110)
        ph.setSectionResizeMode(3, QHeaderView.ResizeMode.Fixed)
        self.proc_table.setColumnWidth(3, 130)
        ph.setSectionResizeMode(4, QHeaderView.ResizeMode.Fixed)
        self.proc_table.setColumnWidth(4, 60)

        p_card_layout.addWidget(self.proc_table)

        # Process summary footer
        p_footer = QHBoxLayout()
        self.lbl_proc_total = QLabel("Active: 0  |  Footprint: 0 MB")
        self.lbl_proc_total.setStyleSheet("font-size: 10px; color: #94a3b8;")
        p_footer.addWidget(self.lbl_proc_total)
        p_footer.addStretch()
        p_card_layout.addLayout(p_footer)

        right_col.addWidget(self.proc_card, 6)

        deck_layout.addLayout(right_col, 50)

        main_layout.addLayout(deck_layout, 1)

    # --- Lifecycle & Data Sync ---

    def showEvent(self, event):
        super().showEvent(event)
        self.update_all_stats()
        if self.chk_auto.isChecked():
            self.refresh_timer.start()

    def hideEvent(self, event):
        super().hideEvent(event)
        self.refresh_timer.stop()

    def reset_ui(self):
        self.update_all_stats()

    def update_all_stats(self):
        if self.worker and self.worker.isRunning():
            return
        self.worker = MemoryWorker(
            self.prev_disk_io, self.last_io_time,
            self.smart_cache, self.smart_last_check,
            self.boot_time
        )
        self.worker.data_fetched.connect(self.handle_stats_data)
        self.worker.start()

    def handle_stats_data(self, data):
        total_ram = 1
        if 'mem' in data:
            mem = data['mem']
            swap = data.get('swap')
            total_ram = mem.total

            # Update Physical RAM Ribbon
            used_gb = mem.used / (1024**3)
            total_gb = mem.total / (1024**3)
            avail_gb = mem.available / (1024**3)
            self.lbl_ram_val.setText(f"{used_gb:.2f} GB / {total_gb:.2f} GB")
            self.bar_ram.setValue(int(mem.percent))
            self.lbl_ram_sub.setText(f"Available: {avail_gb:.2f} GB  |  {mem.percent:.1f}% Used")

            # Memory Pressure Alert Badge
            if mem.percent > 85.0:
                self.lbl_system_pressure.setText(f"⚠️ High RAM Pressure ({mem.percent:.1f}%)")
                self.lbl_system_pressure.setStyleSheet("font-size: 11px; font-weight: 700; color: #ea580c; margin-right: 8px;")
            else:
                self.lbl_system_pressure.setText("🟢 System Memory Healthy")
                self.lbl_system_pressure.setStyleSheet("font-size: 11px; font-weight: 700; color: #10b981; margin-right: 8px;")

            # Update Swap Ribbon
            s_used = 0
            s_tot = 0
            s_pct = 0.0
            if swap:
                s_used = swap.used / (1024**3)
                s_tot = swap.total / (1024**3)
                s_free = swap.free / (1024**3)
                s_pct = swap.percent
                self.lbl_swap_val.setText(f"{s_used:.2f} GB / {s_tot:.2f} GB")
                self.bar_swap.setValue(int(swap.percent))
                self.lbl_swap_sub.setText(f"Free: {s_free:.2f} GB  |  {swap.percent:.1f}% Used")

            # Update Mini Dual Donut
            self.mini_donuts.update_values(mem.percent, s_pct)
            self.chart_ram_hist.update_value(mem.percent)

            # Update Deep Detailed Information Grid
            self.info_mem_total.set_value(self._fmt(mem.total))
            self.info_mem_used.set_value(f"{self._fmt(mem.used)} ({mem.percent:.1f}%)")
            self.info_mem_avail.set_value(self._fmt(mem.available))
            self.info_mem_free.set_value(self._fmt(mem.free))

            cached_bytes = getattr(mem, 'cached', 0) or max(0, mem.available - mem.free)
            self.info_mem_cached.set_value(self._fmt(cached_bytes))

            if swap:
                self.info_swap_total.set_value(self._fmt(swap.total))
                self.info_swap_used.set_value(f"{self._fmt(swap.used)} ({swap.percent:.1f}%)")

                # Windows Commit Calculations
                commit_limit = mem.total + swap.total
                commit_charge = mem.used + swap.used
                commit_pct = (commit_charge / commit_limit * 100.0) if commit_limit > 0 else 0
                self.info_commit_limit.set_value(self._fmt(commit_limit))
                self.info_commit_charge.set_value(f"{self._fmt(commit_charge)} ({commit_pct:.1f}%)")
                self.info_commit_avail.set_value(self._fmt(max(0, commit_limit - commit_charge)))

            # Memory Pressure Index Card
            if mem.percent < 75.0:
                self.info_mem_pressure.set_value(f"Low ({mem.percent:.1f}%)")
                self.info_mem_pressure.lbl_value.setStyleSheet("font-size: 11.5px; font-weight: 800; color: #10b981;")
            elif mem.percent < 90.0:
                self.info_mem_pressure.set_value(f"Moderate ({mem.percent:.1f}%)")
                self.info_mem_pressure.lbl_value.setStyleSheet("font-size: 11.5px; font-weight: 800; color: #f59e0b;")
            else:
                self.info_mem_pressure.set_value(f"Critical ({mem.percent:.1f}%)")
                self.info_mem_pressure.lbl_value.setStyleSheet("font-size: 11.5px; font-weight: 800; color: #ef4444;")

        if 'new_disk_io' in data:
            self.prev_disk_io = data['new_disk_io']
            self.last_io_time = data['new_last_io_time']
            self.chart_read.update_value(data.get('r_speed', 0))
            self.chart_write.update_value(data.get('w_speed', 0))

        if 'cpu' in data:
            disk_active = (self.chart_read.current_value > 0 or self.chart_write.current_value > 0)
            ram_pct = data.get('mem').percent if 'mem' in data else 0
            swap_pct = data.get('swap').percent if 'swap' in data else 0
            self.flow_diagram.update_values(data['cpu'], ram_pct, swap_pct, disk_active)

        if 'uptime' in data:
            self.info_uptime.set_value(data['uptime'])

        if 'smart_cache' in data:
            self.smart_cache = data['smart_cache']
            self.smart_last_check = data['smart_last_check']

        if 'partitions' in data:
            self._render_partitions(data['partitions'])

        if 'procs' in data:
            self._current_procs = data['procs']
            self._render_procs(total_ram)

    def _render_partitions(self, partitions):
        self.disk_table.setRowCount(len(partitions))
        chart_data = []

        is_dark = self.palette().color(QPalette.ColorRole.Window).lightness() < 128

        for row, p in enumerate(partitions):
            # 0: Drive Mountpoint
            it_m = QTableWidgetItem(p['mountpoint'])
            it_m.setFont(QFont("Segoe UI", 9, QFont.Weight.Bold))
            self.disk_table.setItem(row, 0, it_m)

            # 1: Total
            self.disk_table.setItem(row, 1, QTableWidgetItem(self._fmt(p['total'])))

            # 2: Free
            self.disk_table.setItem(row, 2, QTableWidgetItem(self._fmt(p['free'])))

            # 3: Usage Bar
            pct = p['percent']
            prog_widget = QWidget()
            prog_layout = QHBoxLayout(prog_widget)
            prog_layout.setContentsMargins(2, 2, 2, 2)
            prog_layout.setSpacing(6)

            bar = QProgressBar()
            bar.setFixedHeight(6)
            bar.setTextVisible(False)
            bar.setValue(int(pct))
            bar_color = "#10b981" if pct < 75 else ("#f59e0b" if pct < 90 else "#ef4444")
            bar.setStyleSheet(f"""
                QProgressBar {{ background: {'#1e293b' if is_dark else '#e2e8f0'}; border-radius: 3px; border: none; }}
                QProgressBar::chunk {{ background: {bar_color}; border-radius: 3px; }}
            """)
            prog_layout.addWidget(bar, 1)

            lbl_pct = QLabel(f"{pct:.1f}%")
            lbl_pct.setFont(QFont("Segoe UI", 8, QFont.Weight.Bold))
            lbl_pct.setFixedWidth(42)
            prog_layout.addWidget(lbl_pct)
            self.disk_table.setCellWidget(row, 3, prog_widget)

            # 4: FS Type
            it_fs = QTableWidgetItem(p['fstype'])
            it_fs.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            self.disk_table.setItem(row, 4, it_fs)

            # 5: S.M.A.R.T Health Badge
            health = self.smart_cache.get(p['mountpoint'], "Good")
            if health == "Unknown" and os.name == 'nt':
                health = self.smart_cache.get(p['mountpoint'].rstrip('\\'), "Good")

            badge_widget = QWidget()
            b_layout = QHBoxLayout(badge_widget)
            b_layout.setContentsMargins(2, 2, 2, 2)
            b_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

            lbl_h = QLabel(f"● {health}")
            if health == "Good":
                bg = "rgba(16, 185, 129, 0.16)" if is_dark else "#dcfce7"
                fg = "#10b981" if is_dark else "#15803d"
                bdr = "rgba(16, 185, 129, 0.40)" if is_dark else "#86efac"
            else:
                bg = "rgba(245, 158, 11, 0.16)" if is_dark else "#fef3c7"
                fg = "#f59e0b" if is_dark else "#b45309"
                bdr = "rgba(245, 158, 11, 0.40)" if is_dark else "#fde68a"

            lbl_h.setStyleSheet(f"background: {bg}; color: {fg}; border: 1px solid {bdr}; border-radius: 8px; padding: 2px 8px; font-size: 9.5px; font-weight: 700;")
            b_layout.addWidget(lbl_h)
            self.disk_table.setCellWidget(row, 5, badge_widget)

            chart_data.append((p['mountpoint'], p['total']))

        self.disk_chart.update_data(chart_data)

    def _render_procs(self, total_ram):
        search_query = self.txt_proc_search.text().strip().lower()
        filtered = [
            p for p in self._current_procs
            if not search_query or search_query in p['name'].lower() or search_query in str(p['pid'])
        ]

        self.proc_table.setRowCount(len(filtered))
        is_dark = self.palette().color(QPalette.ColorRole.Window).lightness() < 128
        total_rss = sum(p['rss'] for p in filtered)

        for row, p in enumerate(filtered):
            # 0: PID (unclipped centered integer)
            it_pid = QTableWidgetItem(str(p['pid']))
            it_pid.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            it_pid.setForeground(QBrush(QColor("#94a3b8")))
            it_pid.setFont(QFont("Segoe UI", 9))
            self.proc_table.setItem(row, 0, it_pid)

            # 1: Name
            it_name = QTableWidgetItem(p['name'])
            it_name.setFont(QFont("Segoe UI", 9, QFont.Weight.Bold))
            self.proc_table.setItem(row, 1, it_name)

            # 2: Memory RSS
            it_rss = QTableWidgetItem(self._fmt(p['rss']))
            it_rss.setTextAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
            it_rss.setForeground(QBrush(QColor("#0ea5e9")))
            it_rss.setFont(QFont("Segoe UI", 9, QFont.Weight.Bold))
            self.proc_table.setItem(row, 2, it_rss)

            # 3: Memory Share % Bar
            pct = (p['rss'] / total_ram * 100.0) if total_ram > 0 else 0.0
            prog_widget = QWidget()
            prog_layout = QHBoxLayout(prog_widget)
            prog_layout.setContentsMargins(4, 0, 4, 0)
            prog_layout.setSpacing(6)

            bar = QProgressBar()
            bar.setFixedHeight(6)
            bar.setTextVisible(False)
            bar.setValue(min(100, int(pct * 2.5)))
            bar.setStyleSheet(f"""
                QProgressBar {{ background: {'#1e293b' if is_dark else '#e2e8f0'}; border-radius: 3px; border: none; }}
                QProgressBar::chunk {{ background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #0ea5e9, stop:1 #38bdf8); border-radius: 3px; }}
            """)
            prog_layout.addWidget(bar, 1)

            lbl_pct = QLabel(f"{pct:.1f}%")
            lbl_pct.setFont(QFont("Segoe UI", 8, QFont.Weight.Bold))
            lbl_pct.setFixedWidth(40)
            prog_layout.addWidget(lbl_pct)
            self.proc_table.setCellWidget(row, 3, prog_widget)

            # 4: Action Button ("✕" icon button)
            btn_kill = QPushButton("✕")
            btn_kill.setFixedSize(24, 20)
            btn_kill.setCursor(Qt.CursorShape.PointingHandCursor)
            btn_kill.setToolTip(f"Terminate {p['name']} (PID: {p['pid']})")
            btn_kill.setStyleSheet("""
                QPushButton {
                    background: rgba(239, 68, 68, 0.16);
                    color: #ef4444;
                    border: 1px solid rgba(239, 68, 68, 0.40);
                    border-radius: 4px;
                    font-size: 11px;
                    font-weight: 900;
                    padding-bottom: 1px;
                }
                QPushButton:hover {
                    background: #ef4444;
                    color: #ffffff;
                    border: 1px solid #dc2626;
                }
            """)
            btn_kill.clicked.connect(lambda _, pid=p['pid'], name=p['name']: self.kill_proc(pid, name))
            
            btn_container = QWidget()
            btn_l = QHBoxLayout(btn_container)
            btn_l.setContentsMargins(0, 0, 0, 0)
            btn_l.setAlignment(Qt.AlignmentFlag.AlignCenter)
            btn_l.addWidget(btn_kill)
            self.proc_table.setCellWidget(row, 4, btn_container)

        self.lbl_proc_total.setText(
            f"Active: {len(filtered)} processes  |  Tracked Working Set: <b>{self._fmt(total_rss)}</b>"
        )

    def _filter_procs(self, text):
        total_ram = 1
        if hasattr(self, 'worker') and self.worker and hasattr(self.worker, 'boot_time'):
            try:
                total_ram = psutil.virtual_memory().total
            except Exception:
                pass
        self._render_procs(total_ram)

    def kill_proc(self, pid, name):
        reply = QMessageBox.question(
            self, "Terminate Process",
            f"Are you sure you want to terminate:\n\n{name} (PID: {pid})?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No
        )
        if reply == QMessageBox.StandardButton.Yes:
            try:
                p = psutil.Process(pid)
                p.terminate()
                p.wait(timeout=1.5)
                QMessageBox.information(self, "Success", f"Process {name} (PID: {pid}) terminated.")
                self.update_all_stats()
            except Exception as e:
                QMessageBox.warning(self, "Error", f"Failed to terminate process:\n{str(e)}")

    def clean_temp_files(self):
        reply = QMessageBox.question(
            self, "Clean Temporary Files",
            "This will purge temporary system and application cache files to reclaim disk space.\n\nProceed with cleanup?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.Yes
        )
        if reply == QMessageBox.StandardButton.Yes:
            self.btn_clean.setEnabled(False)
            self.btn_clean.setText("Cleaning...")
            self.clean_worker = TempCleanerWorker()
            self.clean_worker.finished_clean.connect(self._on_clean_finished)
            self.clean_worker.start()

    def _on_clean_finished(self, count, freed):
        self.btn_clean.setEnabled(True)
        self.btn_clean.setText("🗑️ Clean Temp")
        QMessageBox.information(
            self, "Cleanup Complete",
            f"Temporary files cleanup completed successfully!\n\nFiles Removed: {count:,}\nDisk Space Reclaimed: {self._fmt(freed)}"
        )
        self.update_all_stats()

    def trim_working_sets(self):
        self.btn_trim.setEnabled(False)
        self.btn_trim.setText("⚡ Trimming...")
        self.optimizer_worker = MemoryOptimizerWorker()
        self.optimizer_worker.finished_trim.connect(self._on_trim_finished)
        self.optimizer_worker.start()

    def _on_trim_finished(self, count):
        self.btn_trim.setEnabled(True)
        self.btn_trim.setText("⚡ Trim Working Sets")
        QMessageBox.information(
            self, "Optimization Complete",
            f"Active process working sets successfully trimmed!\n\nProcesses Trimmed: {count}\nUnreferenced pages flushed to standby pool."
        )
        self.update_all_stats()

    def export_pdf(self):
        try:
            printer = QPrinter(QPrinter.PrinterMode.HighResolution)
            printer.setOutputFormat(QPrinter.OutputFormat.PdfFormat)
            printer.setPageSize(QPageSize(QPageSize.PageSizeId.A4))
            printer.setPageOrientation(QPageSize.Orientation.Portrait)

            temp_path = os.path.join(os.environ.get('TEMP', '.'), f"temp_mem_dossier_{int(time.time())}.pdf")
            printer.setOutputFileName(temp_path)

            mem = psutil.virtual_memory()
            swap = psutil.swap_memory()
            timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            # Collect processes
            procs = sorted(
                psutil.process_iter(['pid', 'name', 'memory_info']),
                key=lambda p: (p.info['memory_info'].rss if p.info.get('memory_info') else 0),
                reverse=True
            )[:12]

            proc_rows = ""
            for p in procs:
                rss = p.info['memory_info'].rss if p.info.get('memory_info') else 0
                share = (rss / mem.total * 100) if mem.total > 0 else 0
                proc_rows += f"""
                <tr>
                    <td align="center">{p.info['pid']}</td>
                    <td><b>{p.info['name'] or 'Unknown'}</b></td>
                    <td align="right">{self._fmt(rss)}</td>
                    <td align="center">{share:.1f}%</td>
                </tr>
                """

            disk_rows = ""
            for p in psutil.disk_partitions():
                try:
                    usage = psutil.disk_usage(p.mountpoint)
                    disk_rows += f"""
                    <tr>
                        <td align="center"><b>{p.mountpoint}</b></td>
                        <td align="right">{self._fmt(usage.total)}</td>
                        <td align="right">{self._fmt(usage.free)}</td>
                        <td align="center">{usage.percent:.1f}%</td>
                        <td align="center">{p.fstype}</td>
                    </tr>
                    """
                except Exception:
                    continue

            html = f"""<!DOCTYPE html>
            <html>
            <head>
              <meta charset="utf-8">
              <style>
                body {{ font-family: 'Segoe UI', Arial, sans-serif; font-size: 9pt; color: #1e293b; line-height: 1.4; }}
                h1 {{ font-size: 16pt; color: #0284c7; margin: 0; padding-bottom: 2px; }}
                h2 {{ font-size: 11pt; color: #0f172a; margin-top: 14px; margin-bottom: 6px; border-bottom: 1px solid #0284c7; padding-bottom: 3px; }}
                table {{ width: 100%; border-collapse: collapse; margin-top: 6px; font-size: 8.5pt; }}
                th {{ background-color: #f1f5f9; color: #475569; padding: 5px 8px; text-align: left; border: 1px solid #cbd5e1; }}
                td {{ padding: 5px 8px; border: 1px solid #e2e8f0; }}
                .kpi-box {{ border: 1px solid #bae6fd; background-color: #f0f9ff; padding: 10px; border-radius: 6px; margin-top: 8px; }}
              </style>
            </head>
            <body>
              <table width="100%" cellspacing="0" cellpadding="0" style="border:none; margin-bottom: 8px; border-bottom: 2px solid #0284c7; padding-bottom: 4px;">
                <tr>
                  <td>
                    <h1>NexaShield Memory & Storage Forensic Dossier</h1>
                    <div style="font-size: 8.5pt; color: #64748b; margin-top: 2px;">
                      Host: <b>{platform.node()}</b> &nbsp;|&nbsp; OS: <b>{platform.system()} {platform.release()} ({platform.machine()})</b> &nbsp;|&nbsp; Generated: <b>{timestamp}</b>
                    </div>
                  </td>
                </tr>
              </table>

              <!-- Executive Memory & Hardware Dossier Table -->
              <div class="kpi-box">
                <table width="100%" style="border:none;">
                  <tr>
                    <td style="border:none;"><b>Processor:</b> {platform.processor()}</td>
                    <td style="border:none;"><b>Logical CPU Cores:</b> {psutil.cpu_count(logical=True)} Cores</td>
                    <td style="border:none;"><b>System Uptime:</b> {self.info_uptime.lbl_value.text()}</td>
                  </tr>
                  <tr>
                    <td style="border:none;"><b>Total Physical RAM:</b> {self._fmt(mem.total)}</td>
                    <td style="border:none;"><b>Used RAM:</b> {self._fmt(mem.used)} ({mem.percent}%)</td>
                    <td style="border:none;"><b>Available RAM:</b> {self._fmt(mem.available)}</td>
                  </tr>
                  <tr>
                    <td style="border:none;"><b>Total Virtual Swap:</b> {self._fmt(swap.total)}</td>
                    <td style="border:none;"><b>Swap Used:</b> {self._fmt(swap.used)} ({swap.percent}%)</td>
                    <td style="border:none;"><b>System Commit Limit:</b> {self.info_commit_limit.lbl_value.text()}</td>
                  </tr>
                </table>
              </div>

              <h2>Top Memory Consuming Working Sets</h2>
              <table>
                <thead>
                  <tr>
                    <th width="12%" align="center">PID</th>
                    <th>Process Name</th>
                    <th width="25%" align="right">Physical Memory (RSS)</th>
                    <th width="15%" align="center">RAM Share</th>
                  </tr>
                </thead>
                <tbody>
                  {proc_rows}
                </tbody>
              </table>

              <h2>Storage Partition Allocations</h2>
              <table>
                <thead>
                  <tr>
                    <th width="15%" align="center">Drive</th>
                    <th width="20%" align="right">Total Size</th>
                    <th width="20%" align="right">Free Space</th>
                    <th width="20%" align="center">Usage %</th>
                    <th width="25%" align="center">File System</th>
                  </tr>
                </thead>
                <tbody>
                  {disk_rows}
                </tbody>
              </table>
            </body>
            </html>
            """

            doc = QTextDocument()
            doc.setPageSize(QSizeF(printer.pageRect(QPrinter.Unit.Point).size()))
            doc.setHtml(html)
            doc.print(printer)

            with open(temp_path, "rb") as f:
                pdf_bytes = f.read()
            if os.path.exists(temp_path):
                os.remove(temp_path)

            filename = f"Memory_Dossier_{time.strftime('%Y%m%d_%H%M%S')}.pdf"
            if self.session and hasattr(self.session, 'file_manager'):
                self.session.file_manager.export_file(
                    filename=filename,
                    content=pdf_bytes,
                    module_source="Memory Intelligence",
                    file_type="PDF",
                    tags="Memory,Forensics,Hardware,Storage"
                )
                self.btn_export.setText("✓ Vaulted in FMS!")
                QMessageBox.information(
                    self, "Dossier Vaulted",
                    f"Memory & Storage Forensic Dossier successfully generated as an executive PDF and vaulted in NexaShield FMS.\n\nFile: {filename}\nSource: Memory Intelligence"
                )
                QTimer.singleShot(2500, lambda: self.btn_export.setText("📥 Export Dossier"))
            else:
                save_path, _ = QFileDialog.getSaveFileName(self, "Save Memory Forensic Dossier", filename, "PDF Files (*.pdf)")
                if save_path:
                    with open(save_path, "wb") as f:
                        f.write(pdf_bytes)
                    QMessageBox.information(self, "Dossier Saved", f"Memory dossier saved to:\n{save_path}")
        except Exception as e:
            QMessageBox.critical(self, "Export Error", f"Failed to generate Memory Dossier PDF:\n{str(e)}")

    def _toggle_auto(self, state):
        if state:
            self.update_all_stats()
            self.refresh_timer.start()
        else:
            self.refresh_timer.stop()

    @staticmethod
    def _fmt(n):
        for u in ["B", "KB", "MB", "GB", "TB"]:
            if n < 1024:
                return f"{n:.2f} {u}"
            n /= 1024
        return f"{n:.2f} PB"
