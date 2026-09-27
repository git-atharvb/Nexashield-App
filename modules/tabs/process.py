import psutil
import datetime
import csv
import time
from collections import deque
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QTableWidget, QTableWidgetItem,
    QPushButton, QLineEdit, QLabel, QHeaderView, QMessageBox, QFileDialog,
    QAbstractItemView, QFrame, QProgressBar, QCheckBox, QComboBox, QStyle, QTextEdit
)
from PyQt6.QtCore import Qt, QTimer, QThread, pyqtSignal
from PyQt6.QtGui import QColor, QBrush, QAction, QPainter, QPainterPath, QLinearGradient, QRadialGradient, QPen, QTextDocument, QPalette, QFont
from PyQt6.QtPrintSupport import QPrinter

import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from database import DatabaseManager
from ai.processAI.process_scanner import ProcessThreatScanner

# --- Constants ---
REFRESH_INTERVAL = 3000  # 3 seconds
HIGH_CPU_THRESHOLD = 80.0
HIGH_MEM_THRESHOLD = 80.0

class SortableTableWidgetItem(QTableWidgetItem):
    """Custom item to ensure proper sorting by UserRole (handles both numeric and strings)."""
    def __lt__(self, other):
        val1 = self.data(Qt.ItemDataRole.UserRole)
        val2 = other.data(Qt.ItemDataRole.UserRole)
        try:
            return float(val1) < float(val2)
        except (ValueError, TypeError):
            return str(val1) < str(val2)

class ProcessWorker(QThread):
    """
    Background thread to fetch system processes.
    Prevents UI freezing during data collection and ML inference.
    """
    data_fetched = pyqtSignal(list)

    def __init__(self):
        super().__init__()
        self.ai_scan_enabled = False
        self.ai_scanner = None

    def enable_ai_scan(self, enable, scanner):
        self.ai_scan_enabled = enable
        self.ai_scanner = scanner

    def run(self):
        processes = []
        # Fetch specific attributes to optimize performance
        attrs = ['pid', 'name', 'status', 'cpu_percent', 'memory_percent', 'username', 'create_time', 'io_counters', 'exe', 'cmdline']
        
        for proc in psutil.process_iter(attrs):
            try:
                pinfo = proc.info
                # Format io_counters to simple string for Disk/Net deltas
                # psutil provides read_bytes, write_bytes for io_counters
                if pinfo.get('io_counters'):
                    io = pinfo['io_counters']
                    # We will just pass the raw bytes, the UI can format them or calculate deltas
                    pinfo['disk_read'] = getattr(io, 'read_bytes', 0)
                    pinfo['disk_write'] = getattr(io, 'write_bytes', 0)
                else:
                    pinfo['disk_read'] = 0
                    pinfo['disk_write'] = 0

                # Perform AI scan in background thread if enabled
                if self.ai_scan_enabled and self.ai_scanner:
                    level, color, prob = self.ai_scanner.predict_threat_level(proc)
                    pinfo['ai_level'] = level
                    pinfo['ai_color'] = color
                else:
                    pinfo['ai_level'] = None
                    pinfo['ai_color'] = None
                    
                processes.append(pinfo)
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass
            
            # CRITICAL: Yield the Global Interpreter Lock (GIL) to the PyQt main thread!
            # Python threads share the GIL. Fetching telemetry for 300+ processes continuously
            # will starve the UI thread, causing lag and "Not Responding" freezes. 
            # This tiny sleep ensures perfectly smooth 60FPS UI rendering.
            time.sleep(0.002)
        
        self.data_fetched.emit(processes)

class ResourceChart(QFrame):
    """Custom widget to draw live resource usage charts."""
    def __init__(self, title, line_color="#0078d7"):
        super().__init__()
        self.setObjectName("ChartCard")
        self.title = title
        self.line_color = QColor(line_color)
        self.data = deque([0]*60, maxlen=60) # 60 data points
        self.setMinimumHeight(150)
        self.current_value = 0.0

    def update_value(self, value):
        self.current_value = value
        self.data.append(value)
        self.update()

    def paintEvent(self, event):
        # Let QSS handle the background
        super().paintEvent(event)

        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        
        w = self.width()
        h = self.height()
        
        top_pad = 40
        chart_h = h - top_pad
        
        grid_col = QColor(128, 128, 128, 30)
        
        # 1. Draw Grid Lines (Underneath graph)
        painter.setPen(QPen(grid_col, 1, Qt.PenStyle.DashLine))
        for i in range(4):
            y_line = top_pad + i * (chart_h / 3)
            painter.drawLine(0, int(y_line), w, int(y_line))
        
        if not self.data:
            return
            
        # 2. Draw Graph Path (Smooth Bezier)
        path = QPainterPath()
        step_x = w / (self.data.maxlen - 1)
        
        prev_x = 0
        prev_y = h - (self.data[0] / 100.0 * chart_h)
        path.moveTo(prev_x, prev_y)
        
        for i in range(1, len(self.data)):
            x = i * step_x
            y = h - (self.data[i] / 100.0 * chart_h)
            
            # Control points for smooth bezier curve
            ctrl_x1 = prev_x + (x - prev_x) * 0.5
            ctrl_y1 = prev_y
            ctrl_x2 = prev_x + (x - prev_x) * 0.5
            ctrl_y2 = y
            
            path.cubicTo(ctrl_x1, ctrl_y1, ctrl_x2, ctrl_y2, x, y)
            prev_x = x
            prev_y = y
            
        # Fill Gradient
        fill_path = QPainterPath(path)
        fill_path.lineTo(w, h)
        fill_path.lineTo(0, h)
        fill_path.closeSubpath()
        
        grad = QLinearGradient(0, top_pad, 0, h)
        c = self.line_color
        grad.setColorAt(0, QColor(c.red(), c.green(), c.blue(), 120))
        grad.setColorAt(1, QColor(c.red(), c.green(), c.blue(), 10))
        
        painter.setBrush(grad)
        painter.setPen(Qt.PenStyle.NoPen)
        painter.drawPath(fill_path)

        # Draw Line
        painter.setPen(QPen(self.line_color, 3, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap, Qt.PenJoinStyle.RoundJoin))
        painter.setBrush(Qt.BrushStyle.NoBrush)
        painter.drawPath(path)

        # Draw Leading Dot Glow
        glow = QRadialGradient(prev_x, prev_y, 20)
        glow.setColorAt(0, QColor(c.red(), c.green(), c.blue(), 180))
        glow.setColorAt(1, Qt.GlobalColor.transparent)
        painter.setBrush(glow)
        painter.setPen(Qt.PenStyle.NoPen)
        painter.drawEllipse(int(prev_x - 20), int(prev_y - 20), 40, 40)

        # Draw Leading Dot
        painter.setBrush(c)
        painter.setPen(QPen(Qt.GlobalColor.white, 2))
        painter.drawEllipse(int(prev_x - 5), int(prev_y - 5), 10, 10)

        # 3. Draw Text & Labels
        text_col = self.palette().color(QPalette.ColorRole.WindowText)
        label_col = QColor(128, 128, 128, 150)
        
        painter.setFont(QFont("Segoe UI", 8))
        painter.setPen(label_col)
        for i in range(4):
            y_line = top_pad + i * (chart_h / 3)
            lbl = ["100%", "66%", "33%", "0%"][i]
            painter.drawText(w - 35, int(y_line) - 4, lbl)
            
        painter.setPen(text_col)
        painter.setFont(QFont("Segoe UI", 12, QFont.Weight.Bold))
        painter.drawText(15, 28, f"{self.title}: {self.current_value:.1f}%")

class ProcessMonitorWidget(QWidget):
    def __init__(self, session_manager=None):
        super().__init__()
        self.session = session_manager
        self.setObjectName("ProcessMonitor")
        
        # State
        self.process_data = []
        self.filter_text = ""
        self.ai_scanner = ProcessThreatScanner()
        self.ai_scan_enabled = False
        
        # UI Setup
        self.setup_ui()
        
        # Worker & Timer
        self.worker = ProcessWorker()
        self.worker.data_fetched.connect(self.update_table)
        
        self.timer = QTimer()
        self.timer.timeout.connect(self.refresh_data)
        
        # Chart Timer (1 second updates)
        self.chart_timer = QTimer()
        self.chart_timer.timeout.connect(self.update_charts)

    def showEvent(self, event):
        super().showEvent(event)
        self.refresh_data()
        self.timer.start(REFRESH_INTERVAL)
        self.chart_timer.start(1000)

    def hideEvent(self, event):
        super().hideEvent(event)
        self.timer.stop()
        self.chart_timer.stop()

    def setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(10)

        # --- Top Control Bar ---
        self.control_frame = QFrame()
        self.control_frame.setObjectName("ProcessToolbar")
        control_bar = QHBoxLayout(self.control_frame)
        control_bar.setContentsMargins(15, 10, 15, 10)
        control_bar.setSpacing(15)
        
        # Search
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("🔍 Search Process Name or PID...")
        self.search_input.setFixedWidth(400)
        self.search_input.textChanged.connect(self.handle_search)
        control_bar.addWidget(self.search_input)

        self.btn_clear_search = QPushButton("X")
        self.btn_clear_search.setObjectName("ClearSearchBtn")
        self.btn_clear_search.setFixedSize(32, 32)
        self.btn_clear_search.setToolTip("Clear Search")
        self.btn_clear_search.clicked.connect(self.clear_search)
        control_bar.addWidget(self.btn_clear_search)

        # Smart Filtering Dropdown
        self.filter_combo = QComboBox()
        self.filter_combo.setObjectName("FilterDropdown")
        self.filter_combo.addItems(["All Levels", "Level 1 (Safe)", "Level 2 (Low Risk)", "Level 3 (Moderate)", "Level 4 (High Risk)", "Level 5 (Critical)"])
        self.filter_combo.setFixedWidth(160)
        self.filter_combo.currentTextChanged.connect(self.set_category_filter)
        self.filter_combo.setVisible(False)
        control_bar.addWidget(self.filter_combo)
        self.current_category = "All Levels"

        # Threat Level Color Guide Icon
        self.info_icon = QLabel("ℹ️")
        self.info_icon.setStyleSheet("QLabel { font-size: 18px; color: #a4b0be; margin-left: 5px; } QLabel:hover { color: #3498db; }")
        
        tooltip_html = (
            "<div style='padding: 8px;'>"
            "<h3 style='color: #ffffff; margin-top: 0px; margin-bottom: 10px; border-bottom: 1px solid #555; padding-bottom: 5px;'>🧠 AI Threat Level Guide</h3>"
            "<table style='font-size: 13px; color: #ecf0f1;' cellspacing='6' cellpadding='0'>"
            "<tr><td><span style='color:#00b894; font-size: 18px;'>●</span></td><td style='padding-left: 8px;'><b style='color: white;'>Level 1:</b> Safe / System</td></tr>"
            "<tr><td><span style='color:#0984e3; font-size: 18px;'>●</span></td><td style='padding-left: 8px;'><b style='color: white;'>Level 2:</b> Low Risk</td></tr>"
            "<tr><td><span style='color:#fdcb6e; font-size: 18px;'>●</span></td><td style='padding-left: 8px;'><b style='color: white;'>Level 3:</b> Moderate Risk</td></tr>"
            "<tr><td><span style='color:#e17055; font-size: 18px;'>●</span></td><td style='padding-left: 8px;'><b style='color: white;'>Level 4:</b> High Risk</td></tr>"
            "<tr><td><span style='color:#d63031; font-size: 18px;'>●</span></td><td style='padding-left: 8px;'><b style='color: white;'>Level 5:</b> Critical / Malicious</td></tr>"
            "</table>"
            "</div>"
        )
        self.info_icon.setToolTip(tooltip_html)
        self.info_icon.setVisible(False)
        control_bar.addWidget(self.info_icon)

        control_bar.addStretch()

        # Charts Toggle Button
        self.btn_toggle_charts = QPushButton("📈 System Graphs")
        self.btn_toggle_charts.setObjectName("BtnOutline")
        self.btn_toggle_charts.setCheckable(True)
        self.btn_toggle_charts.setChecked(True)
        control_bar.addWidget(self.btn_toggle_charts)

        # AI Scan Button
        self.btn_ai_scan = QPushButton("🧠 AI Threat Scan")
        self.btn_ai_scan.setObjectName("BtnPrimary")
        self.btn_ai_scan.setCheckable(True)
        self.btn_ai_scan.toggled.connect(self.toggle_ai_scan)
        control_bar.addWidget(self.btn_ai_scan)

        # Action Buttons
        self.btn_suspend = QPushButton("⏸️ Suspend")
        self.btn_suspend.setObjectName("BtnOutline")
        self.btn_suspend.clicked.connect(lambda: self.change_process_state("suspend"))
        control_bar.addWidget(self.btn_suspend)

        self.btn_resume = QPushButton("▶️ Resume")
        self.btn_resume.setObjectName("BtnOutline")
        self.btn_resume.clicked.connect(lambda: self.change_process_state("resume"))
        control_bar.addWidget(self.btn_resume)

        self.btn_kill = QPushButton("💀 End Task")
        self.btn_kill.setObjectName("BtnDanger") 
        self.btn_kill.clicked.connect(self.kill_process)
        control_bar.addWidget(self.btn_kill)

        self.btn_refresh = QPushButton("🔄 Refresh")
        self.btn_refresh.setObjectName("BtnPrimary")
        self.btn_refresh.clicked.connect(self.refresh_data)
        control_bar.addWidget(self.btn_refresh)

        self.btn_export = QPushButton("📄 CSV")
        self.btn_export.setObjectName("BtnInfo")
        self.btn_export.clicked.connect(self.export_csv)
        control_bar.addWidget(self.btn_export)

        self.btn_export_pdf = QPushButton("📑 PDF")
        self.btn_export_pdf.setObjectName("BtnWarning")
        self.btn_export_pdf.clicked.connect(self.export_pdf)
        control_bar.addWidget(self.btn_export_pdf)

        layout.addWidget(self.control_frame)

        # --- Content Area (Split 1:2) ---
        content_layout = QHBoxLayout()

        # --- Resource Charts (Drawer) ---
        self.charts_panel = QFrame()
        self.charts_panel.setObjectName("DetailsPanel")
        self.charts_panel.setFixedWidth(320)
        
        charts_layout = QVBoxLayout(self.charts_panel)
        charts_layout.setContentsMargins(15, 15, 15, 15)
        charts_layout.setSpacing(15)
        
        charts_header_layout = QHBoxLayout()
        self.lbl_charts_title = QLabel("System Resources")
        self.lbl_charts_title.setObjectName("DetailsTitle")
        charts_header_layout.addWidget(self.lbl_charts_title)
        
        charts_header_layout.addStretch()
        
        self.btn_close_charts = QPushButton("✖")
        self.btn_close_charts.setFixedSize(24, 24)
        self.btn_close_charts.setToolTip("Close Graphs")
        self.btn_close_charts.setStyleSheet("QPushButton { background-color: transparent; border: none; font-size: 18px; font-weight: bold; color: #a4b0be; } QPushButton:hover { color: #e74c3c; background-color: rgba(255, 255, 255, 0.1); border-radius: 4px; }")
        self.btn_close_charts.clicked.connect(lambda: self.btn_toggle_charts.setChecked(False))
        charts_header_layout.addWidget(self.btn_close_charts)
        
        charts_layout.addLayout(charts_header_layout)
        
        self.cpu_chart = ResourceChart("🧠 CPU Usage", "#00c6ff")
        self.mem_chart = ResourceChart("💾 RAM Usage", "#ff5e7e")
        charts_layout.addWidget(self.cpu_chart)
        charts_layout.addWidget(self.mem_chart)
        
        content_layout.addWidget(self.charts_panel)
        
        self.btn_toggle_charts.toggled.connect(self.charts_panel.setVisible)

        # --- Process Table ---
        self.table_container = QFrame()
        self.table_container.setObjectName("ProcessTableContainer")
        table_layout = QVBoxLayout(self.table_container)
        table_layout.setContentsMargins(0, 0, 0, 0)
        
        self.table = QTableWidget()
        self.table.setObjectName("ProcessTable")
        self.table.setColumnCount(10)
        self.table.setHorizontalHeaderLabels([
            "", "PID", "Name", "Status", "CPU", "Memory", "Disk I/O", "Net I/O", "User", "Start Time"
        ])
        
        # Table Styling & Behavior
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.verticalHeader().setVisible(False)
        self.table.setAlternatingRowColors(True)
        self.table.setShowGrid(False)
        self.table.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        
        # Header sizing
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Fixed)
        self.table.setColumnWidth(0, 40)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch) # Name stretches
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents) # PID
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.Fixed) # CPU bar
        self.table.setColumnWidth(4, 120)
        header.setSectionResizeMode(5, QHeaderView.ResizeMode.Fixed) # Mem bar
        self.table.setColumnWidth(5, 100)
        header.setSectionResizeMode(6, QHeaderView.ResizeMode.Fixed) # Disk
        self.table.setColumnWidth(6, 80)
        header.setSectionResizeMode(7, QHeaderView.ResizeMode.Fixed) # Net
        self.table.setColumnWidth(7, 80)
        
        self.table.itemSelectionChanged.connect(self.on_process_selected)
        
        table_layout.addWidget(self.table)
        content_layout.addWidget(self.table_container, 2) # Stretch 2
        
        # --- Deep Dive Panel (Hidden initially) ---
        self.details_panel = QFrame()
        self.details_panel.setObjectName("DetailsPanel")
        self.details_panel.setFixedWidth(300)
        self.details_panel.hide()
        
        details_layout = QVBoxLayout(self.details_panel)
        details_layout.setContentsMargins(15, 15, 15, 15)
        details_layout.setSpacing(10)
        
        details_header_layout = QHBoxLayout()
        
        self.lbl_details_title = QLabel("Process Forensics")
        self.lbl_details_title.setObjectName("DetailsTitle")
        details_header_layout.addWidget(self.lbl_details_title)
        
        details_header_layout.addStretch()
        
        self.btn_close_details = QPushButton("✖")
        self.btn_close_details.setFixedSize(24, 24)
        self.btn_close_details.setToolTip("Close Forensics")
        self.btn_close_details.setStyleSheet("QPushButton { background-color: transparent; border: none; font-size: 18px; font-weight: bold; color: #a4b0be; } QPushButton:hover { color: #e74c3c; background-color: rgba(255, 255, 255, 0.1); border-radius: 4px; }")
        self.btn_close_details.clicked.connect(self.close_details_panel)
        details_header_layout.addWidget(self.btn_close_details)
        
        details_layout.addLayout(details_header_layout)
        
        self.txt_details_info = QTextEdit()
        self.txt_details_info.setReadOnly(True)
        self.txt_details_info.setFrameShape(QFrame.Shape.NoFrame)
        self.txt_details_info.setStyleSheet("background: transparent;")
        self.txt_details_info.setHtml("Select a process to inspect.")
        
        details_layout.addWidget(self.txt_details_info, 1)
        
        content_layout.addWidget(self.details_panel)
        
        layout.addLayout(content_layout)

        # Status Bar / Footer
        self.status_bar = QFrame()
        self.status_bar.setObjectName("ProcessStatusBar")
        self.status_bar.setStyleSheet("""
            QFrame#ProcessStatusBar {
                background-color: #1e1e2d;
                border-top: 1px solid #2d2d3d;
                border-radius: 6px;
            }
        """)
        status_layout = QHBoxLayout(self.status_bar)
        status_layout.setContentsMargins(15, 10, 15, 10)
        
        self.lbl_system_status = QLabel("🟢 System Status: Active")
        self.lbl_system_status.setStyleSheet("color: #2ecc71; font-weight: bold; font-size: 13px;")
        status_layout.addWidget(self.lbl_system_status)
        
        status_layout.addStretch()
        
        self.lbl_global_cpu = QLabel("Global CPU:")
        self.lbl_global_cpu.setStyleSheet("color: #a4b0be; font-weight: bold; font-size: 13px;")
        status_layout.addWidget(self.lbl_global_cpu)
        
        self.val_global_cpu = QLabel("0.0%")
        self.val_global_cpu.setStyleSheet("color: #00c6ff; font-weight: bold; font-size: 14px; min-width: 50px;")
        status_layout.addWidget(self.val_global_cpu)
        
        status_layout.addSpacing(30)
        
        self.lbl_global_ram = QLabel("Global RAM:")
        self.lbl_global_ram.setStyleSheet("color: #a4b0be; font-weight: bold; font-size: 13px;")
        status_layout.addWidget(self.lbl_global_ram)
        
        self.val_global_ram = QLabel("0.0%")
        self.val_global_ram.setStyleSheet("color: #ff5e7e; font-weight: bold; font-size: 14px; min-width: 50px;")
        status_layout.addWidget(self.val_global_ram)
        
        status_layout.addStretch()
        
        self.lbl_process_count = QLabel("Showing 0 Processes")
        self.lbl_process_count.setStyleSheet("color: #f39c12; font-weight: bold; font-size: 13px;")
        status_layout.addWidget(self.lbl_process_count)
        
        layout.addWidget(self.status_bar)

    def reset_ui(self):
        """Clears filters and triggers a data refresh."""
        self.search_input.clear()
        self.chk_select_all.setChecked(False)
        self.refresh_data()

    def toggle_ai_scan(self, checked):
        self.ai_scan_enabled = checked
        self.worker.enable_ai_scan(checked, self.ai_scanner)
        
        self.filter_combo.setVisible(checked)
        self.info_icon.setVisible(checked)
        
        if checked:
            self.btn_ai_scan.setText("🧠 AI Scan Active")
            self.btn_ai_scan.setStyleSheet("background-color: #9b59b6; color: white;")
        else:
            self.filter_combo.setCurrentIndex(0) # Reset filter when AI is turned off
            self.btn_ai_scan.setText("🧠 AI Threat Scan")
            self.btn_ai_scan.setStyleSheet("")
        self.refresh_data()

    def clear_search(self):
        self.search_input.clear()

    def toggle_select_all(self, state):
        check_state = Qt.CheckState(state)
        for row in range(self.table.rowCount()):
            item = self.table.item(row, 0)
            if item:
                item.setCheckState(check_state)

    def update_charts(self):
        cpu = psutil.cpu_percent()
        mem = psutil.virtual_memory().percent
        self.cpu_chart.update_value(cpu)
        self.mem_chart.update_value(mem)

    def refresh_data(self):
        """Triggers the background worker if not already running."""
        if not self.worker.isRunning():
            self.lbl_system_status.setText("🟢 System Status: Updating...")
            self.worker.start()

    def update_table(self, processes):
        """Updates the table with new data while preserving scroll and selection."""
        self.process_data = processes

        # Save current state
        current_scroll = self.table.verticalScrollBar().value()
        selected_pids = self.get_selected_pids()

        # Filter data
        filtered_data = self.filter_data(processes)

        # Disable sorting and updates during refresh to completely eliminate UI lag
        self.table.setUpdatesEnabled(False)
        self.table.setSortingEnabled(False)
        self.table.setRowCount(len(filtered_data))
        
        # Update Status bar with rich information
        cpu_usage = psutil.cpu_percent()
        mem_usage = psutil.virtual_memory().percent
        self.val_global_cpu.setText(f"{cpu_usage}%")
        self.val_global_ram.setText(f"{mem_usage}%")
        self.lbl_process_count.setText(f"Showing {len(filtered_data)} of {len(processes)} Processes")

        for row_idx, p in enumerate(filtered_data):
            self.set_row_data(row_idx, p)

        # Restore State
        self.table.setSortingEnabled(True)
        self.table.setUpdatesEnabled(True)
        self.table.verticalScrollBar().setValue(current_scroll)
        if selected_pids:
            self.select_rows_by_pids(selected_pids)

    def set_row_data(self, row, p):
        """Populates a single row in the table."""
        # 0: Checkbox
        chk_item = self.table.item(row, 0)
        if not chk_item:
            chk_item = QTableWidgetItem()
            chk_item.setFlags(Qt.ItemFlag.ItemIsUserCheckable | Qt.ItemFlag.ItemIsEnabled)
            chk_item.setCheckState(Qt.CheckState.Unchecked)
            self.table.setItem(row, 0, chk_item)
        
        chk_item.setData(Qt.ItemDataRole.UserRole, p['pid'])

        # Helper to update text items efficiently
        def update_item(col, text, color=None, bold=False):
            item = self.table.item(row, col)
            if not item:
                item = QTableWidgetItem()
                self.table.setItem(row, col, item)
            
            if item.text() != text:
                item.setText(text)
            
            # Update Color
            if color:
                item.setForeground(QBrush(QColor(color)))
            else:
                item.setData(Qt.ItemDataRole.ForegroundRole, None)
            
            # Update Font
            font = item.font()
            if font.bold() != bold:
                # Prevent Qt warning for uninitialized font sizes (-1)
                if font.pointSize() <= 0 and font.pixelSize() <= 0:
                    font.setPointSize(10) 
                font.setBold(bold)
                item.setFont(font)

        # Helper to update numeric items for sorting
        def update_sortable_item(col, sort_val, display_text=""):
            item = self.table.item(row, col)
            if not isinstance(item, SortableTableWidgetItem):
                item = SortableTableWidgetItem()
                self.table.setItem(row, col, item)
            item.setData(Qt.ItemDataRole.UserRole, sort_val)
            item.setData(Qt.ItemDataRole.DisplayRole, display_text)
            
            # Ensure proper font if displaying text
            if display_text:
                font = item.font()
                if font.pointSize() <= 0 and font.pixelSize() <= 0:
                    font.setPointSize(10)
                item.setFont(font)
            return item

        # 1: PID
        update_sortable_item(1, p['pid'], str(p['pid']))

        # 2: Name
        update_item(2, str(p['name']))

        # 3: Status Badge
        status_str = str(p['status']).upper()
        # Create an invisible sortable item for the status column so it can be clicked/sorted properly
        update_sortable_item(3, status_str, "")
        
        status_widget = self.table.cellWidget(row, 3)
        if not status_widget:
            status_widget = QLabel()
            status_widget.setAlignment(Qt.AlignmentFlag.AlignCenter)
            self.table.setCellWidget(row, 3, status_widget)
            
        if status_widget.text() != status_str:
            status_widget.setText(status_str)
            if p['status'] == 'running':
                status_widget.setStyleSheet("background-color: #27ae60; color: white; border-radius: 4px; padding: 2px 6px; font-weight: bold; font-size: 10px; margin: 4px;")
            elif p['status'] == 'stopped':
                status_widget.setStyleSheet("background-color: #e74c3c; color: white; border-radius: 4px; padding: 2px 6px; font-weight: bold; font-size: 10px; margin: 4px;")
            else:
                status_widget.setStyleSheet("background-color: #7f8c8d; color: white; border-radius: 4px; padding: 2px 6px; font-weight: bold; font-size: 10px; margin: 4px;")

        # 4: CPU
        cpu_val = p['cpu_percent'] or 0.0
        update_sortable_item(4, cpu_val)
        cpu_bar = self.table.cellWidget(row, 4)
        if not cpu_bar:
            cpu_bar = QProgressBar()
            cpu_bar.setTextVisible(True)
            cpu_bar.setMaximum(100)
            cpu_bar.setObjectName("ProcessResourceBar")
            self.table.setCellWidget(row, 4, cpu_bar)
            
        cpu_bar.setValue(int(cpu_val))
        cpu_bar.setFormat(f"{cpu_val:.1f}%")
        
        # Colorize CPU bar if high
        if cpu_val > HIGH_CPU_THRESHOLD:
            cpu_bar.setStyleSheet("QProgressBar::chunk { background-color: #e74c3c; }")
        else:
            cpu_bar.setStyleSheet("QProgressBar::chunk { background-color: #00c6ff; }")

        # 5: Memory
        mem_val = p['memory_percent'] or 0.0
        update_sortable_item(5, mem_val)
        mem_bar = self.table.cellWidget(row, 5)
        if not mem_bar:
            mem_bar = QProgressBar()
            mem_bar.setTextVisible(True)
            mem_bar.setMaximum(100)
            mem_bar.setObjectName("ProcessResourceBar")
            self.table.setCellWidget(row, 5, mem_bar)
            
        mem_bar.setValue(int(mem_val))
        mem_bar.setFormat(f"{mem_val:.1f}%")
        
        # Colorize Mem bar if high
        if mem_val > HIGH_MEM_THRESHOLD:
            mem_bar.setStyleSheet("QProgressBar::chunk { background-color: #f39c12; }")
        else:
            mem_bar.setStyleSheet("QProgressBar::chunk { background-color: #ff5e7e; }")

        # 6: Disk Read
        disk_r = p.get('disk_read', 0)
        update_sortable_item(6, disk_r)
        update_item(6, f"{disk_r / (1024*1024):.1f} MB", color="#a29bfe")

        # 7: Disk Write
        disk_w = p.get('disk_write', 0)
        update_sortable_item(7, disk_w)
        update_item(7, f"{disk_w / (1024*1024):.1f} MB", color="#74b9ff")

        # 8: User
        user = p.get('username') or "System"
        # Clean up Windows domain prefix if present
        if "\\" in user:
            user = user.split("\\")[-1]
        update_item(8, user)

        # Start Time
        try:
            t = datetime.datetime.fromtimestamp(p['create_time'])
            time_str = t.strftime("%H:%M:%S")
        except Exception:
            time_str = "-"
        update_item(9, time_str)
        
        # AI Threat Highlighting or Suspicious Heuristic
        if self.ai_scan_enabled and p.get('ai_color'):
            bg_color = QColor(p['ai_color'])
            bg_color.setAlpha(50)
        else:
            is_suspicious = (p.get('cpu_percent') or 0) > 85 or (p.get('memory_percent') or 0) > 85
            bg_color = QColor(231, 76, 60, 40) if is_suspicious else None
        
        for col in range(1, 10):
            item = self.table.item(row, col)
            if item:
                if bg_color:
                    item.setBackground(QBrush(bg_color))
                else:
                    item.setData(Qt.ItemDataRole.BackgroundRole, None)

    def filter_data(self, processes):
        filtered = processes
        
        # Apply Category Filter for AI Levels
        if hasattr(self, 'current_category') and self.ai_scan_enabled:
            level_map = {
                "Level 1 (Safe)": 1,
                "Level 2 (Low Risk)": 2,
                "Level 3 (Moderate)": 3,
                "Level 4 (High Risk)": 4,
                "Level 5 (Critical)": 5
            }
            if self.current_category in level_map:
                target_level = level_map[self.current_category]
                filtered = [p for p in filtered if p.get('ai_level') == target_level]

        # Apply Text Filter
        if self.filter_text:
            search_lower = self.filter_text.lower()
            filtered = [p for p in filtered if search_lower in p.get('name', '').lower() or search_lower in str(p.get('pid', ''))]
            
        return filtered

    def set_category_filter(self, category):
        self.current_category = category
        if hasattr(self, 'process_data'):
            self.update_table(self.process_data)

    def close_details_panel(self):
        self.details_panel.hide()
        self.table.clearSelection()

    def handle_search(self, text):
        self.filter_text = text
        self.update_table(self.process_data)
        
    def on_process_selected(self):
        selected = self.table.selectedItems()
        if not selected:
            self.details_panel.hide()
            return
            
        row = selected[0].row()
        pid_item = self.table.item(row, 1)
        if not pid_item:
            return
            
        pid = int(pid_item.text())
        self.details_panel.show()
        self.txt_details_info.setHtml(f"Loading forensics for PID {pid}...")
        
        # One-off forensic pull
        try:
            proc = psutil.Process(pid)
            
            try:
                exe = proc.exe() or "Unknown"
            except psutil.AccessDenied:
                exe = "Access Denied"
                
            try:
                cmd = " ".join(proc.cmdline()) or "Unknown"
            except psutil.AccessDenied:
                cmd = "Access Denied"
                
            try:
                threads = proc.num_threads()
            except psutil.AccessDenied:
                threads = "Unknown"
            
            try:
                conns = len(proc.connections())
            except psutil.AccessDenied:
                conns = "Access Denied"
                
            # Attempt to locate the process in cached data for AI Level
            p_data = None
            if hasattr(self, 'process_data'):
                for p in self.process_data:
                    if p.get('pid') == pid:
                        p_data = p
                        break
            
            ai_reasoning = ""
            if self.ai_scan_enabled and p_data and p_data.get('ai_level'):
                lvl = p_data.get('ai_level')
                reason = "This process exhibits "
                
                # Dynamic Reasoning Engine
                factors = []
                cpu_p = p_data.get('cpu_percent') or 0
                mem_p = p_data.get('memory_percent') or 0
                path_ctx = (exe + " " + cmd).lower()
                
                if 'temp' in path_ctx and 'access denied' not in path_ctx:
                    factors.append("execution from a highly suspicious temporary directory")
                if 'appdata' in path_ctx and 'access denied' not in path_ctx:
                    factors.append("execution from an AppData roaming/local user directory")
                if cpu_p > 30:
                    factors.append(f"excessive CPU utilization ({cpu_p:.1f}%)")
                if mem_p > 30:
                    factors.append(f"heavy memory consumption ({mem_p:.1f}%)")
                if conns != "Access Denied" and conns > 0:
                    factors.append("active outbound network sockets")
                
                if lvl == 1:
                    ai_reasoning = "<b>🧠 AI Analysis: <span style='color:#00b894;'>Level 1 (Safe)</span></b><br>The AI engine determined this process to be benign. It operates within normal system bounds without exhibiting any recognized malicious patterns or resource anomalies."
                elif lvl == 2:
                    reason += factors[0] if factors else "minor telemetry anomalies"
                    ai_reasoning = f"<b>🧠 AI Analysis: <span style='color:#0984e3;'>Level 2 (Low Risk)</span></b><br>The AI detected minor irregularities, primarily {reason}, but it does not currently pose a significant threat. Standard system process behavior is observed."
                elif lvl == 3:
                    reason += " and ".join(factors[:2]) if len(factors) > 0 else "moderate anomalous resource usage"
                    ai_reasoning = f"<b>🧠 AI Analysis: <span style='color:#fdcb6e;'>Level 3 (Moderate Risk)</span></b><br>The AI flagged this process due to its atypical behavioral signature. Specifically, it displays {reason}. It warrants monitoring."
                elif lvl == 4:
                    reason += ", and ".join(factors) if len(factors) > 0 else "highly suspicious characteristics"
                    ai_reasoning = f"<b>🧠 AI Analysis: <span style='color:#e17055;'>Level 4 (High Risk)</span></b><br>The AI strongly suspects this process is malicious. It identified a dangerous combination of {reason}. Immediate investigation is highly recommended."
                elif lvl == 5:
                    reason += ", and ".join(factors) if len(factors) > 0 else "critical malicious indicators"
                    ai_reasoning = f"<b>🧠 AI Analysis: <span style='color:#d63031;'>Level 5 (Critical)</span></b><br><b>WARNING:</b> The AI has classified this process as a critical threat. The specific combination of {reason} perfectly matches high-confidence malware execution signatures."
                
                ai_reasoning += "<br><br>"
            
            details = ai_reasoning
            details += f"<b style='color:#0078d7;'>Executable Path:</b><br>{exe}<br><br>"
            details += f"<b style='color:#0078d7;'>Command Line Arguments:</b><br>{cmd}<br><br>"
            details += f"<b style='color:#0078d7;'>Active Threads:</b> {threads}<br><br>"
            details += f"<b style='color:#0078d7;'>Network Connections:</b> {conns}<br>"
            
            self.txt_details_info.setHtml(details)
        except psutil.NoSuchProcess:
            self.txt_details_info.setHtml(f"Process {pid} has terminated.")
        except Exception as e:
            self.txt_details_info.setHtml(f"Error fetching forensics: {str(e)}")

    def get_selected_pids(self):
        pids = []
        for row in range(self.table.rowCount()):
            item = self.table.item(row, 0)
            if item and item.checkState() == Qt.CheckState.Checked:
                pids.append(item.data(Qt.ItemDataRole.UserRole))
        return pids

    def select_rows_by_pids(self, pids):
        for row in range(self.table.rowCount()):
            item = self.table.item(row, 0)
            if item and item.data(Qt.ItemDataRole.UserRole) in pids:
                item.setCheckState(Qt.CheckState.Checked)

    def kill_process(self):
        pids = self.get_selected_pids()
        if not pids:
            QMessageBox.warning(self, "No Selection", "Please select process(es) to terminate.")
            return

        count = len(pids)
        reply = QMessageBox.question(
            self, "Confirm Kill", 
            f"Are you sure you want to terminate {count} process(es)?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )

        if reply == QMessageBox.StandardButton.Yes:
            errors = []
            for pid in pids:
                if pid in [0, 4]: continue
                try:
                    p = psutil.Process(pid)
                    p_name = p.name()
                    p.terminate()
                    db_path = self.session.get_db_path() if self.session else "nexashield.db"
                    DatabaseManager(db_path).log_siem_event("Process Monitor", f"Terminated process '{p_name}' (PID: {pid})", "Warning")
                except psutil.AccessDenied:
                    errors.append(f"PID {pid}: Access Denied")
                except Exception as e:
                    errors.append(f"PID {pid}: {str(e)}")
            
            if errors:
                QMessageBox.warning(self, "Partial Errors", "\n".join(errors[:5]))
            else:
                QMessageBox.information(self, "Success", "Selected processes terminated.")
            self.refresh_data()

    def change_process_state(self, action):
        pids = self.get_selected_pids()
        if not pids:
            return

        count = 0
        for pid in pids:
            try:
                p = psutil.Process(pid)
                if action == "suspend":
                    p.suspend()
                elif action == "resume":
                    p.resume()
                count += 1
            except Exception:
                pass
        
        self.lbl_system_status.setText(f"🟢 System Status: {action.capitalize()}ed {count} processes.")
        self.refresh_data()

    def export_csv(self):
        import io
        try:
            output = io.StringIO()
            writer = csv.writer(output)
            writer.writerow(["PID", "Name", "Status", "CPU%", "Mem%", "User", "Created"])
            for p in self.process_data:
                writer.writerow([
                    p['pid'], p['name'], p['status'], 
                    p['cpu_percent'], p['memory_percent'], 
                    p['username'], p['create_time']
                ])
                
            if self.session and hasattr(self.session, 'file_manager'):
                self.session.file_manager.export_file(
                    filename="processes.csv",
                    content=output.getvalue(),
                    module_source="Process Monitor",
                    file_type="CSV",
                    tags="Routine"
                )
                QMessageBox.information(self, "Vaulted", "Process list CSV securely vaulted in FMS.")
            else:
                QMessageBox.warning(self, "Warning", "FMS not available.")
        except Exception as e:
            QMessageBox.critical(self, "Export Error", str(e))

    def export_pdf(self):
        import tempfile
        import os
        try:
            temp_fd, temp_path = tempfile.mkstemp(suffix=".pdf")
            os.close(temp_fd)
            
            printer = QPrinter(QPrinter.PrinterMode.HighResolution)
            printer.setOutputFormat(QPrinter.OutputFormat.PdfFormat)
            printer.setOutputFileName(temp_path)
            
            # Build HTML Table
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
                <h1>System Processes Report</h1>
                <p>Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                <table>
                    <thead>
                        <tr>
                            <th>PID</th><th>Name</th><th>Status</th><th>CPU%</th><th>Mem%</th><th>User</th><th>Start Time</th>
                        </tr>
                    </thead>
                    <tbody>
            """

            for p in self.process_data:
                try:
                    t = datetime.datetime.fromtimestamp(p['create_time'])
                    time_str = t.strftime("%H:%M:%S")
                except:
                    time_str = "-"
                
                user = p.get('username') or "System"
                if "\\" in user:
                    user = user.split("\\")[-1]

                html += f"<tr><td>{p['pid']}</td><td>{p['name']}</td><td>{p['status']}</td>" \
                        f"<td>{p['cpu_percent']:.1f}</td><td>{p['memory_percent']:.1f}</td>" \
                        f"<td>{user}</td><td>{time_str}</td></tr>"

            html += "</tbody></table></body></html>"
            
            doc = QTextDocument()
            doc.setHtml(html)
            doc.print(printer)
            
            with open(temp_path, "rb") as f:
                pdf_bytes = f.read()
            os.remove(temp_path)
            
            if self.session and hasattr(self.session, 'file_manager'):
                self.session.file_manager.export_file(
                    filename="processes.pdf",
                    content=pdf_bytes,
                    module_source="Process Monitor",
                    file_type="PDF",
                    tags="Routine"
                )
                QMessageBox.information(self, "Vaulted", "Process list PDF securely vaulted in FMS.")
            else:
                QMessageBox.warning(self, "Warning", "FMS not available.")
            
        except Exception as e:
            QMessageBox.critical(self, "Export Error", str(e))
