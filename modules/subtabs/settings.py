from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QFrame, QListWidget,
    QStackedWidget, QPushButton, QSlider, QComboBox, QFormLayout,
    QLineEdit, QSpinBox, QScrollArea, QListWidgetItem
)
from PyQt6.QtCore import Qt, pyqtProperty, QPropertyAnimation
from PyQt6.QtGui import QColor, QPainter, QBrush
import psutil

class AnimatedToggle(QWidget):
    """A custom iOS-style animated toggle switch for a premium feel."""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedSize(50, 26)
        self._checked = False
        self._position = 3
        
        self.anim = QPropertyAnimation(self, b"position")
        self.anim.setDuration(200)
        self.setCursor(Qt.CursorShape.PointingHandCursor)

    @pyqtProperty(int)
    def position(self):
        return self._position

    @position.setter
    def position(self, pos):
        self._position = pos
        self.update()

    def isChecked(self):
        return self._checked

    def setChecked(self, checked):
        self._checked = checked
        self.anim.setEndValue(25 if checked else 3)
        self.anim.start()

    def mouseReleaseEvent(self, event):
        if event.button() == Qt.MouseButton.LeftButton:
            self.setChecked(not self._checked)
            
    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        
        # Draw background track
        bg_color = QColor("#0078d7") if self._checked else QColor("#555555")
        painter.setBrush(QBrush(bg_color))
        painter.setPen(Qt.PenStyle.NoPen)
        painter.drawRoundedRect(0, 0, self.width(), self.height(), 13, 13)
        
        # Draw circular handle
        painter.setBrush(QBrush(QColor("#ffffff")))
        painter.drawEllipse(self._position, 3, 20, 20)


class SettingsWidget(QWidget):
    def __init__(self, session_manager=None):
        super().__init__()
        self.session = session_manager
        self.setup_ui()

    def setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(20)

        # 1. Header
        header = QLabel("⚙️ Control Panel & Preferences")
        header.setStyleSheet("font-size: 26px; font-weight: 800; color: #0078d7; letter-spacing: 1px;")
        layout.addWidget(header)

        # 2. Split pane (Sidebar + Stacked Content)
        main_split = QHBoxLayout()
        
        # Sidebar Navigation
        self.sidebar = QListWidget()
        self.sidebar.setFixedWidth(220)
        self.sidebar.setObjectName("SettingsSidebar")
        self.sidebar.setStyleSheet("""
            QListWidget {
                background-color: transparent;
                border: none;
                outline: none;
            }
            QListWidget::item {
                padding: 12px 15px;
                margin-bottom: 5px;
                border-radius: 8px;
                font-size: 14px;
                font-weight: bold;
                color: #8b949e;
            }
            QListWidget::item:selected {
                background-color: rgba(0, 120, 215, 0.2);
                color: #0078d7;
                border-left: 4px solid #0078d7;
            }
            QListWidget::item:hover:!selected {
                background-color: rgba(255, 255, 255, 0.05);
            }
        """)
        
        categories = [
            "🎨 Appearance", 
            "🧠 AI & Threat Engine", 
            "🌐 Network & Firewall", 
            "🛑 Antivirus & Sandbox", 
            "🗄️ Database & Storage", 
            "🔔 Notifications & Alerts", 
            "🛡️ Access & Account"
        ]
        self.sidebar.addItems(categories)
        
        # Stacked content area
        self.stack = QStackedWidget()
        
        self.setup_appearance_page()
        self.setup_ai_engine_page()
        self.setup_network_page()
        self.setup_antivirus_page()
        self.setup_database_page()
        self.setup_notifications_page()
        self.setup_account_page()
        
        # Sync sidebar selection with stacked widget
        self.sidebar.currentRowChanged.connect(self.stack.setCurrentIndex)
        self.sidebar.setCurrentRow(0)
        
        main_split.addWidget(self.sidebar)
        main_split.addWidget(self.stack, stretch=1)
        layout.addLayout(main_split)
        
        # 3. Bottom Action Bar
        action_bar = QHBoxLayout()
        action_bar.addStretch()
        
        btn_reset = QPushButton("Restore Defaults")
        btn_reset.setStyleSheet("padding: 8px 15px; border: 1px solid #555; border-radius: 6px; font-weight: bold; background: transparent;")
        
        btn_save = QPushButton("Save Configuration")
        btn_save.setStyleSheet("padding: 8px 15px; background-color: #0078d7; color: white; border-radius: 6px; font-weight: bold; border: none;")
        
        action_bar.addWidget(btn_reset)
        action_bar.addWidget(btn_save)
        
        layout.addLayout(action_bar)

    def create_card(self, title):
        """Helper to create a unified glassmorphic card for settings forms."""
        frame = QFrame()
        frame.setObjectName("CardContainer")
        layout = QVBoxLayout(frame)
        layout.setContentsMargins(20, 20, 20, 20)
        
        lbl_title = QLabel(title)
        lbl_title.setStyleSheet("font-size: 18px; font-weight: bold; background: transparent;")
        layout.addWidget(lbl_title)
        layout.addSpacing(15)
        
        form = QFormLayout()
        form.setSpacing(20)
        layout.addLayout(form)
        return frame, form

    def setup_appearance_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        
        card, form = self.create_card("UI & Aesthetics")
        
        theme_combo = QComboBox()
        theme_combo.addItems(["Dark Mode (SOC Default)", "Light Mode", "System Default"])
        form.addRow(QLabel("System Theme:"), theme_combo)
        
        color_combo = QComboBox()
        color_combo.addItems(["Cyber Blue (Default)", "Hacker Green", "Alert Red", "Deep Purple"])
        form.addRow(QLabel("Accent Color:"), color_combo)
        
        glass_toggle = AnimatedToggle()
        glass_toggle.setChecked(True)
        form.addRow(QLabel("Enable Glassmorphism (Requires restart):"), glass_toggle)
        
        layout.addWidget(card)
        layout.addStretch()
        self.stack.addWidget(page)

    def setup_ai_engine_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        
        card, form = self.create_card("IsolationForest Anomaly Detector")
        
        slider = QSlider(Qt.Orientation.Horizontal)
        slider.setRange(1, 100)
        slider.setValue(80)
        form.addRow(QLabel("Detection Sensitivity (Strict ↔ Lenient):"), slider)
        
        rate = QComboBox()
        rate.addItems(["1 Second (Aggressive)", "2 Seconds (Balanced)", "5 Seconds (Battery Saver)"])
        rate.setCurrentIndex(1)
        form.addRow(QLabel("Telemetry Polling Rate:"), rate)
        
        layout.addWidget(card)
        
        soar_card, soar_form = self.create_card("SOAR Automation Playbooks")
        soar_form.addRow(QLabel("Auto-Kill High Risk Processes:"), AnimatedToggle())
        
        t_block = AnimatedToggle()
        t_block.setChecked(True)
        soar_form.addRow(QLabel("Auto-Block Known Malicious IPs:"), t_block)
        
        layout.addWidget(soar_card)
        layout.addStretch()
        self.stack.addWidget(page)

    def setup_network_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        
        card, form = self.create_card("Network Intrusion Detection System (NIDS)")
        
        iface_combo = QComboBox()
        try:
            interfaces = psutil.net_if_addrs().keys()
            iface_combo.addItems(list(interfaces))
            iface_combo.addItems(["All Interfaces (0.0.0.0)"])
        except Exception:
            iface_combo.addItems(["eth0", "wlan0", "lo", "All Interfaces"])
        form.addRow(QLabel("Monitoring Interface:"), iface_combo)
        
        promiscuous = AnimatedToggle()
        form.addRow(QLabel("Enable Promiscuous Mode (Packet Sniffing):"), promiscuous)
        
        port_scan = QSlider(Qt.Orientation.Horizontal)
        port_scan.setRange(1, 100)
        port_scan.setValue(90)
        form.addRow(QLabel("Port Scan Detection Sensitivity:"), port_scan)
        
        layout.addWidget(card)
        
        fw_card, fw_form = self.create_card("Firewall & Syslog Forwarding")
        
        fw_combo = QComboBox()
        fw_combo.addItems(["Allow All (Monitor Only)", "Trusted Only (Standard)", "Zero Trust (Lockdown)"])
        fw_combo.setCurrentIndex(1)
        fw_form.addRow(QLabel("Firewall Strictness:"), fw_combo)
        
        syslog_ip = QLineEdit()
        syslog_ip.setPlaceholderText("e.g. 192.168.1.100")
        fw_form.addRow(QLabel("Syslog Server IP:"), syslog_ip)
        
        syslog_port = QSpinBox()
        syslog_port.setRange(1, 65535)
        syslog_port.setValue(514)
        fw_form.addRow(QLabel("Syslog Server Port:"), syslog_port)
        
        layout.addWidget(fw_card)
        layout.addStretch()
        self.stack.addWidget(page)

    def setup_antivirus_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        
        card, form = self.create_card("File System Shield & Antivirus")
        
        rt_protect = AnimatedToggle()
        rt_protect.setChecked(True)
        form.addRow(QLabel("Real-Time File System Watchdog:"), rt_protect)
        
        heuristic = AnimatedToggle()
        heuristic.setChecked(True)
        form.addRow(QLabel("Heuristic Analysis Engine:"), heuristic)
        
        quarantine_dir = QLineEdit()
        quarantine_dir.setText("C:\\NexaShield\\Quarantine")
        form.addRow(QLabel("Quarantine Directory:"), quarantine_dir)
        
        layout.addWidget(card)
        
        ex_card, ex_form = self.create_card("Exclusions")
        
        ex_list = QListWidget()
        ex_list.setFixedHeight(100)
        ex_list.setStyleSheet("background: rgba(0,0,0,0.2); border: 1px solid #333; border-radius: 6px; color: white;")
        ex_list.addItems(["C:\\Windows\\System32\\", "D:\\Games\\"])
        ex_form.addRow(QLabel("Excluded Paths:"), ex_list)
        
        btn_add = QPushButton("Add Exclusion")
        ex_form.addRow(QLabel(""), btn_add)
        
        layout.addWidget(ex_card)
        layout.addStretch()
        self.stack.addWidget(page)

    def setup_notifications_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        
        card, form = self.create_card("Alerts & Integrations")
        
        toast = AnimatedToggle()
        toast.setChecked(True)
        form.addRow(QLabel("Show Desktop Notifications:"), toast)
        
        min_sev = QComboBox()
        min_sev.addItems(["Low Risk (All)", "Medium", "High", "Critical Only"])
        min_sev.setCurrentIndex(2)
        form.addRow(QLabel("Minimum Alert Threshold:"), min_sev)
        
        layout.addWidget(card)
        
        int_card, int_form = self.create_card("External Webhooks")
        
        email_inp = QLineEdit()
        email_inp.setPlaceholderText("admin@soc-center.local")
        int_form.addRow(QLabel("Admin Email Address:"), email_inp)
        
        slack_inp = QLineEdit()
        slack_inp.setPlaceholderText("https://hooks.slack.com/services/...")
        int_form.addRow(QLabel("Slack/Discord Webhook URL:"), slack_inp)
        
        layout.addWidget(int_card)
        layout.addStretch()
        self.stack.addWidget(page)


    def setup_database_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        
        card, form = self.create_card("Data Retention & Backup")
        
        retention = QComboBox()
        retention.addItems(["Keep logs for 7 days", "Keep logs for 30 days", "Keep logs for 90 days", "Keep indefinitely"])
        retention.setCurrentIndex(1)
        form.addRow(QLabel("Log Retention Policy:"), retention)
        
        btn_export = QPushButton("Export Configs (*.json)")
        form.addRow(QLabel("Backup:"), btn_export)
        
        layout.addWidget(card)
        
        danger_card = QFrame()
        danger_card.setStyleSheet("QFrame { background-color: rgba(220, 53, 69, 0.1); border: 1px solid #dc3545; border-radius: 12px; }")
        danger_layout = QVBoxLayout(danger_card)
        danger_layout.setContentsMargins(20, 20, 20, 20)
        
        danger_lbl = QLabel("⚠️ Danger Zone")
        danger_lbl.setStyleSheet("font-size: 18px; font-weight: bold; color: #dc3545; border: none; background: transparent;")
        danger_layout.addWidget(danger_lbl)
        
        btn_wipe = QPushButton("Clear Threat Logs")
        btn_wipe.setStyleSheet("padding: 8px 15px; background-color: #dc3545; color: white; border-radius: 6px; font-weight: bold; border: none;")
        danger_layout.addWidget(btn_wipe)
        
        layout.addWidget(danger_card)
        layout.addStretch()
        self.stack.addWidget(page)

    def setup_account_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        
        card, form = self.create_card("Security & Access")
        
        form.addRow(QLabel("Multi-Factor Authentication (2FA):"), AnimatedToggle())
        
        btn_pwd = QPushButton("Change Master Password")
        form.addRow(QLabel("Account Security:"), btn_pwd)
        
        btn_api = QPushButton("Generate New API Key")
        form.addRow(QLabel("Integrations:"), btn_api)
        
        layout.addWidget(card)
        layout.addStretch()
        self.stack.addWidget(page)