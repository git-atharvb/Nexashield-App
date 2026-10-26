from PyQt6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QStackedWidget, QPushButton, QFrame, QMessageBox, QDialog, QApplication
)
from PyQt6.QtCore import Qt, pyqtSignal, QPropertyAnimation, QEasingCurve, QTimer
from tabs.process import ProcessMonitorWidget
from tabs.network import NetworkMonitorWidget
from tabs.siem import SIEMDashboard
from tabs.phishing_detector import PhishingDetectorWidget
from tabs.antivirus import AntivirusWidget
from tabs.memory import MemoryMonitorWidget
from tabs.cloud import CloudSecurityWidget
from tabs.nids import NIDSWidget
from tabs.firewall import FirewallWidget

class LogoutSuccessDialog(QDialog):
    """A custom, modern dialog for successful logout."""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowFlags(Qt.WindowType.FramelessWindowHint | Qt.WindowType.Dialog)
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
        self.setFixedSize(300, 180)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)

        container = QFrame()
        container.setObjectName("SuccessDialogContainer")
        container_layout = QVBoxLayout(container)
        container_layout.setSpacing(10)
        container_layout.setContentsMargins(20, 20, 20, 20)

        # Icon
        icon = QLabel("👋")
        icon.setAlignment(Qt.AlignmentFlag.AlignCenter)
        icon.setObjectName("LogoutIcon")
        
        # Text
        lbl_title = QLabel("Logged Out")
        lbl_title.setObjectName("SuccessTitle")
        lbl_title.setAlignment(Qt.AlignmentFlag.AlignCenter)

        lbl_msg = QLabel("Thank you for using\nNexaShield")
        lbl_msg.setObjectName("SuccessMsg")
        lbl_msg.setAlignment(Qt.AlignmentFlag.AlignCenter)

        container_layout.addWidget(icon)
        container_layout.addWidget(lbl_title)
        container_layout.addWidget(lbl_msg)
        
        layout.addWidget(container)

        # Animation Setup (Snappy and responsive)
        self.setWindowOpacity(0.0)
        
        self.fade_in = QPropertyAnimation(self, b"windowOpacity")
        self.fade_in.setDuration(250)
        self.fade_in.setStartValue(0.0)
        self.fade_in.setEndValue(1.0)
        self.fade_in.setEasingCurve(QEasingCurve.Type.InOutQuad)
        
        self.fade_out = QPropertyAnimation(self, b"windowOpacity")
        self.fade_out.setDuration(250)
        self.fade_out.setStartValue(1.0)
        self.fade_out.setEndValue(0.0)
        self.fade_out.setEasingCurve(QEasingCurve.Type.InOutQuad)
        self.fade_out.finished.connect(self.accept)

        # Sequence: Fade In -> Brief Pause -> Fade Out
        self.fade_in.start()
        QTimer.singleShot(600, self.fade_out.start)

    def mousePressEvent(self, event):
        # Allow user to click to dismiss immediately
        self.accept()

class RefreshToastDialog(QDialog):
    """A non-blocking toast notification for refresh actions."""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowFlags(Qt.WindowType.FramelessWindowHint | Qt.WindowType.ToolTip)
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
        self.setFixedSize(260, 60)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        container = QFrame()
        container.setObjectName("CardContainer") 
        container_layout = QHBoxLayout(container)
        
        icon = QLabel("✅")
        icon.setStyleSheet("color: #28a745; font-size: 18px; background: transparent; border: none;")
        lbl_msg = QLabel("Refreshed page successfully")
        lbl_msg.setStyleSheet("font-size: 13px; font-weight: bold; background: transparent; border: none;")
        
        container_layout.addWidget(icon)
        container_layout.addWidget(lbl_msg)
        layout.addWidget(container)

        self.setWindowOpacity(0.0)
        self.anim = QPropertyAnimation(self, b"windowOpacity")
        self.anim.setDuration(300)
        self.anim.setStartValue(0.0)
        self.anim.setEndValue(1.0)
        self.anim.start()
        
        QTimer.singleShot(1000, self.fade_out)

    def fade_out(self):
        self.anim.setStartValue(1.0)
        self.anim.setEndValue(0.0)
        self.anim.finished.connect(self.accept)
        self.anim.start()

class HomeWindow(QMainWindow):
    logout_requested = pyqtSignal()

    def __init__(self, session_manager=None):
        super().__init__()
        self.session = session_manager
        
        # Main Layout
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        # Use 0 margins so the navbar touches the edges
        self.layout = QVBoxLayout(central_widget)
        self.layout.setContentsMargins(0, 0, 0, 0)
        self.layout.setSpacing(0)

        # --- Top Navigation Bar ---
        self.navbar = QFrame()
        self.navbar.setObjectName("Navbar")
        self.navbar.setFixedHeight(60)
        nav_layout = QHBoxLayout(self.navbar)
        nav_layout.setContentsMargins(20, 0, 20, 0)
        nav_layout.setSpacing(15)

        # Logo / Title
        title = QLabel("NexaShield")
        title.setObjectName("NavbarTitle")
        nav_layout.addWidget(title)

        nav_layout.addStretch()

        # Module definitions with lazy factory callables to avoid eager loading freeze
        self.module_definitions = [
            ("📊 SIEM", "SIEM Dashboard", lambda: SIEMDashboard(self.session)),
            ("⚡ Processes", "Process Management", lambda: ProcessMonitorWidget(self.session)),
            ("🌐 Network", "Network Management", lambda: NetworkMonitorWidget(self.session)),
            ("🧠 Memory", "Memory Analysis", lambda: MemoryMonitorWidget(self.session)),
            ("🎣 Phishing", "Phishing Detector", lambda: PhishingDetectorWidget(self.session)),
            ("🚨 NIDS", "Network Intrusion Detection System", lambda: NIDSWidget(self.session)),
            ("🔥 Firewall", "Firewall Control", lambda: FirewallWidget(self.session)),
            ("🛡️ Antivirus", "Antivirus Scanner", lambda: AntivirusWidget(self.session)),
            ("☁️ Cloud", "Cloud Security", lambda: CloudSecurityWidget(self.session))
        ]

        self.tab_instances = [None] * len(self.module_definitions)
        self.nav_buttons = []

        for i, (btn_text, _, _) in enumerate(self.module_definitions):
            btn = QPushButton(btn_text)
            btn.setObjectName("NavButton")
            btn.setCheckable(True)
            btn.clicked.connect(lambda checked, idx=i: self.switch_tab(idx))
            nav_layout.addWidget(btn)
            self.nav_buttons.append(btn)

        # Refresh Button
        self.refresh_btn = QPushButton("🔄")
        self.refresh_btn.setFixedSize(40, 40)
        self.refresh_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.refresh_btn.setObjectName("IconButton")
        self.refresh_btn.setToolTip("Refresh Current Tab")
        self.refresh_btn.clicked.connect(self.refresh_current_tab)
        nav_layout.addWidget(self.refresh_btn)

        # Theme Toggle
        self.theme_toggle = QPushButton("☀️")
        self.theme_toggle.setFixedSize(40, 40)
        self.theme_toggle.setCursor(Qt.CursorShape.PointingHandCursor)
        self.theme_toggle.setObjectName("ThemeToggle")
        self.theme_toggle.setToolTip("Toggle Theme (Dark / Light)")
        nav_layout.addWidget(self.theme_toggle)

        # Logout Button
        self.logout_btn = QPushButton("Logout")
        self.logout_btn.setFixedHeight(40)
        self.logout_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.logout_btn.setObjectName("LogoutButton")
        self.logout_btn.setToolTip("Sign Out of Session")
        self.logout_btn.clicked.connect(self.confirm_logout)
        nav_layout.addWidget(self.logout_btn)

        self.layout.addWidget(self.navbar)

        # --- Content Area (Stacked) ---
        self.content_area = QStackedWidget()
        self.layout.addWidget(self.content_area)

        # Pre-populate stacked widget with placeholders for lazy-loaded tabs
        for i, (_, label, _) in enumerate(self.module_definitions):
            self.content_area.addWidget(self.create_placeholder(label))

        # Immediately activate Tab 0 (SIEM Dashboard) smoothly
        self.switch_tab(0)

    def switch_tab(self, index):
        """Switches the stacked widget and lazily loads tab widgets on demand."""
        if index < 0 or index >= len(self.module_definitions):
            return

        for i, btn in enumerate(self.nav_buttons):
            btn.setChecked(i == index)

        # If this module hasn't been instantiated yet, construct it smoothly
        if self.tab_instances[index] is None:
            QApplication.setOverrideCursor(Qt.CursorShape.WaitCursor)
            QApplication.processEvents()
            try:
                creator = self.module_definitions[index][2]
                widget = creator()
                self.tab_instances[index] = widget
                
                # Replace the placeholder widget
                old_widget = self.content_area.widget(index)
                self.content_area.removeWidget(old_widget)
                if old_widget:
                    old_widget.deleteLater()
                self.content_area.insertWidget(index, widget)
            except Exception as e:
                print(f"[-] Error lazily loading tab {index}: {e}")
            finally:
                QApplication.restoreOverrideCursor()
                QApplication.processEvents()

        self.content_area.setCurrentIndex(index)

    def refresh_current_tab(self):
        current_index = self.content_area.currentIndex()
        current_widget = self.content_area.widget(current_index)
        
        # Trigger reset/refresh if supported by the active module
        if hasattr(current_widget, "reset_ui"):
            current_widget.reset_ui()
        elif hasattr(current_widget, "refresh_data"):
            current_widget.refresh_data()
        elif hasattr(current_widget, "update_all_stats"):
            current_widget.update_all_stats()
        elif hasattr(current_widget, "load_rules"):
            current_widget.load_rules()
            
        # Show Toast Notification
        self._toast = RefreshToastDialog(self)
        parent_geom = self.geometry()
        x = parent_geom.x() + (parent_geom.width() - self._toast.width()) // 2
        y = parent_geom.y() + 80 # Display slightly below the navbar
        self._toast.move(x, y)
        self._toast.show()

    def create_placeholder(self, text):
        widget = QWidget()
        layout = QVBoxLayout(widget)
        label = QLabel(f"⚡ Loading {text}...")
        label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        label.setObjectName("PlaceholderLabel")
        label.setStyleSheet("font-size: 16px; color: #888888; font-weight: bold;")
        layout.addWidget(label)
        return widget

    def confirm_logout(self):
        reply = QMessageBox.question(
            self, "Confirm Logout", 
            "Are you sure you want to log out?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No
        )
        if reply == QMessageBox.StandardButton.Yes:
            dlg = LogoutSuccessDialog(self)
            dlg.exec()
            self.logout_requested.emit()