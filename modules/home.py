from PyQt6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QStackedWidget, QPushButton, QFrame, QMessageBox, QDialog
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

        # Animation Setup
        self.setWindowOpacity(0.0)
        
        self.fade_in = QPropertyAnimation(self, b"windowOpacity")
        self.fade_in.setDuration(500)
        self.fade_in.setStartValue(0.0)
        self.fade_in.setEndValue(1.0)
        self.fade_in.setEasingCurve(QEasingCurve.Type.InOutQuad)
        
        self.fade_out = QPropertyAnimation(self, b"windowOpacity")
        self.fade_out.setDuration(500)
        self.fade_out.setStartValue(1.0)
        self.fade_out.setEndValue(0.0)
        self.fade_out.setEasingCurve(QEasingCurve.Type.InOutQuad)
        self.fade_out.finished.connect(self.accept)

        # Sequence: Fade In -> Wait -> Fade Out
        self.fade_in.start()
        QTimer.singleShot(1500, self.fade_out.start)

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

        nav_layout.addStretch() # Push buttons to the right (or center if you prefer)

        # Navigation Buttons
        self.nav_buttons = []
        self.modules = [
            ("📊 SIEM", "SIEM Dashboard"),
            ("⚡ Processes", "Process Management"),
            ("🌐 Network", "Network Management"),
            ("🧠 Memory", "Memory Analysis"),
            ("🎣 Phishing", "Phishing Detector"),
            ("🚨 NIDS", "Network Intrusion Detection System"),
            ("🔥 Firewall", "Firewall Control"),
            ("🛡️ Antivirus", "Antivirus Scanner"),
            ("☁️ Cloud", "Cloud Security")
        ]

        for i, (btn_text, _) in enumerate(self.modules):
            btn = QPushButton(btn_text)
            btn.setObjectName("NavButton")
            btn.setCheckable(True)
            # Use lambda with default argument to capture the current index 'i'
            btn.clicked.connect(lambda checked, idx=i: self.switch_tab(idx))
            nav_layout.addWidget(btn)
            self.nav_buttons.append(btn)

        # Refresh Button
        self.refresh_btn = QPushButton("🔄")
        self.refresh_btn.setFixedSize(40, 40)
        self.refresh_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.refresh_btn.setObjectName("ThemeToggle") # Reuse transparent styling
        self.refresh_btn.clicked.connect(self.refresh_current_tab)
        nav_layout.addWidget(self.refresh_btn)

        # Theme Toggle
        self.theme_toggle = QPushButton("☀️")
        self.theme_toggle.setFixedSize(40, 40)
        self.theme_toggle.setCursor(Qt.CursorShape.PointingHandCursor)
        self.theme_toggle.setObjectName("ThemeToggle")
        nav_layout.addWidget(self.theme_toggle)

        # Logout Button
        logout_btn = QPushButton("Logout")
        logout_btn.setObjectName("LogoutButton")
        logout_btn.clicked.connect(self.confirm_logout)
        nav_layout.addWidget(logout_btn)

        self.layout.addWidget(self.navbar)

        # --- Content Area (Stacked) ---
        self.content_area = QStackedWidget()
        self.layout.addWidget(self.content_area)

        # Inject SessionManager into all modules
        self.content_area.addWidget(SIEMDashboard(self.session))
        self.content_area.addWidget(ProcessMonitorWidget(self.session))
        self.content_area.addWidget(NetworkMonitorWidget(self.session))
        self.content_area.addWidget(MemoryMonitorWidget(self.session))
        self.content_area.addWidget(PhishingDetectorWidget(self.session))
        self.content_area.addWidget(NIDSWidget(self.session))
        self.content_area.addWidget(FirewallWidget(self.session))
        self.content_area.addWidget(AntivirusWidget(self.session))
        self.content_area.addWidget(CloudSecurityWidget(self.session))

        # Set default selection
        self.switch_tab(0)

    def switch_tab(self, index):
        """Switches the stacked widget and updates button styles."""
        for i, btn in enumerate(self.nav_buttons):
            btn.setChecked(i == index)
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
        layout = QVBoxLayout()
        label = QLabel(f"{text} Module\n(Under Construction)")
        label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        label.setObjectName("PlaceholderLabel")
        layout.addWidget(label)
        widget.setLayout(layout)
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