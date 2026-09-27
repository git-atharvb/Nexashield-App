import sys
import os
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QStackedWidget
)
from PyQt6.QtGui import QIcon, QPalette, QColor
from database import DatabaseManager
from login import LoginWindow
from signup import SignupWindow
from forgot_password import ForgotPasswordWindow
from home import HomeWindow
from session_manager import SessionManager

# MAIN APPLICATION CONTROLLER

class NexaShieldApp(QMainWindow):
    def __init__(self):
        super().__init__()
        
        self.is_dark_mode = True
        self.setWindowTitle("NexaShield Cybersecurity Suite")
        
        # Set Window Icon
        icon_path = os.path.join(os.path.dirname(__file__), "..", "assets", "nexa.png")
        self.setWindowIcon(QIcon(icon_path))

        self.setMinimumSize(500, 650) # Taller ratio to perfectly fit auth forms without scrollbars
        self.center()

        self.db = DatabaseManager()

        # Stacked Widget to manage screens
        self.stack = QStackedWidget()
        self.setCentralWidget(self.stack)

        # Initialize Screens
        self.login_screen = LoginWindow(self.db)
        self.signup_screen = SignupWindow(self.db)
        self.forgot_screen = ForgotPasswordWindow(self.db)
        
        # Home screen will be dynamically instantiated on login for isolated sessions
        self.home_screen = None

        # Add screens to stack
        self.stack.addWidget(self.login_screen)  # Index 0
        self.stack.addWidget(self.signup_screen) # Index 1
        self.stack.addWidget(self.forgot_screen) # Index 2

        # Connect Signals
        self.login_screen.switch_to_signup.connect(lambda: self.stack.setCurrentIndex(1))
        self.login_screen.switch_to_forgot.connect(lambda: self.stack.setCurrentIndex(2))
        self.login_screen.login_success.connect(self.show_home)
        
        self.signup_screen.switch_to_login.connect(lambda: self.stack.setCurrentIndex(0))
        self.signup_screen.signup_success.connect(self.show_home)

        self.forgot_screen.switch_to_login.connect(lambda: self.stack.setCurrentIndex(0))
        # Theme Toggles
        self.login_screen.theme_toggle.clicked.connect(self.toggle_theme)
        self.signup_screen.theme_toggle.clicked.connect(self.toggle_theme)
        self.forgot_screen.theme_toggle.clicked.connect(self.toggle_theme)

        self.apply_theme()

        # --- Normal Boot Flow Restored ---

    def center(self):
        w, h = 550, 650
        screen = QApplication.primaryScreen().availableGeometry()
        x = screen.x() + (screen.width() - w) // 2
        y = screen.y() + (screen.height() - h) // 2
        self.setGeometry(x, y, w, h)

    def show_home(self, username, auth_type="local", auth_token=""):
        # 1. Create the user's isolated workspace with auth context
        self.session_manager = SessionManager(username, auth_type, auth_token)
        
        # 2. Destroy the old home screen to wipe all data/threads from RAM
        if self.home_screen is not None:
            self.stack.removeWidget(self.home_screen)
            self.home_screen.deleteLater()
            
        # 3. Instantiate a fresh, isolated home screen
        self.home_screen = HomeWindow(self.session_manager)
        
        # 4. Reconnect dynamic signals
        self.home_screen.logout_requested.connect(self.handle_logout)
        self.home_screen.theme_toggle.clicked.connect(self.toggle_theme)
        self.home_screen.theme_toggle.setText("☀️" if self.is_dark_mode else "🌙")
        
        # 5. Add to stack and show
        self.stack.addWidget(self.home_screen) # Automatically appends at end
        
        self.setWindowTitle(f"NexaShield Cybersecurity Suite : Welcome {username}")
        self.stack.setCurrentWidget(self.home_screen)
        self.showMaximized()
        self.apply_theme()

    def handle_logout(self):
        self.setWindowTitle("NexaShield Cybersecurity Suite")
        self.login_screen.clear_inputs()
        self.stack.setCurrentIndex(0)
        self.showNormal()
        self.resize(550, 650)
        self.center()

    def toggle_theme(self):
        self.is_dark_mode = not self.is_dark_mode
        icon = "☀️" if self.is_dark_mode else "🌙"
        
        # Update icons on all screens
        self.login_screen.theme_toggle.setText(icon)
        self.signup_screen.theme_toggle.setText(icon)
        self.forgot_screen.theme_toggle.setText(icon)
        if self.home_screen:
            self.home_screen.theme_toggle.setText(icon)
        
        self.apply_theme()

    def apply_theme(self):
        """Centralized and robust dynamic theming engine using QPalette and global QSS."""
        palette = QPalette()
        
        if self.is_dark_mode:
            bg = "#1e1e1e"
            base = "#252526"
            text = "#ffffff"
            text_muted = "#aaaaaa"
            accent = "#0078d7"
            accent_hover = "#0063b1"
            border = "#3e3e42"
        else:
            bg = "#f3f3f3"
            base = "#ffffff"
            text = "#111111"
            text_muted = "#555555"
            accent = "#0078d7"
            accent_hover = "#005a9e"
            border = "#cccccc"

        # 1. Apply Global Palette (Fixes custom paintEvent charts automatically)
        palette.setColor(QPalette.ColorRole.Window, QColor(bg))
        palette.setColor(QPalette.ColorRole.WindowText, QColor(text))
        palette.setColor(QPalette.ColorRole.Base, QColor(base))
        palette.setColor(QPalette.ColorRole.AlternateBase, QColor(bg))
        palette.setColor(QPalette.ColorRole.Text, QColor(text))
        palette.setColor(QPalette.ColorRole.Button, QColor(base))
        palette.setColor(QPalette.ColorRole.ButtonText, QColor(text))
        palette.setColor(QPalette.ColorRole.Link, QColor(accent))
        palette.setColor(QPalette.ColorRole.Highlight, QColor(accent))
        palette.setColor(QPalette.ColorRole.HighlightedText, QColor("#ffffff"))
        QApplication.instance().setPalette(palette)

        # 2. Load Comprehensive QSS Files
        qss_file = "style.qss" if self.is_dark_mode else "style_light.qss"
        style_path = os.path.join(os.path.dirname(__file__), qss_file)
        
        if os.path.exists(style_path):
            with open(style_path, "r") as f:
                self.setStyleSheet(f.read())

if __name__ == "__main__":
    app = QApplication(sys.argv)
    
    # Enforce a strictly positive global point size before ANY widgets are created to silence Qt warnings
    default_font = app.font()
    default_font.setPointSize(10)
    app.setFont(default_font)
    
    window = NexaShieldApp()
    window.show()
    sys.exit(app.exec())