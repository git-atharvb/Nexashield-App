import json
import os
from PyQt6.QtWidgets import (
    QLabel, QLineEdit, QPushButton, QMessageBox, QWidget, QDialog, QVBoxLayout, QHBoxLayout,
    QFrame, QGraphicsDropShadowEffect, QStackedWidget
)
from PyQt6.QtGui import QPainter, QPainterPath, QColor, QLinearGradient, QPen, QPixmap, QIcon
from PyQt6.QtCore import Qt, pyqtSignal, QTimer, QPropertyAnimation, QEasingCurve
from ui_components import AuthStyle, PasswordInput, GlowingLogo
from google_auth import GoogleAuthWorker

class LoginSuccessDialog(QDialog):
    """A custom, modern dialog for successful login."""
    def __init__(self, parent=None, username="User"):
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
        icon = QLabel("🔓")
        icon.setAlignment(Qt.AlignmentFlag.AlignCenter)
        icon.setObjectName("SuccessIcon")
        
        # Text
        lbl_title = QLabel("Login Successful")
        lbl_title.setObjectName("SuccessTitle")
        lbl_title.setAlignment(Qt.AlignmentFlag.AlignCenter)

        lbl_msg = QLabel(f"Welcome back,\n{username}")
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

        # Sequence
        self.fade_in.start()
        QTimer.singleShot(1500, self.fade_out.start)

class LoadingSpinner(QWidget):
    """A simple rotating spinner widget."""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedSize(40, 40)

        self.angle = 0
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.rotate)

    def rotate(self):
        self.angle = (self.angle + 45) % 360
        self.update()

    def showEvent(self, event):
        self.timer.start(80)
        super().showEvent(event)

    def hideEvent(self, event):
        self.timer.stop()
        super().hideEvent(event)

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.translate(self.width() / 2, self.height() / 2)
        painter.rotate(self.angle)
        
        pen = QPen(QColor("#0078d7"), 3)
        pen.setCapStyle(Qt.PenCapStyle.RoundCap)
        painter.setPen(pen)
        painter.drawArc(-12, -12, 24, 24, 0, 270 * 16)

class LoginWindow(AuthStyle):
    switch_to_signup = pyqtSignal()
    switch_to_forgot = pyqtSignal()
    login_success = pyqtSignal(str, str, str) # username, auth_type, auth_token

    def __init__(self, db):
        super().__init__()
        self.db = db

        # --- Logo Section ---
        self.logo = GlowingLogo()
        self.frame_layout.addWidget(self.logo, alignment=Qt.AlignmentFlag.AlignCenter)

        title = QLabel("NexaShield Login")
        title.setObjectName("LoginTitle")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.frame_layout.addWidget(title)

        subtitle = QLabel("Advanced Cybersecurity Defense System")
        subtitle.setObjectName("AuthSubtitle")
        subtitle.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.frame_layout.addWidget(subtitle)
        
        # Add some spacing before inputs
        self.frame_layout.addSpacing(10)

        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText("Username")
        self.frame_layout.addWidget(self.username_input)

        # Replaced standard QLineEdit with custom PasswordInput
        self.password_input = PasswordInput("Password")
        self.frame_layout.addWidget(self.password_input)

        self.login_btn = QPushButton("Login")
        self.login_btn.setObjectName("AuthPrimaryButton")
        self.login_btn.clicked.connect(self.handle_login)
        self.frame_layout.addWidget(self.login_btn)

        self.forgot_link = QPushButton("Forgot Password?")
        self.forgot_link.setObjectName("LinkButton")
        self.forgot_link.clicked.connect(self.switch_to_forgot.emit)
        self.frame_layout.addWidget(self.forgot_link)

        self.google_btn = QPushButton(" Sign in with Google")
        self.google_btn.setObjectName("GoogleButton")
        google_icon_path = os.path.join(os.path.dirname(__file__), "..", "assets", "google.png")
        self.google_btn.setIcon(QIcon(google_icon_path))
        self.google_btn.clicked.connect(self.handle_google_login)
        self.frame_layout.addWidget(self.google_btn)

        self.signup_link = QPushButton("Create an Account")
        self.signup_link.setObjectName("LinkButton")
        self.signup_link.clicked.connect(self.switch_to_signup.emit)
        self.frame_layout.addWidget(self.signup_link)

    def handle_login(self):
        self.login_btn.setText("Logging in...")
        self.login_btn.setEnabled(False)
        
        # Simulate processing delay for animation
        QTimer.singleShot(1500, self.perform_login)

    def perform_login(self):
        username = self.username_input.text()
        password = self.password_input.text()

        self.login_btn.setText("Login")
        self.login_btn.setEnabled(True)

        if self.db.verify_user(username, password):
            dlg = LoginSuccessDialog(self, username)
            dlg.exec()
            self.login_success.emit(username, "local", "")
        else:
            QMessageBox.warning(self, "Error", "Invalid username or password")

    def handle_google_login(self):
        # Load credentials from client_secret.json
        client_id = None
        client_secret = None
        
        # --- CONFIGURATION: Optional manual override path ---
        # Leave as None to auto-detect client_secret.json next to the app / project root.
        manual_path = None
        # ---------------------------------------------------------

        # Look for the file in the same directory as this script or one level up
        current_dir = os.path.dirname(os.path.abspath(__file__))
        project_root = os.path.dirname(current_dir)
        possible_paths = [
            manual_path,
            os.path.join(current_dir, "client_secret.json"),
            os.path.join(project_root, "client_secret.json"),
            os.path.join(project_root, "assets", "client_secret.json")
        ]

        for path in possible_paths:
            if not path:
                continue
            if os.path.exists(path):
                try:
                    with open(path, 'r') as f:
                        data = json.load(f)
                        # Check for 'installed' (desktop) or 'web' keys
                        creds = data.get('installed') or data.get('web')
                        if creds:
                            client_id = creds.get('client_id')
                            client_secret = creds.get('client_secret')
                            break
                except Exception as e:
                    QMessageBox.warning(self, "Error", f"Failed to parse client_secret.json: {e}")
                    return

        if not client_id or not client_secret:
            QMessageBox.critical(self, "Config Error", "client_secret.json not found or invalid.\nPlease place it in the project root.")
            return

        self.google_worker = GoogleAuthWorker(client_id, client_secret)
        self.google_worker.auth_success.connect(self.on_google_success)
        self.google_worker.auth_error.connect(self.on_google_error)
        
        self.login_btn.setEnabled(False)
        self.google_btn.setText("Waiting for browser...")
        self.google_worker.start()

    def on_google_success(self, user_info):
        email = user_info.get('email', 'Google User')
        access_token = user_info.get('access_token', '')
        # Here you could register the user in your DB if they don't exist
        dlg = LoginSuccessDialog(self, email)
        dlg.exec()
        self.login_success.emit(email, "google", access_token)
        self.login_btn.setEnabled(True)
        self.google_btn.setText(" Sign in with Google")

    def on_google_error(self, error_msg):
        QMessageBox.critical(self, "Google Login Error", error_msg)
        self.login_btn.setEnabled(True)
        self.google_btn.setText(" Sign in with Google")

    def clear_inputs(self):
        self.username_input.clear()
        self.password_input.line_edit.clear()