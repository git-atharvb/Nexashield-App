import random
from PyQt6.QtWidgets import QLabel, QLineEdit, QPushButton, QMessageBox
from PyQt6.QtCore import Qt, pyqtSignal
from ui_components import AuthStyle, PasswordInput, GlowingLogo

class ForgotPasswordWindow(AuthStyle):
    switch_to_login = pyqtSignal()

    def __init__(self, db):
        super().__init__()
        self.db = db
        self.generated_otp = None
        self.current_username = None

        # --- Logo Section ---
        self.logo = GlowingLogo()
        self.frame_layout.addWidget(self.logo, alignment=Qt.AlignmentFlag.AlignCenter)

        title = QLabel("Reset Password")
        title.setObjectName("LoginTitle") # Reuse login title style
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.frame_layout.addWidget(title)

        subtitle = QLabel("Verify your identity to restore access securely")
        subtitle.setObjectName("AuthSubtitle")
        subtitle.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.frame_layout.addWidget(subtitle)
        
        self.frame_layout.addSpacing(10)

        # --- STEP 1: Username Input ---
        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText("Enter Username")
        self.username_input.returnPressed.connect(self.handle_send_otp)
        self.frame_layout.addWidget(self.username_input)

        self.send_otp_btn = QPushButton("Send OTP")
        self.send_otp_btn.setObjectName("AuthOrangeButton")
        self.send_otp_btn.clicked.connect(self.handle_send_otp)
        self.frame_layout.addWidget(self.send_otp_btn)

        # --- STEP 2: OTP & New Password (Hidden initially) ---
        self.otp_input = QLineEdit()
        self.otp_input.setPlaceholderText("Enter 6-digit OTP")
        self.otp_input.returnPressed.connect(self.handle_reset_password)
        self.otp_input.hide()
        self.frame_layout.addWidget(self.otp_input)

        self.new_password_input = PasswordInput("New Password")
        self.new_password_input.line_edit.returnPressed.connect(self.handle_reset_password)
        self.new_password_input.hide()
        self.frame_layout.addWidget(self.new_password_input)

        self.reset_btn = QPushButton("Reset Password")
        self.reset_btn.setObjectName("AuthPrimaryButton")
        self.reset_btn.clicked.connect(self.handle_reset_password)
        self.reset_btn.hide()
        self.frame_layout.addWidget(self.reset_btn)

        # Back Button
        self.back_btn = QPushButton("Back to Login")
        self.back_btn.setObjectName("LinkButton")
        self.back_btn.clicked.connect(self.on_back_to_login)
        self.frame_layout.addWidget(self.back_btn)

    def on_back_to_login(self):
        self.reset_ui()
        self.switch_to_login.emit()

    def handle_send_otp(self):
        username = self.username_input.text().strip()
        if not username:
            QMessageBox.warning(self, "Error", "Please enter your username.")
            return

        phone = self.db.get_user_phone(username)
        if not phone:
            QMessageBox.warning(self, "Error", "User not found.")
            return

        # Generate 6-digit OTP
        self.generated_otp = str(random.randint(100000, 999999))
        self.current_username = username

        # Simulate SMS Gateway
        masked_phone = phone[:2] + "****" + phone[-2:] if len(phone) > 4 else "****"
        QMessageBox.information(self, "OTP Sent", 
                                f"OTP sent to registered phone ending in {masked_phone}.\n\n"
                                f"(SIMULATION: Your OTP is {self.generated_otp})")

        # Switch UI to Step 2
        self.username_input.hide()
        self.send_otp_btn.hide()
        
        self.otp_input.show()
        self.new_password_input.show()
        self.reset_btn.show()

    def handle_reset_password(self):
        otp = self.otp_input.text().strip()
        new_pw = self.new_password_input.text()

        if otp != self.generated_otp:
            QMessageBox.warning(self, "Error", "Invalid OTP. Please check the 6-digit code.")
            return
        
        if not new_pw or len(new_pw) < 8:
            QMessageBox.warning(self, "Error", "New password must be at least 8 characters.")
            return

        if self.db.update_password(self.current_username, new_pw):
            QMessageBox.information(self, "Success", "Password reset successfully! Please log in with your new password.")
            self.on_back_to_login()
        else:
            QMessageBox.critical(self, "Error", "Failed to update password.")

    def reset_ui(self):
        """Reset the form state for next use."""
        self.username_input.clear()
        self.username_input.show()
        self.send_otp_btn.show()
        self.otp_input.clear()
        self.otp_input.hide()
        self.new_password_input.line_edit.clear()
        self.new_password_input.hide()
        self.reset_btn.hide()
        self.generated_otp = None
        self.current_username = None