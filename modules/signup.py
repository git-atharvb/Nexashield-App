from PyQt6.QtWidgets import QLabel, QLineEdit, QPushButton, QMessageBox, QProgressBar
from PyQt6.QtCore import Qt, pyqtSignal, QRegularExpression
from PyQt6.QtGui import QRegularExpressionValidator
from ui_components import AuthStyle, PasswordInput, GlowingLogo

class SignupWindow(AuthStyle):
    switch_to_login = pyqtSignal()
    signup_success = pyqtSignal(str, str, str)

    def __init__(self, db):
        super().__init__()
        self.db = db
        self.is_password_strong = False

        # --- Logo Section ---
        self.frame_layout.addSpacing(-30) 
        self.logo = GlowingLogo() 
        self.frame_layout.addWidget(self.logo, alignment=Qt.AlignmentFlag.AlignCenter)
        self.frame_layout.addSpacing(20)

        title = QLabel("Create Account")
        title.setObjectName("SignupTitle")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.frame_layout.addWidget(title)

        subtitle = QLabel("Initialize your next-generation security profile")
        subtitle.setObjectName("AuthSubtitle")
        subtitle.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.frame_layout.addWidget(subtitle)
        
        self.frame_layout.addSpacing(10)

        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText("Choose Username")
        self.frame_layout.addWidget(self.username_input)

        self.phone_input = QLineEdit()
        self.phone_input.setPlaceholderText("Phone Number")
        # Input Validation: Allow only digits
        rx = QRegularExpression("^[0-9]*$")
        self.phone_input.setValidator(QRegularExpressionValidator(rx))
        self.frame_layout.addWidget(self.phone_input)

        self.address_input = QLineEdit()
        self.address_input.setPlaceholderText("Address")
        self.frame_layout.addWidget(self.address_input)

        # Replaced standard QLineEdit with custom PasswordInput
        self.password_input = PasswordInput("Choose Password")
        # Connect text change signal to strength checker
        self.password_input.line_edit.textChanged.connect(self.check_password_strength)
        self.frame_layout.addWidget(self.password_input)

        # Password Strength Meter
        self.strength_bar = QProgressBar()
        self.strength_bar.setObjectName("StrengthBar")
        self.strength_bar.setFixedHeight(5)
        self.strength_bar.setTextVisible(False)
        self.frame_layout.addWidget(self.strength_bar)

        self.strength_label = QLabel("Password Strength: None")
        self.strength_label.setObjectName("StrengthLabel")
        self.frame_layout.addWidget(self.strength_label)

        self.signup_btn = QPushButton("Sign Up")
        self.signup_btn.setObjectName("AuthGreenButton")
        self.signup_btn.clicked.connect(self.handle_signup)
        self.frame_layout.addWidget(self.signup_btn)

        self.login_link = QPushButton("Back to Login")
        self.login_link.setObjectName("LinkButton")
        self.login_link.clicked.connect(self.switch_to_login.emit)
        self.frame_layout.addWidget(self.login_link)

    def check_password_strength(self):
        password = self.password_input.text()
        score = 0
        
        # Criteria
        if len(password) >= 8: score += 1
        if any(c.isdigit() for c in password): score += 1
        if any(c.isupper() for c in password): score += 1
        if any(not c.isalnum() for c in password): score += 1 # Special char

        # Update UI based on score
        self.strength_bar.setValue(score * 25)

        if score < 2:
            self.strength_bar.setStyleSheet("QProgressBar::chunk { background-color: #ff4757; }")
            self.strength_label.setText("Weak (Need 8+ chars, numbers, symbols)")
            self.strength_label.setStyleSheet("color: #ff4757;")
            self.is_password_strong = False
        elif score < 4:
            self.strength_bar.setStyleSheet("QProgressBar::chunk { background-color: #ffa502; }")
            self.strength_label.setText("Medium (Add special chars & uppercase)")
            self.strength_label.setStyleSheet("color: #ffa502;")
            self.is_password_strong = False
        else:
            self.strength_bar.setStyleSheet("QProgressBar::chunk { background-color: #2ed573; }")
            self.strength_label.setText("Strong")
            self.strength_label.setStyleSheet("color: #2ed573;")
            self.is_password_strong = True

    def handle_signup(self):
        username = self.username_input.text()
        password = self.password_input.text()
        phone = self.phone_input.text()
        address = self.address_input.text()

        if not all([username, password, phone, address]):
            QMessageBox.warning(self, "Error", "Fields cannot be empty")
            return

        if not self.is_password_strong:
            QMessageBox.warning(self, "Weak Password", "Please ensure your password meets all security requirements.")
            return

        if self.db.register_user(username, password, phone, address):
            QMessageBox.information(self, "Success", "Account created! Logging you in...")
            self.signup_success.emit(username, "local", "")
        else:
            QMessageBox.warning(self, "Error", "Username already exists")