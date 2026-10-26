import requests
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, 
    QTextEdit, QPushButton, QFrame, QMessageBox
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal

class FormspreeWorker(QThread):
    """Background worker to send HTTP POST requests without freezing the UI."""
    result_signal = pyqtSignal(bool, str)

    def __init__(self, endpoint, data):
        super().__init__()
        self.endpoint = endpoint
        self.data = data

    def run(self):
        try:
            # Formspree cleanly accepts JSON payloads
            response = requests.post(self.endpoint, json=self.data)
            if response.status_code in (200, 201):
                self.result_signal.emit(True, "Thank you! Your message has been sent successfully.")
            else:
                self.result_signal.emit(False, f"Failed to send message. Server returned status code: {response.status_code}")
        except Exception as e:
            self.result_signal.emit(False, f"Connection Error: {str(e)}")

class ContactWidget(QWidget):
    def __init__(self):
        super().__init__()
        # IMPORTANT: Replace the below string with your actual Formspree endpoint URL
        self.formspree_endpoint = "https://formspree.io/f/mkoqyydk"
        self.setup_ui()

    def setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(50, 40, 50, 40)
        layout.setSpacing(20)

        # --- Header ---
        header = QLabel("📞 Contact Support")
        header.setStyleSheet("font-size: 28px; font-weight: 900; color: #0078d7; letter-spacing: 1px;")
        layout.addWidget(header)

        desc = QLabel(
            "Need help, have a question, or want to report a bug? "
            "Fill out the form below and our team will get back to you as soon as possible."
        )
        desc.setWordWrap(True)
        desc.setStyleSheet("font-size: 15px; line-height: 1.5; background: transparent; margin-bottom: 15px;")
        layout.addWidget(desc)

        # --- Form Container ---
        form_card = QFrame()
        form_card.setObjectName("CardContainer")
        form_card.setStyleSheet("QFrame#CardContainer { border: 1px solid #88888850; border-radius: 12px; background: transparent; }")
        
        card_layout = QVBoxLayout(form_card)
        card_layout.setContentsMargins(40, 40, 40, 40)
        card_layout.setSpacing(20)

        # Fields
        self.name_input = QLineEdit()
        self.name_input.setPlaceholderText("e.g. Jane Doe")
        
        self.email_input = QLineEdit()
        self.email_input.setPlaceholderText("e.g. jane@example.com")
        
        self.subject_input = QLineEdit()
        self.subject_input.setPlaceholderText("What is this regarding?")
        
        self.message_input = QTextEdit()
        self.message_input.setPlaceholderText("Write your message here...")

        # Helper to quickly format styled form fields
        def create_field(label_text, widget):
            field_layout = QVBoxLayout()
            field_layout.setSpacing(8)
            
            lbl = QLabel(label_text)
            lbl.setStyleSheet("font-weight: bold; font-size: 14px; background: transparent; border: none;")
            field_layout.addWidget(lbl)
            
            if isinstance(widget, QLineEdit):
                widget.setMinimumHeight(42)
            elif isinstance(widget, QTextEdit):
                widget.setMinimumHeight(160)
                
            field_layout.addWidget(widget)
            return field_layout

        # Name and Email in one side-by-side row
        row_layout = QHBoxLayout()
        row_layout.setSpacing(20)
        row_layout.addLayout(create_field("Name", self.name_input))
        row_layout.addLayout(create_field("Email Address", self.email_input))
        
        card_layout.addLayout(row_layout)
        card_layout.addLayout(create_field("Subject", self.subject_input))
        card_layout.addLayout(create_field("Message", self.message_input))

        card_layout.addSpacing(10)

        # Submit Button
        self.submit_btn = QPushButton("📨 Send Message")
        self.submit_btn.setMinimumHeight(45)
        self.submit_btn.setFixedWidth(220)
        self.submit_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.submit_btn.setObjectName("PrimaryBtn")
        self.submit_btn.clicked.connect(self.submit_form)
        
        btn_layout = QHBoxLayout()
        btn_layout.addStretch()
        btn_layout.addWidget(self.submit_btn)
        
        card_layout.addLayout(btn_layout)

        layout.addWidget(form_card)
        layout.addStretch()

    def submit_form(self):
        name = self.name_input.text().strip()
        email = self.email_input.text().strip()
        subject = self.subject_input.text().strip()
        message = self.message_input.toPlainText().strip()

        if not all([name, email, subject, message]):
            QMessageBox.warning(self, "Validation Error", "Please fill out all fields before sending.")
            return

        if "YOUR_FORM_ID_HERE" in self.formspree_endpoint:
            QMessageBox.warning(
                self, 
                "Configuration Required", 
                "Formspree endpoint is not configured.\n\n"
                "Please replace 'YOUR_FORM_ID_HERE' with your actual Formspree ID in contact.py."
            )
            return

        self.submit_btn.setEnabled(False)
        self.submit_btn.setText("⏳ Sending...")

        data = {
            "name": name,
            "email": email,
            "subject": subject,
            "message": message
        }

        # Kick off background API call
        self.worker = FormspreeWorker(self.formspree_endpoint, data)
        self.worker.result_signal.connect(self.handle_response)
        self.worker.start()

    def handle_response(self, success, message):
        self.submit_btn.setEnabled(True)
        self.submit_btn.setText("📨 Send Message")

        if success:
            QMessageBox.information(self, "Success", message)
            self.name_input.clear()
            self.email_input.clear()
            self.subject_input.clear()
            self.message_input.clear()
        else:
            QMessageBox.critical(self, "Error", message)