import os
import sys
import json
import requests
import re
import html
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QTextBrowser, QLineEdit, 
    QPushButton, QLabel, QMessageBox, QFrame, QListWidget, QListWidgetItem, QSplitter
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer
from PyQt6.QtGui import QFont, QColor

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from database import DatabaseManager

def parse_markdown(text):
    """A lightweight markdown to HTML converter for PyQt's rich text engine."""
    # First escape HTML to prevent injection and rendering bugs
    parsed = html.escape(text)
    
    # Handle Code Blocks
    parsed = re.sub(r'```(?:.*?)\n(.*?)```', r'<pre style="background-color: #0d1117; padding: 10px; border: 1px solid #30363d; border-radius: 6px; font-family: Consolas, monospace; font-size: 13px;">\1</pre>', parsed, flags=re.DOTALL)
    
    # Handle Inline Code
    parsed = re.sub(r'`(.*?)`', r'<code style="background-color: #2b323b; padding: 2px 5px; border-radius: 4px; font-family: Consolas, monospace;">\1</code>', parsed)
    
    # Handle Bold
    parsed = re.sub(r'\*\*(.*?)\*\*', r'<b>\1</b>', parsed)
    
    # Handle Headers
    parsed = re.sub(r'^### (.*?)$', r'<h3 style="color: #00FFCC; margin-top: 10px;">\1</h3>', parsed, flags=re.MULTILINE)
    parsed = re.sub(r'^## (.*?)$', r'<h2 style="color: #00FFCC; margin-top: 10px;">\1</h2>', parsed, flags=re.MULTILINE)
    parsed = re.sub(r'^# (.*?)$', r'<h1 style="color: #00FFCC; margin-top: 10px;">\1</h1>', parsed, flags=re.MULTILINE)
    
    # Handle Lists
    parsed = re.sub(r'^(\*|-) (.*?)$', r'<li>\2</li>', parsed, flags=re.MULTILINE)
    
    # Replace standard newlines with HTML breaks
    parsed = parsed.replace('\n', '<br>')
    return parsed


class AIChatWorker(QThread):
    chunk_received = pyqtSignal(str)
    response_finished = pyqtSignal()
    error_occurred = pyqtSignal(str)

    def __init__(self, api_key, model, messages):
        super().__init__()
        self.api_key = api_key
        self.model = model
        self.messages = messages

    def run(self):
        try:
            url = "https://openrouter.ai/api/v1/chat/completions"
            headers = {
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
                "HTTP-Referer": "https://github.com/nexashield", 
                "X-Title": "NexaShield SIEM"
            }
            payload = {
                "model": self.model,
                "messages": self.messages,
                "temperature": 0.7,
                "stream": True
            }
            
            response = requests.post(url, headers=headers, json=payload, stream=True, timeout=10)
            
            if response.status_code == 200:
                for line in response.iter_lines():
                    if line:
                        decoded_line = line.decode('utf-8')
                        if decoded_line.startswith("data: "):
                            data_str = decoded_line[6:]
                            if data_str == "[DONE]":
                                break
                            try:
                                data = json.loads(data_str)
                                if 'choices' in data and len(data['choices']) > 0:
                                    delta = data['choices'][0].get('delta', {})
                                    if 'content' in delta:
                                        self.chunk_received.emit(delta['content'])
                            except json.JSONDecodeError:
                                pass
                self.response_finished.emit()
            else:
                try:
                    error_data = response.json()
                    self.error_occurred.emit(f"Error {response.status_code}: {error_data.get('error', {}).get('message', 'Unknown')}")
                except:
                    self.error_occurred.emit(f"API Error {response.status_code}: {response.text}")

        except Exception as e:
            self.error_occurred.emit(str(e))


class AiChatWidget(QWidget):
    def __init__(self, session_manager=None):
        super().__init__()
        self.session = session_manager
        self.db = DatabaseManager()
        
        self.system_prompt = {
            "role": "system",
            "content": (
                "You are Nexa, a highly advanced Cybersecurity AI Assistant integrated directly into "
                "the NexaShield SIEM platform. Your role is to assist the user (a security analyst) in "
                "understanding threats, analyzing logs, recommending firewall rules, and identifying "
                "malware anomalies. Be highly technical, concise, and professional."
            )
        }
        
        self.current_model = "google/gemma-4-26b-a4b-it:free"
        self.current_session_id = None
        self.chat_history = []
        self.ai_response_buffer = ""
        
        self.setup_env()
        self.setup_ui()
        self.load_sessions_list()
        self.start_new_chat()
        self.check_api_key()

    def setup_env(self):
        env_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', '.env'))
        if os.path.exists(env_path):
            with open(env_path, 'r') as f:
                for line in f:
                    if line.strip() and not line.startswith('#') and '=' in line:
                        key, val = line.strip().split('=', 1)
                        os.environ[key.strip()] = val.strip()

    def setup_ui(self):
        main_layout = QHBoxLayout(self)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)
        
        splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # ================= LEFT SIDEBAR (History) =================
        sidebar = QFrame()
        sidebar.setObjectName("ChatSidebar")
        sidebar.setFixedWidth(240)
        sidebar.setStyleSheet("QFrame#ChatSidebar { background-color: #1a1e24; border-right: 1px solid #2b323b; }")
        
        sidebar_layout = QVBoxLayout(sidebar)
        sidebar_layout.setContentsMargins(15, 20, 15, 20)
        sidebar_layout.setSpacing(10)
        
        new_chat_btn = QPushButton("➕ New Chat")
        new_chat_btn.setObjectName("PrimaryBtn")
        new_chat_btn.clicked.connect(self.start_new_chat)
        sidebar_layout.addWidget(new_chat_btn)
        
        history_lbl = QLabel("Recent Chats")
        history_lbl.setStyleSheet("color: #8b949e; font-size: 12px; font-weight: bold; margin-top: 15px;")
        sidebar_layout.addWidget(history_lbl)
        
        self.session_list = QListWidget()
        self.session_list.setObjectName("ChatList")
        self.session_list.setStyleSheet("""
            QListWidget { background: transparent; border: none; outline: none; }
            QListWidget::item { color: #c9d1d9; padding: 10px; border-radius: 5px; margin-bottom: 2px; }
            QListWidget::item:selected { background-color: #2b323b; color: #00FFCC; font-weight: bold; }
            QListWidget::item:hover:!selected { background-color: #21262d; }
        """)
        self.session_list.itemClicked.connect(self.load_selected_session)
        sidebar_layout.addWidget(self.session_list)
        
        delete_chat_btn = QPushButton("🗑️ Delete Chat")
        delete_chat_btn.setStyleSheet("QPushButton { background-color: #da3633; color: white; padding: 8px; border-radius: 4px; font-weight: bold; } QPushButton:hover { background-color: #f85149; }")
        delete_chat_btn.clicked.connect(self.delete_current_session)
        sidebar_layout.addWidget(delete_chat_btn)
        
        splitter.addWidget(sidebar)
        
        # ================= RIGHT MAIN AREA (Chat) =================
        main_area = QWidget()
        main_area_layout = QVBoxLayout(main_area)
        main_area_layout.setContentsMargins(20, 20, 20, 20)
        main_area_layout.setSpacing(15)

        # Header
        header_layout = QHBoxLayout()
        title_lbl = QLabel("🤖 Nexa AI Assistant")
        title_lbl.setStyleSheet("font-size: 20px; font-weight: bold; color: white;")
        
        self.model_lbl = QLabel(f"Model: {self.current_model.split('/')[1]}")
        self.model_lbl.setStyleSheet("color: #00FFCC; font-size: 12px; font-weight: bold; background: #161b22; padding: 5px 10px; border-radius: 10px; border: 1px solid #30363d;")
        
        header_layout.addWidget(title_lbl)
        header_layout.addStretch()
        header_layout.addWidget(self.model_lbl)
        main_area_layout.addLayout(header_layout)

        # Chat Display
        self.chat_display = QTextBrowser()
        self.chat_display.setOpenExternalLinks(True)
        self.chat_display.setStyleSheet("""
            QTextBrowser {
                background-color: transparent;
                border: none;
                font-size: 14px;
                color: #e6edf3;
            }
        """)
        main_area_layout.addWidget(self.chat_display)
        
        # Loading Indicator
        self.loading_lbl = QLabel("🤖 Nexa is analyzing your request...")
        self.loading_lbl.setStyleSheet("color: #00FFCC; font-style: italic; font-size: 12px;")
        self.loading_lbl.hide()
        main_area_layout.addWidget(self.loading_lbl)

        # Input Area
        input_layout = QHBoxLayout()
        self.input_field = QLineEdit()
        self.input_field.setPlaceholderText("Ask Nexa about logs, firewall rules, or threat analysis...")
        self.input_field.setStyleSheet("QLineEdit { background: #0d1117; border: 1px solid #30363d; border-radius: 6px; padding: 12px; font-size: 14px; color: white; } QLineEdit:focus { border: 1px solid #00FFCC; }")
        self.input_field.returnPressed.connect(self.send_message)
        
        self.send_btn = QPushButton("Send")
        self.send_btn.setObjectName("PrimaryBtn")
        self.send_btn.setFixedWidth(100)
        self.send_btn.setMinimumHeight(42)
        self.send_btn.clicked.connect(self.send_message)
        
        input_layout.addWidget(self.input_field)
        input_layout.addWidget(self.send_btn)
        
        main_area_layout.addLayout(input_layout)
        
        splitter.addWidget(main_area)
        splitter.setSizes([240, 800])
        main_layout.addWidget(splitter)

    def load_sessions_list(self):
        self.session_list.clear()
        sessions = self.db.get_chat_sessions()
        for s_id, title, _ in sessions:
            item = QListWidgetItem(title)
            item.setData(Qt.ItemDataRole.UserRole, s_id)
            self.session_list.addItem(item)

    def start_new_chat(self):
        self.current_session_id = self.db.create_chat_session("New Chat")
        self.chat_history = [self.system_prompt]
        self.chat_display.clear()
        self.load_sessions_list()
        
        # Select the newly created chat
        for i in range(self.session_list.count()):
            if self.session_list.item(i).data(Qt.ItemDataRole.UserRole) == self.current_session_id:
                self.session_list.setCurrentRow(i)
                break
                
        self.append_ui_bubble("Nexa", "Hello! I am Nexa, your SIEM assistant. How can I help you analyze your security posture today?", False)

    def load_selected_session(self, item):
        session_id = item.data(Qt.ItemDataRole.UserRole)
        self.current_session_id = session_id
        
        messages = self.db.get_chat_messages(session_id)
        self.chat_history = [self.system_prompt]
        self.chat_display.clear()
        
        if not messages:
            self.append_ui_bubble("Nexa", "Hello! I am Nexa, your SIEM assistant. How can I help you analyze your security posture today?", False)
            return

        for role, content in messages:
            self.chat_history.append({"role": role, "content": content})
            if role == "user":
                self.append_ui_bubble("You", content, True)
            elif role == "assistant":
                self.append_ui_bubble("Nexa", content, False)
        
        # Scroll to bottom
        self.scroll_to_bottom()

    def delete_current_session(self):
        if not self.current_session_id:
            return
            
        reply = QMessageBox.question(self, 'Delete Chat', 'Are you sure you want to delete this chat?',
                                     QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No, QMessageBox.StandardButton.No)
        if reply == QMessageBox.StandardButton.Yes:
            self.db.delete_chat_session(self.current_session_id)
            self.start_new_chat()

    def append_ui_bubble(self, sender, text, is_user):
        """Builds a beautiful HTML bubble for the chat display."""
        parsed_text = parse_markdown(text) if not is_user else html.escape(text)
        
        if is_user:
            html_bubble = f"""
            <div style="margin: 10px 0px 10px 20%; padding: 12px 16px; background-color: #1f252e; border-radius: 8px; border: 1px solid #30363d;">
                <span style="color: #8b949e; font-size: 11px; font-weight: bold; text-transform: uppercase;">{sender}</span><br/>
                <span style="color: white; font-size: 14px;">{parsed_text}</span>
            </div>
            """
        else:
            html_bubble = f"""
            <div style="margin: 10px 20% 10px 0px; padding: 12px 16px; background-color: transparent; border-left: 3px solid #00FFCC;">
                <span style="color: #00FFCC; font-size: 11px; font-weight: bold; text-transform: uppercase;">{sender}</span><br/>
                <span style="color: #e6edf3; font-size: 14px;">{parsed_text}</span>
            </div>
            """
        self.chat_display.append(html_bubble)
        self.scroll_to_bottom()

    def scroll_to_bottom(self):
        scrollbar = self.chat_display.verticalScrollBar()
        scrollbar.setValue(scrollbar.maximum())

    def check_api_key(self):
        key = os.getenv("OPENROUTER_API_KEY")
        if not key or key == "your_api_key_here":
            self.append_ui_bubble("System", "⚠️ No OpenRouter API key found. Please add your key to the `.env` file at the root of the project.", False)
            self.input_field.setDisabled(True)
            self.send_btn.setDisabled(True)

    def send_message(self):
        text = self.input_field.text().strip()
        if not text:
            return
            
        api_key = os.getenv("OPENROUTER_API_KEY")
        if not api_key or api_key == "your_api_key_here":
            self.check_api_key()
            return
            
        # Update Chat Title if it's the first message
        if len(self.chat_history) == 1:
            title = text[:30] + "..." if len(text) > 30 else text
            self.db.update_chat_title(self.current_session_id, title)
            self.load_sessions_list()
            # Reselect current row
            for i in range(self.session_list.count()):
                if self.session_list.item(i).data(Qt.ItemDataRole.UserRole) == self.current_session_id:
                    self.session_list.setCurrentRow(i)
                    break

        self.append_ui_bubble("You", text, True)
        self.input_field.clear()
        
        self.db.add_chat_message(self.current_session_id, "user", text)
        self.chat_history.append({"role": "user", "content": text})
        
        self.input_field.setDisabled(True)
        self.send_btn.setDisabled(True)
        self.send_btn.setText("Thinking...")
        self.loading_lbl.show()
        
        # Prepare for streaming
        self.ai_response_buffer = ""
        # Create an empty bubble for the AI that we will update live
        self.chat_display.append(f"""
            <div id="streaming_bubble" style="margin: 10px 20% 10px 0px; padding: 12px 16px; background-color: transparent; border-left: 3px solid #00FFCC;">
                <span style="color: #00FFCC; font-size: 11px; font-weight: bold; text-transform: uppercase;">Nexa</span><br/>
                <span id="streaming_text" style="color: #e6edf3; font-size: 14px;"></span>
            </div>
        """)
        self.scroll_to_bottom()
        
        # Create a text cursor attached to the end for live updates
        self.live_cursor = self.chat_display.textCursor()
        
        self.worker = AIChatWorker(api_key, self.current_model, self.chat_history)
        self.worker.chunk_received.connect(self.handle_chunk)
        self.worker.response_finished.connect(self.handle_finished)
        self.worker.error_occurred.connect(self.handle_error)
        self.worker.start()

    def handle_chunk(self, chunk):
        self.loading_lbl.hide()
        self.ai_response_buffer += chunk
        
        # In PyQt, updating a specific HTML block live is tricky. 
        # A performant trick is to simply insert HTML at the cursor.
        # However, to support Markdown parsing live, we rebuild the entire document or just append raw text temporarily.
        # The simplest robust way for streaming in QTextBrowser is to replace the last block completely or just insert text.
        
        # For true professional Markdown, we parse the buffer and replace the entire HTML.
        # But for performance, we'll just insert the raw text chunks and parse it all at the end.
        self.live_cursor.movePosition(self.live_cursor.MoveOperation.End)
        self.live_cursor.insertText(chunk)
        self.scroll_to_bottom()

    def handle_finished(self):
        # Once finished, we redraw the entire chat to apply Markdown parsing
        # (This cleans up the raw text inserted during streaming)
        text = self.ai_response_buffer
        self.db.add_chat_message(self.current_session_id, "assistant", text)
        self.chat_history.append({"role": "assistant", "content": text})
        
        # Reload the session UI to beautifully render the Markdown HTML
        self.load_selected_session(self.session_list.currentItem())
        
        self.unlock_ui()

    def handle_error(self, error_msg):
        self.append_ui_bubble("System Error", f"❌ API Request Failed: {error_msg}", False)
        if self.chat_history[-1]['role'] == 'user':
            self.chat_history.pop()
        self.unlock_ui()

    def unlock_ui(self):
        self.loading_lbl.hide()
        self.input_field.setDisabled(False)
        self.send_btn.setDisabled(False)
        self.send_btn.setText("Send")
        self.input_field.setFocus()
