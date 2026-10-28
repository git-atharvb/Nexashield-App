import sys
import os
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QFrame, QPushButton, QStackedWidget
)
from PyQt6.QtCore import Qt

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from subtabs.overview import OverviewWidget
from subtabs.files import FilesWidget
from subtabs.settings import SettingsWidget
from subtabs.about import AboutWidget
from subtabs.help import HelpWidget
from subtabs.contact import ContactWidget
from subtabs.ai_chat import AiChatWidget

class SIEMDashboard(QWidget):
    def __init__(self, session_manager=None):
        super().__init__()
        self.session = session_manager
        self.setup_ui()

    def setup_ui(self):
        # Main Layout (Horizontal: Sidebar + Content)
        main_layout = QHBoxLayout(self)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        # --- Left Sidebar ---
        self.sidebar = QFrame()
        self.sidebar.setObjectName("SIEMSidebar")
        self.sidebar.setFixedWidth(200)
        
        sidebar_layout = QVBoxLayout(self.sidebar)
        sidebar_layout.setContentsMargins(0, 20, 0, 20)
        sidebar_layout.setSpacing(5)

        # Sidebar Title
        title_lbl = QLabel("SIEM Controls")
        title_lbl.setObjectName("SidebarTitle")
        sidebar_layout.addWidget(title_lbl)

        # Menu Buttons
        self.menu_buttons = []
        menus = [
            ("📊 Overview", 0),
            ("📂 Files", 1),
            ("⚙️ Settings", 2),
            ("ℹ️ About", 3),
            ("❓ Help", 4),
            ("📞 Contact", 5),
            ("🤖 AI Assistant", 6)
        ]

        for text, idx in menus:
            btn = QPushButton(text)
            btn.setCheckable(True)
            btn.setCursor(Qt.CursorShape.PointingHandCursor)
            btn.clicked.connect(lambda checked, i=idx: self.switch_view(i))
            sidebar_layout.addWidget(btn)
            self.menu_buttons.append(btn)

        sidebar_layout.addStretch()
        
        # --- Right Content Area ---
        self.content_area = QStackedWidget()
        
        # Add sub-modules
        self.overview_widget = OverviewWidget(self.session, siem_dashboard=self)
        self.files_widget = FilesWidget(self.session)
        self.settings_widget = SettingsWidget()
        self.about_widget = AboutWidget()
        self.help_widget = HelpWidget()
        self.contact_widget = ContactWidget()
        self.ai_chat_widget = AiChatWidget(self.session)

        self.content_area.addWidget(self.overview_widget)
        self.content_area.addWidget(self.files_widget)
        self.content_area.addWidget(self.settings_widget)
        self.content_area.addWidget(self.about_widget)
        self.content_area.addWidget(self.help_widget)
        self.content_area.addWidget(self.contact_widget)
        self.content_area.addWidget(self.ai_chat_widget)

        # Add to main layout
        main_layout.addWidget(self.sidebar)
        main_layout.addWidget(self.content_area)

        # Select first tab
        self.switch_view(0)

    def switch_view(self, index):
        self.content_area.setCurrentIndex(index)
        for i, btn in enumerate(self.menu_buttons):
            btn.setChecked(i == index)
        # If switching to Files subtab, trigger a fresh reload of files table
        if index == 1 and hasattr(self, 'files_widget') and self.files_widget:
            try:
                self.files_widget.load_files()
            except Exception:
                pass
