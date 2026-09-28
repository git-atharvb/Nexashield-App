import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
    QFrame, QScrollArea, QGridLayout, QSizePolicy,
    QPushButton
)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QFont
from ui_components import GlowingLogo

class AboutWidget(QWidget):
    def __init__(self):
        super().__init__()
        self.setup_ui()

    def setup_ui(self):
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(0, 0, 0, 0)
        
        # --- Scrollable Container ---
        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        scroll_area.setFrameShape(QFrame.Shape.NoFrame)
        scroll_area.setStyleSheet("background: transparent;")
        
        content_widget = QWidget()
        content_widget.setStyleSheet("background: transparent;")
        layout = QVBoxLayout(content_widget)
        layout.setContentsMargins(40, 40, 40, 40)
        layout.setSpacing(35)

        # --- 1. Header Card ---
        header_frame = QFrame()
        header_frame.setObjectName("CardContainer")
        header_layout = QVBoxLayout(header_frame)
        header_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        header_layout.setSpacing(10)
        
        # Replace Emoji with Actual Login Logo Image
        logo = GlowingLogo(size=90, radius=20)
        header_layout.addWidget(logo, alignment=Qt.AlignmentFlag.AlignCenter)
        
        title = QLabel("NexaShield")
        title.setStyleSheet("font-size: 36px; font-weight: 900; color: #0078d7; letter-spacing: 2px;")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        subtitle = QLabel("Advanced CyberSecurity Defense System")
        subtitle.setStyleSheet("font-size: 18px; font-weight: bold; background: transparent;")
        subtitle.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        version = QLabel("Version 1.0.0  |  Unified Threat Management (UTM) Suite")
        version.setStyleSheet("font-size: 13px; background: transparent;")
        version.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        header_layout.addWidget(title)
        header_layout.addWidget(subtitle)
        header_layout.addWidget(version)
        layout.addWidget(header_frame)

        # --- 2. Mission Statement ---
        mission_frame = QFrame()
        mission_frame.setObjectName("CardContainer")
        mission_layout = QVBoxLayout(mission_frame)
        mission_layout.setContentsMargins(30, 30, 30, 30)
        
        mission_title = QLabel("🚀 Our Mission")
        mission_title.setStyleSheet("font-size: 22px; font-weight: 900; color: #0078d7; background: transparent; padding-bottom: 10px;")
        
        mission_text = QLabel(
            "<div style='font-size: 15px; line-height: 1.8;'>"
            "<p>In an increasingly interconnected world, digital security is paramount. "
            "<b>NexaShield</b> addresses this critical need by offering an intelligent, adaptive desktop defense system. "
            "It integrates multiple threat detection mechanisms—ranging from Machine Learning-based phishing and malware detection "
            "to real-time network packet sniffing and active OS-level firewall prevention.</p>"
            "<p>Our goal is to empower users and organizations with a proactive, seamless, and unified threat management suite "
            "to defend against evolving cyber threats.</p></div>"
        )
        mission_text.setWordWrap(True)
        
        mission_layout.addWidget(mission_title)
        mission_layout.addWidget(mission_text)
        layout.addWidget(mission_frame)

        # --- 3. Core Modules Grid ---
        modules_frame = QFrame()
        modules_frame.setObjectName("CardContainer")
        modules_layout = QVBoxLayout(modules_frame)
        modules_layout.setContentsMargins(30, 30, 30, 30)
        
        modules_title = QLabel("🧩 Core Security Modules")
        modules_title.setStyleSheet("font-size: 22px; font-weight: 900; color: #0078d7; background: transparent; padding-bottom: 15px;")
        modules_layout.addWidget(modules_title)
        
        grid = QGridLayout()
        grid.setSpacing(20)
        
        modules = [
            ("📊 SIEM Dashboard", "An advanced command center featuring a 5-dimensional Security Posture Radar, a live OSINT Threat Ticker, and an Unsupervised ML (IsolationForest) engine for zero-day anomaly detection."),
            ("🚨 Network Intrusion (NIDS)", "Live deep packet inspection via promiscuous mode. Automatically detects aggressive port scans, enforces Zero Trust firewall rules, and supports real-time Syslog forwarding."),
            ("🦠 Antivirus & Sandbox", "A dual-engine defense system running a Real-Time File System Watchdog and a deep Heuristic Analysis sandbox. Malicious binaries are instantly isolated into an encrypted Quarantine Vault."),
            ("🎣 Phishing Detector", "An AI-powered URL and content analysis engine utilizing Natural Language Processing (NLP) to intercept zero-day phishing campaigns and block social engineering attacks."),
            ("⚡ Process & Memory (SOAR)", "Deep kernel-level insight into system performance. Employs Security Orchestration, Automation, and Response (SOAR) playbooks to 'Auto-Kill' malicious process trees automatically."),
            ("⚙️ Global Configuration", "A comprehensive, 7-tab enterprise Control Panel featuring custom iOS-style Animated Toggles, allowing granular control over AI sensitivity, log retention, and 2FA access.")
        ]
        
        for i, (mod_title, mod_desc) in enumerate(modules):
            mod_card = QFrame()
            # Elegant border outline instead of an opaque background filler
            mod_card.setStyleSheet("QFrame { border: 1px solid #88888850; border-radius: 10px; background: transparent; }")
            m_layout = QVBoxLayout(mod_card)
            m_layout.setContentsMargins(20, 20, 20, 20)
            
            l_title = QLabel(mod_title)
            l_title.setStyleSheet("font-weight: 900; font-size: 16px; color: #0078d7; background: transparent; border: none;")
            
            l_desc = QLabel(mod_desc)
            l_desc.setWordWrap(True)
            l_desc.setStyleSheet("font-size: 14px; background: transparent; border: none; padding-top: 8px;")
            
            m_layout.addWidget(l_title)
            m_layout.addWidget(l_desc)
            m_layout.addStretch()
            
            grid.addWidget(mod_card, i // 2, i % 2)
            
        modules_layout.addLayout(grid)
        layout.addWidget(modules_frame)

        # --- 4. Tech Stack & Footer ---
        bottom_layout = QHBoxLayout()
        bottom_layout.setSpacing(25)
        
        # Tech Stack
        tech_frame = QFrame()
        tech_frame.setObjectName("CardContainer")
        tech_layout = QVBoxLayout(tech_frame)
        tech_layout.setContentsMargins(30, 30, 30, 30)
        
        tech_title = QLabel("🛠️ Technology Stack")
        tech_title.setStyleSheet("font-size: 22px; font-weight: 900; color: #0078d7; background: transparent; padding-bottom: 10px;")
        tech_layout.addWidget(tech_title)
        
        tech_grid = QGridLayout()
        tech_grid.setSpacing(15)
        
        tech_items = [
            ("🐍", "Desktop Framework", "Python 3, PyQt6 (GUI)"),
            ("🕸️", "Networking & NIDS", "Scapy, OS Native Firewall"),
            ("⚙️", "System Telemetry", "psutil, WMI, bash scripts"),
            ("🧠", "Machine Learning", "Scikit-learn, Pandas, NumPy"),
            ("🗄️", "Local Database", "SQLite3 (nexashield.db)"),
            ("📄", "Export & Reporting", "QtPrintSupport (PDF Reports), CSV")
        ]
        
        for i, (icon, t_title, t_desc) in enumerate(tech_items):
            t_card = QFrame()
            t_card.setStyleSheet("QFrame { border: 1px solid #88888850; border-radius: 10px; background: transparent; }")
            t_card_layout = QHBoxLayout(t_card)
            t_card_layout.setContentsMargins(15, 12, 15, 12)
            
            lbl_icon = QLabel(icon)
            lbl_icon.setStyleSheet("font-size: 28px; background: transparent; border: none;")
            
            text_layout = QVBoxLayout()
            text_layout.setSpacing(2)
            
            lbl_title = QLabel(t_title)
            lbl_title.setStyleSheet("font-weight: 900; font-size: 14px; color: #0078d7; background: transparent; border: none;")
            
            lbl_desc = QLabel(t_desc)
            lbl_desc.setStyleSheet("font-size: 13px; background: transparent; border: none;")
            
            text_layout.addWidget(lbl_title)
            text_layout.addWidget(lbl_desc)
            
            t_card_layout.addWidget(lbl_icon)
            t_card_layout.addSpacing(10)
            t_card_layout.addLayout(text_layout)
            t_card_layout.addStretch()
            
            tech_grid.addWidget(t_card, i // 2, i % 2)
            
        tech_layout.addLayout(tech_grid)
        tech_layout.addStretch()
        bottom_layout.addWidget(tech_frame, 2)
        
        # Credits & Licensing
        credits_frame = QFrame()
        credits_frame.setObjectName("CardContainer")
        credits_layout = QVBoxLayout(credits_frame)
        credits_layout.setContentsMargins(30, 30, 30, 30)
        
        credits_title = QLabel("👥 Credits & Licensing")
        credits_title.setStyleSheet("font-size: 22px; font-weight: 900; color: #0078d7; background: transparent; padding-bottom: 10px;")
        credits_layout.addWidget(credits_title)
        
        team_lbl = QLabel(
            "<div style='font-size: 15px; line-height: 1.8;'>"
            "<p><b>Lead Developer:</b> Atharv</p>"
            "<p><b>Architecture & Design:</b> NexaShield Core Team</p>"
            "<br>"
            "<p><b>Licensing:</b> MIT License (Open Source)</p>"
            "<p>NexaShield is an independent, non-commercial research project dedicated to advancing the field of cybersecurity through unified, ML-driven threat detection systems.</p>"
            "</div>"
        )
        team_lbl.setWordWrap(True)
        team_lbl.setStyleSheet("background: transparent; color: #cccccc;")
        credits_layout.addWidget(team_lbl)
        
        credits_layout.addStretch()
        
        # Action Buttons
        btn_github = QPushButton("🌐 View on GitHub")
        btn_github.setStyleSheet("padding: 10px 15px; background-color: transparent; border: 1px solid #555; color: white; border-radius: 6px; font-weight: bold;")
        
        btn_update = QPushButton("🔄 Check for Updates")
        btn_update.setStyleSheet("padding: 10px 15px; background-color: #0078d7; color: white; border-radius: 6px; font-weight: bold; border: none;")
        
        btn_layout = QHBoxLayout()
        btn_layout.addWidget(btn_github)
        btn_layout.addWidget(btn_update)
        credits_layout.addLayout(btn_layout)
        
        bottom_layout.addWidget(credits_frame, 1)
        
        layout.addLayout(bottom_layout)
        
        # Finalize Scroll Area
        layout.addStretch()
        scroll_area.setWidget(content_widget)
        main_layout.addWidget(scroll_area)