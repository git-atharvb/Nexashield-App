from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QFrame, QTreeWidget, QTreeWidgetItem,
    QTextBrowser, QLineEdit, QSplitter
)
from PyQt6.QtCore import Qt

class HelpWidget(QWidget):
    def __init__(self, session_manager=None):
        super().__init__()
        self.session = session_manager
        
        # This dictionary holds all our markdown/HTML documentation content
        self.docs_database = self._build_docs_database()
        
        self.setup_ui()

    def _build_docs_database(self):
        return {
            "Introduction": (
                "<h1>🚀 Welcome to NexaShield</h1>"
                "<p>NexaShield is an enterprise-grade Cybersecurity Suite & SIEM (Security Information and Event Management) platform. "
                "It is designed to aggregate, analyze, and act upon telemetry across your entire infrastructure in real-time.</p>"
                "<h3>Core Architecture</h3>"
                "<ul>"
                "<li><b>Telemetry Engine:</b> Polls CPU, Memory, Disk, and Network hardware metrics continuously.</li>"
                "<li><b>AI Threat Engine:</b> Uses Unsupervised Machine Learning (IsolationForest) to detect zero-day behavioral anomalies.</li>"
                "<li><b>SOAR Automation:</b> Security Orchestration, Automation, and Response playbooks that can automatically neutralize threats.</li>"
                "</ul>"
            ),
            "Quick Start Guide": (
                "<h1>⚡ Quick Start Guide</h1>"
                "<ol>"
                "<li>Navigate to the <b>Settings</b> module and configure your <i>Log Retention Policy</i>.</li>"
                "<li>Go to the <b>SIEM Overview</b> dashboard.</li>"
                "<li>Observe the <b>Threat Radar Map</b> for any live OSINT threats detected globally.</li>"
                "<li>If an anomaly occurs, it will automatically populate the <b>Real-Time Security Feed</b> on the right side of the dashboard.</li>"
                "</ol>"
                "<div style='background-color: rgba(0, 120, 215, 0.1); padding: 15px; border-left: 4px solid #0078d7; margin-top: 20px; border-radius: 4px;'>"
                "<b>💡 Pro Tip:</b> You can double-click any row in the Real-Time Security Feed to view the raw JSON telemetry for that event."
                "</div>"
            ),
            "Dashboard & Telemetry": (
                "<h1>📊 SIEM Dashboard Explained</h1>"
                "<p>The Overview tab is your primary command center. It visualizes the raw telemetry data coming from the host machine.</p>"
                "<h3>The Security Posture Radar</h3>"
                "<p>The yellow radar chart maps 5 key dimensions of host health: Endpoint, Traffic, Storage, Memory, and Network. "
                "A perfect score is a fully expanded polygon. As threats or high loads occur, the points will collapse inward.</p>"
                "<h3>Live Threat Ticker</h3>"
                "<p>The red scrolling text at the top of the dashboard displays severe alerts and global OSINT Threat Intelligence (like known ransomware C2 servers) in real-time.</p>"
            ),
            "AI Anomaly Detection": (
                "<h1>🤖 AI Anomaly Detection Engine</h1>"
                "<p>NexaShield uses an advanced Machine Learning model known as an <b>Isolation Forest</b>.</p>"
                "<p>Instead of relying purely on signature databases (which fail against zero-day malware), the AI continuously "
                "profiles normal behavior on the host. If a sudden spike in CPU, Memory, and Network IO occurs simultaneously—a pattern "
                "highly indicative of ransomware encryption or cryptomining—the model flags it as a <b>Behavioral Anomaly</b>.</p>"
                "<h3>Adjusting Sensitivity</h3>"
                "<p>You can adjust the strictness of the ML model in <code>Settings > AI & Threat Engine</code>.</p>"
            ),
            "Antivirus & Sandbox": (
                "<h1>🛑 Antivirus & File System Shield</h1>"
                "<p>The NexaShield AV engine operates in two distinct modes:</p>"
                "<ul>"
                "<li><b>Real-Time Watchdog:</b> Monitors file system events (Create, Modify, Delete) dynamically and scans files before they execute.</li>"
                "<li><b>Heuristic Sandbox:</b> Suspicious binaries are detonated in an isolated environment to monitor API calls and registry modifications before they are allowed on the host.</li>"
                "</ul>"
                "<h3>Quarantine Management</h3>"
                "<p>If a file is deemed malicious, it is automatically encrypted and moved to the Quarantine Vault. You can permanently delete or restore it from there.</p>"
            ),
            "Network Intrusion (NIDS)": (
                "<h1>🌐 Network Intrusion Detection System</h1>"
                "<p>The NIDS module sniffs packet traffic across your configured network interfaces in Promiscuous mode.</p>"
                "<h3>Features</h3>"
                "<ul>"
                "<li><b>Port Scan Detection:</b> Automatically detects and blocks IPs that attempt aggressive SYN scans across your ports.</li>"
                "<li><b>Syslog Forwarding:</b> NexaShield can forward all captured packets to a central SIEM server like Splunk or ELK via UDP port 514.</li>"
                "<li><b>Zero Trust Firewall:</b> Configure the firewall strictly to block all incoming connections by default unless explicitly trusted.</li>"
                "</ul>"
            ),
            "Troubleshooting & Logs": (
                "<h1>❓ Troubleshooting & Logs</h1>"
                "<h3>What do I do during a Critical Alert?</h3>"
                "<p>Do not panic. Follow the incident response playbook:</p>"
                "<ol>"
                "<li>Click the <b>Isolate Host</b> button in the Network tab to cut off internet access while maintaining local SIEM communication.</li>"
                "<li>Review the exact process that triggered the alert in the <b>Processes</b> tab.</li>"
                "<li>Right-click the malicious process and select <b>Kill Tree</b>.</li>"
                "</ol>"
                "<h3>Exporting Diagnostics</h3>"
                "<p>If you encounter a software bug, navigate to <code>Settings > Database & Storage</code> and click <b>Export Configs</b>. Send the resulting `.json` file to support.</p>"
            )
        }

    def setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(15)

        # 1. Header
        header = QLabel("📖 NexaShield Knowledge Base")
        header.setStyleSheet("font-size: 26px; font-weight: 800; color: #0078d7; letter-spacing: 1px;")
        layout.addWidget(header)
        
        # 2. Main Splitter (Left ToC, Right Content)
        splitter = QSplitter(Qt.Orientation.Horizontal)
        from PyQt6.QtWidgets import QSizePolicy
        splitter.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        splitter.setChildrenCollapsible(False)
        
        # --- LEFT PANEL: Table of Contents ---
        toc_frame = QFrame()
        toc_frame.setObjectName("CardContainer")
        toc_layout = QVBoxLayout(toc_frame)
        toc_layout.setContentsMargins(15, 15, 15, 15)
        
        self.search_bar = QLineEdit()
        self.search_bar.setPlaceholderText("🔍 Search documentation...")
        self.search_bar.setStyleSheet("""
            QLineEdit {
                padding: 10px;
                border: 1px solid #333;
                border-radius: 6px;
                background-color: rgba(0, 0, 0, 0.2);
                color: white;
            }
            QLineEdit:focus { border: 1px solid #0078d7; }
        """)
        self.search_bar.textChanged.connect(self.filter_toc)
        toc_layout.addWidget(self.search_bar)
        
        self.tree = QTreeWidget()
        self.tree.setHeaderHidden(True)
        self.tree.setStyleSheet("""
            QTreeWidget {
                background-color: transparent;
                border: none;
                outline: none;
            }
            QTreeWidget::item {
                padding: 8px;
                border-radius: 5px;
                color: #cccccc;
                font-weight: bold;
            }
            QTreeWidget::item:selected {
                background-color: rgba(0, 120, 215, 0.2);
                color: #0078d7;
            }
            QTreeWidget::item:hover:!selected {
                background-color: rgba(255, 255, 255, 0.05);
            }
        """)
        self.tree.itemSelectionChanged.connect(self.on_item_selected)
        
        self.populate_tree()
        toc_layout.addWidget(self.tree)
        
        splitter.addWidget(toc_frame)
        
        # --- RIGHT PANEL: Content Viewer ---
        content_frame = QFrame()
        content_frame.setObjectName("CardContainer")
        content_layout = QVBoxLayout(content_frame)
        content_layout.setContentsMargins(30, 20, 30, 20)
        
        self.lbl_breadcrumb = QLabel("📖 Home")
        self.lbl_breadcrumb.setStyleSheet("color: #8b949e; font-weight: bold; font-size: 13px;")
        content_layout.addWidget(self.lbl_breadcrumb)
        
        # Separator line
        sep = QFrame()
        sep.setFrameShape(QFrame.Shape.HLine)
        sep.setStyleSheet("border: 1px solid #333; margin-top: 5px; margin-bottom: 10px;")
        content_layout.addWidget(sep)
        
        self.browser = QTextBrowser()
        self.browser.setOpenExternalLinks(True)
        self.browser.setStyleSheet("""
            QTextBrowser {
                background-color: transparent;
                border: none;
                color: #e0e0e0;
                font-size: 15px;
                line-height: 1.6;
            }
        """)
        
        content_layout.addWidget(self.browser)
        splitter.addWidget(content_frame)
        
        # Set splitter sizes (Left 30%, Right 70%)
        splitter.setSizes([300, 800])
        
        layout.addWidget(splitter, 1)
        
        # Load default document
        self.display_document("Introduction", "🚀 Getting Started")

    def populate_tree(self):
        """Builds the Table of Contents tree."""
        self.tree.clear()
        
        # Section: Getting Started
        sec_start = QTreeWidgetItem(self.tree, ["🚀 Getting Started"])
        QTreeWidgetItem(sec_start, ["Introduction"])
        QTreeWidgetItem(sec_start, ["Quick Start Guide"])
        
        # Section: SIEM & Analytics
        sec_siem = QTreeWidgetItem(self.tree, ["📊 SIEM & Analytics"])
        QTreeWidgetItem(sec_siem, ["Dashboard & Telemetry"])
        QTreeWidgetItem(sec_siem, ["AI Anomaly Detection"])
        
        # Section: Security Modules
        sec_sec = QTreeWidgetItem(self.tree, ["🛡️ Security Modules"])
        QTreeWidgetItem(sec_sec, ["Antivirus & Sandbox"])
        QTreeWidgetItem(sec_sec, ["Network Intrusion (NIDS)"])
        
        # Section: Administration
        sec_admin = QTreeWidgetItem(self.tree, ["⚙️ Administration"])
        QTreeWidgetItem(sec_admin, ["Troubleshooting & Logs"])
        
        self.tree.expandAll()

    def filter_toc(self, text):
        """Filters the tree items based on search text."""
        query = text.lower()
        
        for i in range(self.tree.topLevelItemCount()):
            top_item = self.tree.topLevelItem(i)
            # Default hide
            top_item.setHidden(True)
            
            has_visible_child = False
            for j in range(top_item.childCount()):
                child = top_item.child(j)
                if query in child.text(0).lower() or query in top_item.text(0).lower():
                    child.setHidden(False)
                    has_visible_child = True
                else:
                    child.setHidden(True)
                    
            if has_visible_child or query in top_item.text(0).lower():
                top_item.setHidden(False)

    def on_item_selected(self):
        """Fired when user clicks a topic in the tree."""
        selected = self.tree.selectedItems()
        if not selected:
            return
            
        item = selected[0]
        # Ignore clicks on root categories
        if item.childCount() > 0:
            return
            
        topic = item.text(0)
        parent_category = item.parent().text(0)
        
        self.display_document(topic, parent_category)

    def display_document(self, topic, category):
        """Renders the HTML document into the browser."""
        self.lbl_breadcrumb.setText(f"📖 NexaShield Docs > {category} > {topic}")
        
        html_content = self.docs_database.get(topic, "<h1>⚠️ 404 - Document Not Found</h1><p>The requested documentation page is missing or under construction.</p>")
        
        # Wrap content in basic CSS for styling within QTextBrowser
        full_html = f"""
        <html>
        <head>
        <style>
            body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; }}
            h1 {{ color: #ffffff; font-size: 24px; margin-bottom: 20px; }}
            h3 {{ color: #0078d7; font-size: 18px; margin-top: 25px; }}
            p {{ color: #cccccc; margin-bottom: 12px; font-size: 14px; line-height: 1.6; }}
            ul, ol {{ color: #cccccc; margin-bottom: 15px; margin-left: 20px; font-size: 14px; line-height: 1.6; }}
            li {{ margin-bottom: 8px; }}
            code {{ background-color: rgba(255,255,255,0.1); padding: 2px 5px; border-radius: 4px; font-family: monospace; color: #ffc107; }}
        </style>
        </head>
        <body>
        {html_content}
        </body>
        </html>
        """
        self.browser.setHtml(full_html)