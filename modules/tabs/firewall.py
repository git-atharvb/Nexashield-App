import sys
import os
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QGridLayout, QLabel, QPushButton, QTableWidget, QTableWidgetItem,
    QHeaderView, QAbstractItemView, QDialog, QFormLayout, QLineEdit, QComboBox, QMessageBox, QFrame, QFileDialog
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal

# Import the backend logic and UI components
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from firewall_logic import FirewallManager
from subtabs.overview import ThreatDonutChart

class AddRuleDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Add Firewall Rule")
        self.setMinimumSize(450, 400)
        self.setStyleSheet("background-color: #2b2b2b; color: white;")
        
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(15)
        
        # Header
        header = QLabel("🛡️ New Advanced Firewall Rule")
        header.setStyleSheet("font-size: 18px; font-weight: bold; color: #0078d7;")
        layout.addWidget(header)
        
        # Form
        form_layout = QFormLayout()
        form_layout.setSpacing(15)
        
        self.name_input = QLineEdit()
        self.name_input.setPlaceholderText("e.g., Block Malicious IP")
        
        self.direction_combo = QComboBox()
        self.direction_combo.addItems(["Inbound", "Outbound"])
        
        self.action_combo = QComboBox()
        self.action_combo.addItems(["Block", "Allow"])
        
        self.ip_input = QLineEdit()
        self.ip_input.setPlaceholderText("Optional (e.g., 192.168.1.50 or Any)")
        
        self.protocol_combo = QComboBox()
        self.protocol_combo.addItems(["TCP", "UDP", "Any"])
        
        self.port_input = QLineEdit()
        self.port_input.setPlaceholderText("Optional (e.g., 80, 443)")
        
        # App Path with Browse Button
        self.app_path_input = QLineEdit()
        self.app_path_input.setPlaceholderText("Optional (.exe path)")
        browse_btn = QPushButton("Browse")
        browse_btn.clicked.connect(self.browse_app)
        
        app_layout = QHBoxLayout()
        app_layout.addWidget(self.app_path_input)
        app_layout.addWidget(browse_btn)
        
        form_layout.addRow("Rule Name:", self.name_input)
        form_layout.addRow("Direction:", self.direction_combo)
        form_layout.addRow("Action:", self.action_combo)
        form_layout.addRow("Target IP:", self.ip_input)
        form_layout.addRow("Protocol:", self.protocol_combo)
        form_layout.addRow("Target Port:", self.port_input)
        form_layout.addRow("Application:", app_layout)
        
        layout.addLayout(form_layout)
        
        # Buttons
        btn_layout = QHBoxLayout()
        self.btn_save = QPushButton("Save Rule")
        self.btn_save.setObjectName("BtnPrimary")
        self.btn_save.setMinimumHeight(35)
        self.btn_save.clicked.connect(self.accept)
        
        self.btn_cancel = QPushButton("Cancel")
        self.btn_cancel.setObjectName("BtnSecondary")
        self.btn_cancel.setMinimumHeight(35)
        self.btn_cancel.clicked.connect(self.reject)
        
        btn_layout.addWidget(self.btn_cancel)
        btn_layout.addWidget(self.btn_save)
        layout.addLayout(btn_layout)

    def browse_app(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select Executable", "", "Executables (*.exe)")
        if file_path:
            # PowerShell requires backslashes or valid path format, QFileDialog returns forward slashes
            self.app_path_input.setText(file_path.replace('/', '\\'))

class LoadRulesThread(QThread):
    rules_loaded = pyqtSignal(list)
    
    def __init__(self, manager):
        super().__init__()
        self.manager = manager
        
    def run(self):
        rules = self.manager.get_firewall_rules(limit=100)
        self.rules_loaded.emit(rules)

class FirewallWidget(QWidget):
    def __init__(self, session_manager=None):
        super().__init__()
        self.session = session_manager
        self.manager = FirewallManager()
        self.init_ui()
        self.load_rules()
        
    def init_ui(self):
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(20, 20, 20, 20)
        main_layout.setSpacing(20)
        
        # --- TITLE SECTION ---
        header_layout = QHBoxLayout()
        title_label = QLabel("Advanced Firewall Control")
        title_label.setObjectName("PageTitle")
        title_label.setStyleSheet("font-size: 24px; font-weight: bold;")
        
        self.lbl_status = QLabel("Status: Loading...")
        self.lbl_status.setStyleSheet("color: #aaaaaa; font-size: 14px;")
        
        header_layout.addWidget(title_label)
        header_layout.addStretch()
        header_layout.addWidget(self.lbl_status)
        main_layout.addLayout(header_layout)
        
        # --- HORIZONTAL SPLIT (Left: Table, Right: Analytics & Actions) ---
        content_layout = QHBoxLayout()
        content_layout.setSpacing(20)
        
        # LEFT PANEL (Table)
        left_panel = QVBoxLayout()
        
        # Table Actions
        action_bar = QHBoxLayout()
        self.btn_add = QPushButton("➕ Add Rule")
        self.btn_add.setObjectName("BtnPrimary")
        self.btn_add.setMinimumHeight(35)
        self.btn_add.clicked.connect(self.show_add_dialog)
        
        self.btn_toggle = QPushButton("⏯️ Toggle State")
        self.btn_toggle.setMinimumHeight(35)
        self.btn_toggle.clicked.connect(self.toggle_selected)
        
        self.btn_delete = QPushButton("🗑️ Delete Selected")
        self.btn_delete.setObjectName("BtnDanger")
        self.btn_delete.setMinimumHeight(35)
        self.btn_delete.clicked.connect(self.delete_selected)
        
        self.btn_refresh = QPushButton("🔄 Refresh")
        self.btn_refresh.setMinimumHeight(35)
        self.btn_refresh.clicked.connect(self.load_rules)
        
        action_bar.addWidget(self.btn_add)
        action_bar.addWidget(self.btn_toggle)
        action_bar.addWidget(self.btn_delete)
        
        self.btn_export_csv = QPushButton("📄 CSV")
        self.btn_export_csv.setObjectName("BtnSecondary")
        self.btn_export_csv.setMinimumHeight(35)
        self.btn_export_csv.clicked.connect(self.export_csv)
        
        self.btn_export_pdf = QPushButton("📑 PDF")
        self.btn_export_pdf.setObjectName("BtnSecondary")
        self.btn_export_pdf.setMinimumHeight(35)
        self.btn_export_pdf.clicked.connect(self.export_pdf)
        
        action_bar.addWidget(self.btn_export_csv)
        action_bar.addWidget(self.btn_export_pdf)
        
        # Info Icon for table guidelines
        self.lbl_info = QLabel("ℹ️ Help")
        self.lbl_info.setStyleSheet("color: #0078d7; font-weight: bold; padding: 5px;")
        self.lbl_info.setCursor(Qt.CursorShape.PointingHandCursor)
        self.lbl_info.setToolTip(
            "<b>Table Reading Guidelines:</b><br>"
            "<ul>"
            "<li><span style='color: #28a745;'>Green Text / Dark Green Row:</span> Allowed Traffic</li>"
            "<li><span style='color: #dc3545;'>Red Text / Dark Red Row:</span> Blocked Traffic</li>"
            "<li><span style='color: gray;'>Gray Text / Dimmed Row:</span> Rule is Disabled</li>"
            "<li><b>Rule ID:</b> Internal Windows identifier for the rule</li>"
            "</ul>"
        )
        
        action_bar.addStretch()
        action_bar.addWidget(self.lbl_info)
        action_bar.addWidget(self.btn_refresh)
        
        left_panel.addLayout(action_bar)
        
        # Table
        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(["Rule Name", "Direction", "Action", "Enabled", "Rule ID"])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setAlternatingRowColors(True)
        left_panel.addWidget(self.table)
        
        content_layout.addLayout(left_panel, 2)  # Takes 2/3 of the space
        
        # RIGHT PANEL (Analytics and Quick Actions)
        right_panel = QVBoxLayout()
        right_panel.setSpacing(20)
        
        # Direction Stats Box (New Graph/Chart)
        direction_box = QFrame()
        direction_box.setObjectName("Card")
        direction_layout = QVBoxLayout(direction_box)
        dir_title = QLabel("Traffic Direction Stats")
        dir_title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        dir_title.setStyleSheet("font-weight: bold; font-size: 16px;")
        direction_layout.addWidget(dir_title)
        
        # Inbound Bar
        self.lbl_inbound = QLabel("Inbound Rules: 0")
        direction_layout.addWidget(self.lbl_inbound)
        from PyQt6.QtWidgets import QProgressBar
        self.prog_inbound = QProgressBar()
        self.prog_inbound.setTextVisible(False)
        self.prog_inbound.setStyleSheet("QProgressBar { border-radius: 5px; background: #333; height: 10px; } QProgressBar::chunk { background-color: #0078d7; border-radius: 5px; }")
        direction_layout.addWidget(self.prog_inbound)
        
        # Outbound Bar
        self.lbl_outbound = QLabel("Outbound Rules: 0")
        direction_layout.addWidget(self.lbl_outbound)
        self.prog_outbound = QProgressBar()
        self.prog_outbound.setTextVisible(False)
        self.prog_outbound.setStyleSheet("QProgressBar { border-radius: 5px; background: #333; height: 10px; } QProgressBar::chunk { background-color: #e83e8c; border-radius: 5px; }")
        direction_layout.addWidget(self.prog_outbound)
        
        right_panel.addWidget(direction_box)
        
        # Chart Box
        self.chart = ThreatDonutChart()
        chart_box = QFrame()
        chart_box.setObjectName("Card")
        chart_layout = QVBoxLayout(chart_box)
        chart_title = QLabel("Rules Distribution")
        chart_title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        chart_title.setStyleSheet("font-weight: bold; font-size: 16px;")
        chart_layout.addWidget(chart_title)
        chart_layout.addWidget(self.chart)
        right_panel.addWidget(chart_box, 1)
        
        # Quick Actions Box
        actions_box = QFrame()
        actions_box.setObjectName("Card")
        actions_layout = QVBoxLayout(actions_box)
        actions_title = QLabel("Quick Actions")
        actions_title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        actions_title.setStyleSheet("font-weight: bold; font-size: 16px;")
        actions_layout.addWidget(actions_title)
        
        # Since it's a vertical column now, we stack them vertically
        self.btn_panic = QPushButton("🚨 Activate Panic Mode (Block Web)")
        self.btn_panic.setObjectName("BtnDanger")
        self.btn_panic.setMinimumHeight(45)
        self.btn_panic.clicked.connect(self.activate_panic)
        
        self.btn_telemetry = QPushButton("🛑 Block Windows Telemetry")
        self.btn_telemetry.setObjectName("BtnSecondary")
        self.btn_telemetry.setMinimumHeight(45)
        self.btn_telemetry.clicked.connect(self.activate_telemetry_block)
        
        self.btn_pings = QPushButton("🏓 Block Incoming Pings (ICMP)")
        self.btn_pings.setObjectName("BtnSecondary")
        self.btn_pings.setMinimumHeight(45)
        self.btn_pings.clicked.connect(self.activate_ping_block)
        
        self.btn_reset = QPushButton("🛡️ Reset Firewall to Default")
        self.btn_reset.setObjectName("BtnSecondary")
        self.btn_reset.setMinimumHeight(45)
        self.btn_reset.clicked.connect(self.activate_reset)
        
        actions_layout.addWidget(self.btn_panic)
        actions_layout.addWidget(self.btn_telemetry)
        actions_layout.addWidget(self.btn_pings)
        actions_layout.addWidget(self.btn_reset)
        actions_layout.addStretch()
        
        right_panel.addWidget(actions_box, 2)
        
        content_layout.addLayout(right_panel, 1)  # Takes 1/3 of the space
        
        main_layout.addLayout(content_layout)
        
    def load_rules(self):
        self.btn_refresh.setEnabled(False)
        self.lbl_status.setText("Status: Fetching Rules...")
        self.table.setRowCount(0)
        
        self.thread = LoadRulesThread(self.manager)
        self.thread.rules_loaded.connect(self.populate_table)
        self.thread.start()
        
    def populate_table(self, rules):
        self.table.setRowCount(len(rules))
        
        from PyQt6.QtGui import QColor, QBrush
        
        stats = {"Safe": 0, "Warning": 0, "Critical": 0} # Using ThreatDonutChart colors
        inbound_count = 0
        outbound_count = 0
        
        for row, rule in enumerate(rules):
            is_enabled = rule['enabled'] == "True"
            is_block = rule['action'] == "Block"
            
            # Row Background Color Logic
            bg_color = QColor(40, 40, 40) # Default dark grey
            if not is_enabled:
                bg_color = QColor(30, 30, 30) # Dimmed
            elif is_block:
                bg_color = QColor(60, 20, 20) # Faint red
            else:
                bg_color = QColor(20, 60, 20) # Faint green
                
            brush = QBrush(bg_color)
            
            # Name
            item_name = QTableWidgetItem(rule['name'])
            item_name.setBackground(brush)
            self.table.setItem(row, 0, item_name)
            
            # Direction
            item_dir = QTableWidgetItem(rule['direction'])
            item_dir.setBackground(brush)
            self.table.setItem(row, 1, item_dir)
            if rule['direction'] == "Inbound":
                inbound_count += 1
            else:
                outbound_count += 1
            
            # Action
            action_item = QTableWidgetItem(rule['action'])
            action_item.setBackground(brush)
            if rule['action'] == "Block":
                action_item.setForeground(Qt.GlobalColor.red)
                if is_enabled: stats["Critical"] += 1
            else:
                action_item.setForeground(Qt.GlobalColor.green)
                if is_enabled: stats["Safe"] += 1
            self.table.setItem(row, 2, action_item)
            
            # Enabled
            enabled_item = QTableWidgetItem(rule['enabled'])
            enabled_item.setBackground(brush)
            if not is_enabled:
                enabled_item.setForeground(Qt.GlobalColor.gray)
                stats["Warning"] += 1
                # Remove from critical/safe if disabled
                item_name.setForeground(Qt.GlobalColor.gray)
            self.table.setItem(row, 3, enabled_item)
            
            # Rule ID (Hidden)
            id_item = QTableWidgetItem(rule['id'])
            id_item.setBackground(brush)
            self.table.setItem(row, 4, id_item)
            
        self.chart.update_stats(stats)
        
        # Update Direction Stats
        total_rules = len(rules)
        if total_rules > 0:
            self.prog_inbound.setMaximum(total_rules)
            self.prog_inbound.setValue(inbound_count)
            self.lbl_inbound.setText(f"Inbound Rules: {inbound_count} ({(inbound_count/total_rules)*100:.1f}%)")
            
            self.prog_outbound.setMaximum(total_rules)
            self.prog_outbound.setValue(outbound_count)
            self.lbl_outbound.setText(f"Outbound Rules: {outbound_count} ({(outbound_count/total_rules)*100:.1f}%)")
        self.lbl_status.setText(f"Status: Displaying {len(rules)} rules")
        self.btn_refresh.setEnabled(True)
        
    def show_add_dialog(self):
        dlg = AddRuleDialog(self)
        if dlg.exec():
            name = dlg.name_input.text().strip()
            if not name:
                QMessageBox.warning(self, "Validation Error", "Rule Name is required.")
                return
                
            direction = dlg.direction_combo.currentText()
            action = dlg.action_combo.currentText()
            ip = dlg.ip_input.text().strip()
            protocol = dlg.protocol_combo.currentText()
            port = dlg.port_input.text().strip()
            app_path = dlg.app_path_input.text().strip()
            
            if protocol == "Any": protocol = None
            if not ip or ip.lower() == "any": ip = None
            if not port: port = None
            if not app_path: app_path = None
            
            success, msg = self.manager.add_rule(name, direction, action, ip, port, protocol, app_path)
            if success:
                QMessageBox.information(self, "Success", "Firewall rule added successfully.")
                self.load_rules()
            else:
                QMessageBox.critical(self, "Error", f"Failed to add rule:\n{msg}")

    def toggle_selected(self):
        selected = self.table.selectedItems()
        if not selected:
            QMessageBox.information(self, "Selection", "Please select a rule to toggle.")
            return
            
        row = selected[0].row()
        rule_id = self.table.item(row, 4).text()
        current_state = self.table.item(row, 3).text()
        
        new_state = current_state == "False"
        
        success, msg = self.manager.toggle_rule(rule_id, enable=new_state)
        if success:
            self.load_rules()
        else:
            QMessageBox.critical(self, "Error", f"Failed to toggle rule:\n{msg}")

    def delete_selected(self):
        selected = self.table.selectedItems()
        if not selected:
            QMessageBox.information(self, "Selection", "Please select a rule to delete.")
            return
            
        row = selected[0].row()
        rule_name = self.table.item(row, 0).text()
        rule_id = self.table.item(row, 4).text()
        
        reply = QMessageBox.question(
            self, 'Confirm Deletion', 
            f"Are you sure you want to delete the rule '{rule_name}'?\nThis will modify your Windows Firewall.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        
        if reply == QMessageBox.StandardButton.Yes:
            success, msg = self.manager.delete_rule(rule_id)
            if success:
                self.load_rules()
            else:
                QMessageBox.critical(self, "Error", f"Failed to delete rule:\n{msg}")
                
    def activate_panic(self):
        reply = QMessageBox.critical(
            self, 'PANIC MODE', 
            "This will aggressively block standard outbound web ports (80, 443) to stop ongoing data exfiltration.\n\nProceed?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        if reply == QMessageBox.StandardButton.Yes:
            success, msg = self.manager.quick_panic()
            if success:
                QMessageBox.information(self, "Panic Activated", "Web traffic has been blocked. Review your rules.")
                self.load_rules()
            else:
                QMessageBox.critical(self, "Error", msg)

    def activate_telemetry_block(self):
        success, msg = self.manager.block_telemetry()
        if success:
            QMessageBox.information(self, "Success", msg)
            self.load_rules()
        else:
            QMessageBox.critical(self, "Error", msg)

    def activate_ping_block(self):
        success, msg = self.manager.block_pings()
        if success:
            QMessageBox.information(self, "Success", msg)
            self.load_rules()
        else:
            QMessageBox.critical(self, "Error", msg)
            
    def activate_reset(self):
        reply = QMessageBox.critical(
            self, 'Confirm Reset', 
            "Are you absolutely sure you want to reset the Windows Firewall to its factory defaults?\n\nAll custom rules (including NexaShield blocks) will be lost!",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        if reply == QMessageBox.StandardButton.Yes:
            success, msg = self.manager.reset_firewall()
            if success:
                QMessageBox.information(self, "Reset Complete", msg)
                self.load_rules()
            else:
                QMessageBox.critical(self, "Error", msg)

    def export_csv(self):
        import csv
        import io
        try:
            output = io.StringIO()
            writer = csv.writer(output)
            writer.writerow(["Name", "Direction", "Action", "Enabled", "Protocol", "Ports"])
            for r in range(self.table.rowCount()):
                writer.writerow([
                    self.table.item(r, 0).text() if self.table.item(r, 0) else "",
                    self.table.item(r, 1).text() if self.table.item(r, 1) else "",
                    self.table.item(r, 2).text() if self.table.item(r, 2) else "",
                    self.table.item(r, 3).text() if self.table.item(r, 3) else "",
                    self.table.item(r, 4).text() if self.table.item(r, 4) else "",
                    self.table.item(r, 5).text() if self.table.item(r, 5) else ""
                ])
                
            if self.session and hasattr(self.session, 'file_manager'):
                self.session.file_manager.export_file(
                    filename="firewall_rules.csv",
                    content=output.getvalue(),
                    module_source="Firewall",
                    file_type="CSV",
                    tags="Routine"
                )
                QMessageBox.information(self, "Vaulted", "Firewall rules CSV securely vaulted in FMS.")
            else:
                QMessageBox.warning(self, "Warning", "FMS not available.")
        except Exception as e:
            QMessageBox.critical(self, "Export Error", str(e))

    def export_pdf(self):
        import tempfile
        import os
        import datetime
        from PyQt6.QtPrintSupport import QPrinter
        from PyQt6.QtGui import QTextDocument
        try:
            temp_fd, temp_path = tempfile.mkstemp(suffix=".pdf")
            os.close(temp_fd)
            
            printer = QPrinter(QPrinter.PrinterMode.HighResolution)
            printer.setOutputFormat(QPrinter.OutputFormat.PdfFormat)
            printer.setOutputFileName(temp_path)
            
            html = f"""
            <html>
            <head>
                <style>
                    h1 {{ text-align: center; font-family: Arial, sans-serif; }}
                    table {{ border-collapse: collapse; width: 100%; font-family: Arial, sans-serif; font-size: 10pt; }}
                    th, td {{ border: 1px solid #333; padding: 4px; text-align: left; }}
                    th {{ background-color: #f2f2f2; font-weight: bold; }}
                </style>
            </head>
            <body>
                <h1>Firewall Rules Report</h1>
                <p>Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                <table>
                    <thead>
                        <tr>
                            <th>Name</th><th>Direction</th><th>Action</th><th>Enabled</th><th>Protocol</th><th>Ports</th>
                        </tr>
                    </thead>
                    <tbody>
            """
            for r in range(self.table.rowCount()):
                n = self.table.item(r, 0).text() if self.table.item(r, 0) else ""
                d = self.table.item(r, 1).text() if self.table.item(r, 1) else ""
                a = self.table.item(r, 2).text() if self.table.item(r, 2) else ""
                e_val = self.table.item(r, 3).text() if self.table.item(r, 3) else ""
                p = self.table.item(r, 4).text() if self.table.item(r, 4) else ""
                pts = self.table.item(r, 5).text() if self.table.item(r, 5) else ""
                html += f"<tr><td>{n}</td><td>{d}</td><td>{a}</td><td>{e_val}</td><td>{p}</td><td>{pts}</td></tr>"
                
            html += "</tbody></table></body></html>"
            
            doc = QTextDocument()
            doc.setHtml(html)
            doc.print(printer)
            
            with open(temp_path, "rb") as f:
                pdf_bytes = f.read()
            os.remove(temp_path)
            
            if self.session and hasattr(self.session, 'file_manager'):
                self.session.file_manager.export_file(
                    filename="firewall_rules.pdf",
                    content=pdf_bytes,
                    module_source="Firewall",
                    file_type="PDF",
                    tags="Routine"
                )
                QMessageBox.information(self, "Vaulted", "Firewall rules PDF securely vaulted in FMS.")
            else:
                QMessageBox.warning(self, "Warning", "FMS not available.")
        except Exception as e:
            QMessageBox.critical(self, "Export Error", str(e))
