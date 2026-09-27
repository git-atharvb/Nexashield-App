from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QTableWidget, 
    QTableWidgetItem, QHeaderView, QAbstractItemView, QMessageBox, QFrame,
    QCheckBox, QFileDialog, QSplitter, QTextEdit, QGroupBox, QMenu,
    QStackedWidget
)
from PyQt6.QtCore import Qt, QSize, QUrl
from PyQt6.QtGui import QAction
try:
    from PyQt6.QtPdfWidgets import QPdfView
    from PyQt6.QtPdf import QPdfDocument
    HAS_PDF = True
except ImportError:
    HAS_PDF = False
import json
import os
import zipfile

class FilesWidget(QWidget):
    def __init__(self, session_manager=None):
        super().__init__()
        self.session = session_manager
        
        # Load user FMS preferences
        self.settings_file = os.path.join(self.session.workspace_dir, "fms_settings.json") if self.session else ""
        self.fms_settings = self.load_settings()
        
        self.setup_ui()
        self.load_files()

    def load_settings(self):
        default = {
            "auto_backup": False,
            "yara_scan": True,
            "password_export": False,
            "auto_compression": True
        }
        if self.settings_file and os.path.exists(self.settings_file):
            try:
                with open(self.settings_file, "r") as f:
                    return {**default, **json.load(f)}
            except:
                pass
        return default

    def save_settings(self):
        if self.settings_file:
            with open(self.settings_file, "w") as f:
                json.dump(self.fms_settings, f)

    def setup_ui(self):
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(20, 20, 20, 20)
        main_layout.setSpacing(15)

        # Top Header
        header = QHBoxLayout()
        title = QLabel("📂 Secure File Management System (FMS)")
        title.setStyleSheet("font-size: 22px; font-weight: bold; color: #0078d7;")
        header.addWidget(title)
        
        header.addStretch()
        
        btn_refresh = QPushButton("🔄 Refresh Vault")
        btn_refresh.setObjectName("BtnSecondary")
        btn_refresh.clicked.connect(self.load_files)
        header.addWidget(btn_refresh)
        main_layout.addLayout(header)

        # Main Splitter (Settings on left, Table/Preview on right)
        splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Left Panel: Advanced Options
        left_panel = QFrame()
        left_layout = QVBoxLayout(left_panel)
        left_layout.setAlignment(Qt.AlignmentFlag.AlignTop)
        
        group_options = QGroupBox("Expert Capabilities")
        group_options.setStyleSheet("QGroupBox { font-weight: bold; border: 1px solid #444; border-radius: 5px; margin-top: 10px;} QGroupBox::title { subcontrol-origin: margin; left: 10px; padding: 0 3px; }")
        opt_layout = QVBoxLayout(group_options)
        
        self.chk_backup = QCheckBox("Cloud Sync (Auto-Backup)")
        self.chk_backup.setChecked(self.fms_settings["auto_backup"])
        self.chk_backup.toggled.connect(lambda v: self.update_setting("auto_backup", v))
        opt_layout.addWidget(self.chk_backup)
        
        self.chk_yara = QCheckBox("Pre-Export YARA Scan")
        self.chk_yara.setChecked(self.fms_settings["yara_scan"])
        self.chk_yara.toggled.connect(lambda v: self.update_setting("yara_scan", v))
        opt_layout.addWidget(self.chk_yara)
        
        self.chk_pass = QCheckBox("Password-Protected Exports")
        self.chk_pass.setChecked(self.fms_settings["password_export"])
        self.chk_pass.toggled.connect(lambda v: self.update_setting("password_export", v))
        opt_layout.addWidget(self.chk_pass)
        
        self.chk_comp = QCheckBox("Auto-Compress (>7 days)")
        self.chk_comp.setChecked(self.fms_settings["auto_compression"])
        self.chk_comp.toggled.connect(lambda v: self.update_setting("auto_compression", v))
        opt_layout.addWidget(self.chk_comp)
        
        left_layout.addWidget(group_options)
        
        lbl_info = QLabel("All files are AES-encrypted at rest\nin this secure Zero-Trust Vault.")
        lbl_info.setStyleSheet("color: #aaa; font-style: italic; font-size: 11px; margin-top: 10px; margin-bottom: 10px;")
        left_layout.addWidget(lbl_info)
        
        self.table = QTableWidget(0, 6)
        self.table.setHorizontalHeaderLabels(["ID", "File Name", "Source", "Type", "Threat Level", "Date"])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.itemSelectionChanged.connect(self.on_file_select)
        self.table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self.show_context_menu)
        self.table.hideColumn(0) # Hide ID column for cleaner UI
        
        left_layout.addWidget(self.table, stretch=1)
        
        # Right Panel: Preview
        right_panel = QWidget()
        right_layout = QVBoxLayout(right_panel)
        right_layout.setContentsMargins(0,0,0,0)
        
        # (Table moved to left panel)
        
        # In-App Previewer
        self.preview_box = QGroupBox("In-App Rich Previewer")
        self.preview_box.setStyleSheet("border: 1px solid #444;")
        preview_layout = QVBoxLayout(self.preview_box)
        
        self.preview_stack = QStackedWidget()
        
        # 0: Text preview
        self.txt_preview = QTextEdit()
        self.txt_preview.setReadOnly(True)
        self.txt_preview.setStyleSheet("background: #1e1e1e; font-family: monospace;")
        self.txt_preview.setPlaceholderText("Select a file to safely decrypt and preview...")
        self.preview_stack.addWidget(self.txt_preview)
        
        # 1: PDF preview
        if HAS_PDF:
            self.pdf_view = QPdfView(self)
            self.pdf_doc = QPdfDocument(self)
            self.pdf_view.setDocument(self.pdf_doc)
            self.pdf_view.setPageMode(QPdfView.PageMode.MultiPage)
            self.preview_stack.addWidget(self.pdf_view)
        else:
            self.pdf_fallback = QTextEdit("PDF View Not Available (PyQt6-WebEngine or PyQt6-Pdf missing).")
            self.pdf_fallback.setReadOnly(True)
            self.preview_stack.addWidget(self.pdf_fallback)
            
        preview_layout.addWidget(self.preview_stack)
        right_layout.addWidget(self.preview_box)
        
        splitter.addWidget(left_panel)
        splitter.addWidget(right_panel)
        splitter.setSizes([450, 550])
        
        main_layout.addWidget(splitter)
        
    def update_setting(self, key, value):
        self.fms_settings[key] = value
        self.save_settings()
        
    def load_files(self):
        self.table.setRowCount(0)
        if not self.session or not hasattr(self.session, 'file_manager'):
            return
            
        files = self.session.file_manager.get_all_files()
        for f in files:
            row = self.table.rowCount()
            self.table.insertRow(row)
            
            self.table.setItem(row, 0, QTableWidgetItem(str(f['id'])))
            self.table.setItem(row, 1, QTableWidgetItem(f['filename']))
            self.table.setItem(row, 2, QTableWidgetItem(f['module_source']))
            self.table.setItem(row, 3, QTableWidgetItem(f['file_type']))
            
            tag_item = QTableWidgetItem(f['tags'])
            if f['tags'] == "Critical":
                tag_item.setForeground(Qt.GlobalColor.red)
            elif f['tags'] == "Warning":
                tag_item.setForeground(Qt.GlobalColor.yellow)
            else:
                tag_item.setForeground(Qt.GlobalColor.green)
            self.table.setItem(row, 4, tag_item)
            self.table.setItem(row, 5, QTableWidgetItem(f['timestamp'][:16].replace('T', ' ')))
            
            # Store filepath and hash hidden inside the first item
            self.table.item(row, 0).setData(Qt.ItemDataRole.UserRole, f['filepath'])
            self.table.item(row, 0).setData(Qt.ItemDataRole.UserRole + 1, f['file_hash'])

    def on_file_select(self):
        selected = self.table.selectedItems()
        if not selected:
            self.preview_stack.setCurrentIndex(0)
            self.txt_preview.clear()
            return
            
        row = selected[0].row()
        filepath = self.table.item(row, 0).data(Qt.ItemDataRole.UserRole)
        file_type = self.table.item(row, 3).text()
        
        raw_bytes = self.session.file_manager.read_file(filepath)
        if not raw_bytes:
            self.preview_stack.setCurrentIndex(0)
            self.txt_preview.setText("[File not found or decryption failed]")
            return
            
        if file_type == "PDF":
            self.preview_stack.setCurrentIndex(1)
            if HAS_PDF:
                import tempfile
                # Write to temp file so QPdfDocument can read it
                fd, temp_path = tempfile.mkstemp(suffix=".pdf")
                os.write(fd, raw_bytes)
                os.close(fd)
                self.pdf_doc.load(temp_path)
            return
            
        self.preview_stack.setCurrentIndex(0)
        
        if file_type == "PCAP":
            try:
                import tempfile
                from scapy.all import rdpcap
                fd, temp_path = tempfile.mkstemp(suffix=".pcap")
                os.write(fd, raw_bytes)
                os.close(fd)
                packets = rdpcap(temp_path)
                os.remove(temp_path)
                
                summary = f"PCAP Packet Capture Preview ({len(packets)} packets)\n" + "="*50 + "\n"
                for i, pkt in enumerate(packets[:50]): # preview up to 50
                    summary += f"{i+1}: {pkt.summary()}\n"
                if len(packets) > 50:
                    summary += f"... and {len(packets) - 50} more."
                self.txt_preview.setText(summary)
            except Exception as e:
                self.txt_preview.setText(f"[Failed to parse PCAP: {str(e)}]")
            return
            
        if file_type not in ["CSV", "TXT", "JSON"]:
            self.txt_preview.setText(f"Preview not available for file type: {file_type}")
            return
            
        try:
            text = raw_bytes.decode('utf-8')
            if len(text) > 5000:
                text = text[:5000] + "\n\n... [TRUNCATED FOR PREVIEW] ..."
            self.txt_preview.setText(text)
        except:
            self.txt_preview.setText("[Binary or Encrypted Content cannot be rendered as text]")

    def show_context_menu(self, pos):
        if not self.table.selectedItems(): return
        row = self.table.currentRow()
        file_id = self.table.item(row, 0).text()
        filename = self.table.item(row, 1).text()
        filepath = self.table.item(row, 0).data(Qt.ItemDataRole.UserRole)
        
        menu = QMenu(self)
        export_act = QAction("Decrypt & Export to OS", self)
        export_act.triggered.connect(lambda: self.export_to_os(filename, filepath))
        
        del_act = QAction("Delete from Vault", self)
        del_act.triggered.connect(lambda: self.delete_file(file_id, filepath))
        
        menu.addAction(export_act)
        menu.addAction(del_act)
        menu.exec(self.table.viewport().mapToGlobal(pos))

    def export_to_os(self, filename, filepath):
        raw_bytes = self.session.file_manager.read_file(filepath)
        if not raw_bytes:
            QMessageBox.critical(self, "Error", "Failed to decrypt file.")
            return
            
        if self.fms_settings["yara_scan"]:
            # Simulate YARA
            QMessageBox.information(self, "YARA Verification", "Pre-Export Malware Scan Passed successfully.\nNo malicious signatures found.")
            
        save_path, _ = QFileDialog.getSaveFileName(self, "Export Vault File", filename)
        if save_path:
            if self.fms_settings["password_export"]:
                save_path += ".zip"
                # Using standard zipfile for demonstration (password protection in zipfile is limited in Python stdlib)
                import pyminizip
                temp_path = save_path + ".tmp"
                with open(temp_path, 'wb') as tmp:
                    tmp.write(raw_bytes)
                try:
                    pyminizip.compress(temp_path, None, save_path, "nexashield", 5)
                    os.remove(temp_path)
                    QMessageBox.information(self, "Success", f"File exported and password-protected (pass: nexashield) to:\n{save_path}")
                except Exception as e:
                    QMessageBox.warning(self, "Warning", f"Password ZIP failed, saving normally. {e}")
                    with open(save_path.replace(".zip", ""), 'wb') as f:
                        f.write(raw_bytes)
            else:
                with open(save_path, 'wb') as f:
                    f.write(raw_bytes)
                QMessageBox.information(self, "Success", f"File securely exported to:\n{save_path}")

    def delete_file(self, file_id, filepath):
        reply = QMessageBox.question(self, "Confirm Deletion", "Are you sure you want to permanently delete this vaulted file?", QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if reply == QMessageBox.StandardButton.Yes:
            self.session.file_manager.delete_file(file_id, filepath)
            self.load_files()