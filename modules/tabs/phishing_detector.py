import sqlite3
import datetime
import pickle
import re
import os
import socket
import json
import math
from urllib.parse import urlparse

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLineEdit, QPushButton,
    QLabel, QTableWidget, QTableWidgetItem, QHeaderView,
    QMessageBox, QFileDialog, QFrame, QGroupBox, QProgressBar,
    QAbstractItemView, QToolTip
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QRectF
from PyQt6.QtGui import QColor, QBrush, QTextDocument, QFont, QPainter, QPen, QPalette
from PyQt6.QtPrintSupport import QPrinter

# --- Constants ---
DB_NAME = "nexashield.db"
MODEL_PATH = "phishing_model.pkl"
VECTORIZER_PATH = "vectorizer.pkl"

class PhishingAnalyzer:
    """Core logic for phishing detection, separated from UI threads."""
    def __init__(self):
        self.model = None
        self.vectorizer = None
        self.ml_enabled = False
        self._load_models()

    def _load_models(self):
        """Attempts to load ML models. Falls back to heuristics if failed."""
        try:
            if os.path.exists(MODEL_PATH) and os.path.exists(VECTORIZER_PATH):
                with open(MODEL_PATH, 'rb') as f:
                    self.model = pickle.load(f)
                with open(VECTORIZER_PATH, 'rb') as f:
                    self.vectorizer = pickle.load(f)
                self.ml_enabled = True
        except Exception as e:
            print(f"ML Model Load Error: {e}")
            self.ml_enabled = False

    def scan(self, url):
        try:
            if not url:
                raise ValueError("Empty URL")

            # 1. Heuristic Analysis
            heuristic_score, reasons = self.analyze_heuristics(url)
            
            # 2. ML Analysis (if available)
            ml_score = 0.0
            ml_confidence = 0.0
            
            if self.ml_enabled and self.vectorizer and self.model:
                try:
                    # Vectorize URL
                    features = self.vectorizer.transform([url])
                    # Predict (Assuming class 1 is phishing)
                    prob = self.model.predict_proba(features)[0][1]
                    ml_score = prob * 100
                    ml_confidence = prob * 100 if prob > 0.5 else (1 - prob) * 100
                except Exception as e:
                    reasons.append(f"ML Analysis Failed: {str(e)}")
            
            # 3. Hybrid Decision
            if self.ml_enabled:
                # If heuristics detect a strong threat, trust them over ML (which might be outdated)
                if heuristic_score > 75:
                    final_score = max(ml_score, heuristic_score)
                    method = "Hybrid (Heuristics Dominant)"
                else:
                    final_score = (ml_score * 0.6) + (heuristic_score * 0.4)
                    method = "Hybrid (ML Weighted)"
            else:
                final_score = heuristic_score
                method = "Heuristics Only"

            # Determine Threat Level
            if final_score < 30:
                level = "Safe"
            elif final_score < 60:
                level = "Low Risk"
            elif final_score < 85:
                level = "Medium Risk"
            else:
                level = "High Risk"

            details = self.get_url_details(url)

            return {
                "url": url,
                "score": final_score,
                "level": level,
                "method": method,
                "reasons": reasons,
                "details": details,
                "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }

        except Exception as e:
            return {"error": str(e)}

    def get_url_details(self, url):
        details = {}
        try:
            parsed = urlparse(url)
            details["Scheme"] = parsed.scheme
            details["Netloc"] = parsed.netloc
            details["Path"] = parsed.path
            details["Query"] = parsed.query
            
            domain = parsed.hostname
            port = parsed.port
            details["Hostname"] = domain
            details["Port"] = str(port) if port else ("80" if parsed.scheme == "http" else "443")

            # Resolve IP
            if domain:
                try:
                    ip = socket.gethostbyname(domain)
                    details["Resolved IP"] = ip
                except:
                    details["Resolved IP"] = "Failed to resolve"
        except Exception as e:
            details["Error"] = str(e)
        return details

    def analyze_heuristics(self, url):
        score = 0
        reasons = []
        
        try:
            parsed = urlparse(url)
            domain = parsed.netloc
            path = parsed.path
        except Exception:
            domain = ""
            path = ""
        
        # Rule 1: IP Address in URL
        ip_pattern = r'^(http|https)://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
        if re.search(ip_pattern, url):
            score += 50
            reasons.append("Uses IP address instead of domain")

        # Rule 2: Length
        if len(url) > 75:
            score += 15
            reasons.append("URL is suspiciously long (>75 chars)")

        # Rule 3: @ Symbol (Obfuscation)
        if "@" in url:
            score += 25
            reasons.append("Contains '@' symbol (often used for obfuscation)")

        # Rule 4: Suspicious Keywords
        keywords = ["login", "verify", "update", "secure", "account", "banking", "confirm", "signin", "wallet", "paypal", "crypto"]
        if any(k in url.lower() for k in keywords):
            score += 20
            reasons.append("Contains sensitive keywords often used in phishing")

        # Rule 5: Excessive Subdomains
        if domain.count('.') > 3:
            score += 20
            reasons.append("Excessive subdomains detected")

        # Rule 6: Suspicious TLDs
        suspicious_tlds = ['.xyz', '.top', '.gq', '.tk', '.ml', '.ga', '.cf', '.cn', '.vip', '.cc']
        if any(domain.endswith(tld) for tld in suspicious_tlds):
            score += 25
            reasons.append("Uses a TLD commonly associated with phishing")

        # Rule 7: URL Shorteners
        shorteners = ['bit.ly', 'tinyurl.com', 'goo.gl', 'ow.ly', 't.co', 'is.gd', 'buff.ly']
        if any(s in domain.lower() for s in shorteners):
            score += 20
            reasons.append("Uses a URL shortening service")

        # Rule 8: Hyphens in domain (Typosquatting)
        if domain.count('-') > 1:
            score += 15
            reasons.append("Domain contains multiple hyphens (possible typosquatting)")

        # Rule 9: Double slash in path (Open Redirect)
        if '//' in path:
            score += 20
            reasons.append("Contains '//' in path (possible open redirect)")

        # Rule 10: Punycode (Homograph attack)
        if 'xn--' in domain:
            score += 40
            reasons.append("Uses Punycode (possible homograph attack)")

        # Rule 11: Non-standard port
        if parsed.port and parsed.port not in [80, 443]:
            score += 15
            reasons.append(f"Uses non-standard port {parsed.port}")

        return min(score, 100), reasons

class PhishingScannerWorker(QThread):
    """Background thread for single URL scan."""
    scan_complete = pyqtSignal(dict)
    error_occurred = pyqtSignal(str)

    def __init__(self, url):
        super().__init__()
        self.url = url
        self.analyzer = None

    def run(self):
        self.analyzer = PhishingAnalyzer() # Load models in the background thread
        result = self.analyzer.scan(self.url)
        if "error" in result:
            self.error_occurred.emit(result["error"])
        else:
            self.scan_complete.emit(result)

class BatchPhishingWorker(QThread):
    """Background thread for batch URL scanning."""
    progress = pyqtSignal(int, int) # current, total
    result_ready = pyqtSignal(dict)
    finished_batch = pyqtSignal()

    def __init__(self, urls):
        super().__init__()
        self.urls = urls
        self.analyzer = None
        self.is_running = True

    def stop(self):
        self.is_running = False

    def run(self):
        self.analyzer = PhishingAnalyzer() # Load models in the background thread
        total = len(self.urls)
        for i, url in enumerate(self.urls):
            if not self.is_running: break
            
            url = url.strip()
            if url:
                result = self.analyzer.scan(url)
                if "error" not in result:
                    self.result_ready.emit(result)
            
            self.progress.emit(i + 1, total)
        
        self.finished_batch.emit()

class PhishingStatsChart(QWidget):
    """Pie chart to visualize threat distribution."""
    def __init__(self):
        super().__init__()
        self.setMinimumSize(150, 150)
        self.stats = {"Safe": 0, "Low Risk": 0, "Medium Risk": 0, "High Risk": 0}
        self.setMouseTracking(True)

    def update_stats(self, stats):
        self.stats = stats
        self.update()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        
        w = self.width()
        h = self.height()
        
        # Background
        painter.fillRect(0, 0, w, h, self.palette().color(QPalette.ColorRole.Window))
        
        total = sum(self.stats.values())
        if total == 0:
            return

        # Colors
        colors = {
            "Safe": "#28a745",
            "Low Risk": "#17a2b8",
            "Medium Risk": "#ffc107",
            "High Risk": "#dc3545"
        }
        
        # Title
        text_col = self.palette().color(QPalette.ColorRole.WindowText)
        painter.setPen(text_col)
        painter.setFont(QFont("Segoe UI", 10, QFont.Weight.Bold))
        painter.drawText(0, 10, w, 20, Qt.AlignmentFlag.AlignCenter, "Scan Distribution")

        # Draw Donut
        top_pad = 35
        size = min(w, h - top_pad) - 10
        rect = QRectF((w - size) / 2, top_pad, size, size)
        start_angle = 90 * 16
        
        for label, count in self.stats.items():
            if count > 0:
                span = int((count / total) * 360 * 16)
                painter.setBrush(QColor(colors.get(label, "#888")))
                painter.setPen(Qt.PenStyle.NoPen)
                painter.drawPie(rect, start_angle, span)
                start_angle += span
                
        # Inner Donut Hole
        painter.setBrush(self.palette().color(QPalette.ColorRole.Window))
        inner_size = size * 0.65
        inner_rect = QRectF((w - inner_size) / 2, top_pad + (size - inner_size) / 2, inner_size, inner_size)
        painter.drawEllipse(inner_rect)
        
        painter.setPen(text_col)
        painter.setFont(QFont("Segoe UI", 12, QFont.Weight.Bold))
        painter.drawText(inner_rect, Qt.AlignmentFlag.AlignCenter, f"Total\n{total}")

    def mouseMoveEvent(self, event):
        total = sum(self.stats.values())
        if total == 0:
            return super().mouseMoveEvent(event)
            
        pos = event.pos()
        w, h = self.width(), self.height()
        top_pad = 35
        size = min(w, h - top_pad) - 10
        rect = QRectF((w - size) / 2, top_pad, size, size)
        
        center = rect.center()
        dx = pos.x() - center.x()
        dy = pos.y() - center.y()
        distance = math.hypot(dx, dy)
        
        inner_radius = (size * 0.65) / 2
        outer_radius = size / 2
        
        if inner_radius <= distance <= outer_radius:
            angle = math.degrees(math.atan2(-dy, dx))
            if angle < 0:
                angle += 360
            mapped_angle = (angle - 90) % 360
            
            current_span = 0
            for label, count in self.stats.items():
                if count > 0:
                    span = (count / total) * 360
                    if current_span <= mapped_angle <= current_span + span:
                        QToolTip.showText(event.globalPosition().toPoint(), f"Threat Level: {label}\nUrls Scanned: {count}\nShare: {(count/total)*100:.1f}%", self)
                        return
                    current_span += span
                    
        QToolTip.hideText()
        super().mouseMoveEvent(event)

class PhishingDetectorWidget(QWidget):
    def __init__(self, session_manager=None):
        super().__init__()
        self.session = session_manager
        self.setObjectName("PhishingDetector")
        self.init_db()
        self.setup_ui()

    def init_db(self):
        """Initialize the history table."""
        try:
            db_path = self.session.get_db_path() if self.session else DB_NAME
            self.conn = sqlite3.connect(db_path)
            cursor = self.conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS phishing_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    url TEXT,
                    threat_level TEXT,
                    score REAL,
                    timestamp TEXT,
                    details TEXT,
                    reasons TEXT
                )
            """)
            
            # Migration: Add columns if they don't exist
            cursor.execute("PRAGMA table_info(phishing_history)")
            columns = [info[1] for info in cursor.fetchall()]
            if "details" not in columns:
                cursor.execute("ALTER TABLE phishing_history ADD COLUMN details TEXT")
            if "reasons" not in columns:
                cursor.execute("ALTER TABLE phishing_history ADD COLUMN reasons TEXT")
                
            self.conn.commit()
        except sqlite3.Error as e:
            QMessageBox.critical(self, "Database Error", f"Failed to init database: {e}")

    def setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(15)

        # --- Input Section ---
        input_group = QGroupBox("🔍 URL Scanner")
        input_layout = QHBoxLayout(input_group)
        
        self.url_input = QLineEdit()
        self.url_input.setPlaceholderText("🌐 Enter URL to scan (e.g., http://example.com)...")
        self.url_input.setClearButtonEnabled(True)
        input_layout.addWidget(self.url_input)

        self.btn_scan = QPushButton("🔍 Scan URL")
        self.btn_scan.setObjectName("BtnPrimary")
        self.btn_scan.clicked.connect(self.start_scan)
        input_layout.addWidget(self.btn_scan)
        
        self.btn_batch = QPushButton("📂 Import Batch")
        self.btn_batch.setObjectName("BtnSecondary")
        self.btn_batch.clicked.connect(self.import_batch)
        input_layout.addWidget(self.btn_batch)

        layout.addWidget(input_group)

        # --- Result Section ---
        self.result_frame = QFrame()
        self.result_frame.setObjectName("CardContainer")
        self.result_frame.hide() # Hidden until scan
        
        res_layout = QVBoxLayout(self.result_frame)
        
        # Header
        self.lbl_threat_level = QLabel("🛡️ Threat Level: -")
        self.lbl_threat_level.setObjectName("ThreatLabel")
        self.lbl_threat_level.setAlignment(Qt.AlignmentFlag.AlignCenter)
        res_layout.addWidget(self.lbl_threat_level)

        # Score Bar
        self.score_bar = QProgressBar()
        self.score_bar.setObjectName("ScoreBar")
        self.score_bar.setTextVisible(True)
        self.score_bar.setFormat("Risk Score: %p%")
        self.score_bar.setFixedHeight(20)
        res_layout.addWidget(self.score_bar)

        # Details
        details_layout = QHBoxLayout()
        self.lbl_method = QLabel("⚙️ Method: -")
        self.lbl_timestamp = QLabel("🕒 Time: -")
        details_layout.addWidget(self.lbl_method)
        details_layout.addStretch()
        details_layout.addWidget(self.lbl_timestamp)
        res_layout.addLayout(details_layout)

        # Reasons
        self.lbl_reasons = QLabel("📝 Reasons: -")
        self.lbl_reasons.setWordWrap(True)
        self.lbl_reasons.setObjectName("ReasonLabel")
        res_layout.addWidget(self.lbl_reasons)

        # URL Details
        self.lbl_details = QLabel("ℹ️ URL Details: -")
        self.lbl_details.setWordWrap(True)
        self.lbl_details.setObjectName("DetailsLabel")
        res_layout.addWidget(self.lbl_details)

        layout.addWidget(self.result_frame)

        # --- History Section ---
        hist_group = QGroupBox("📜 Scan History")
        hist_main_layout = QHBoxLayout(hist_group)

        # Left: Table & Controls
        hist_left_widget = QWidget()
        hist_layout = QVBoxLayout(hist_left_widget)
        hist_layout.setContentsMargins(0, 0, 0, 0)

        # Controls
        hist_controls = QHBoxLayout()
        self.progress_bar = QProgressBar()
        self.progress_bar.hide()
        hist_controls.addWidget(self.progress_bar)

        self.btn_export = QPushButton("💾 Export History")
        self.btn_export.setObjectName("BtnWarning")
        self.btn_export.clicked.connect(self.export_history)
        hist_controls.addWidget(self.btn_export)
        
        self.btn_reset = QPushButton("🗑️ Clear History")
        self.btn_reset.setObjectName("BtnDanger")
        self.btn_reset.clicked.connect(self.clear_history)
        hist_controls.addWidget(self.btn_reset)
        hist_controls.addStretch()
        hist_layout.addLayout(hist_controls)

        # Table
        self.table = QTableWidget()
        self.table.setColumnCount(4)
        self.table.setHorizontalHeaderLabels(["🕒 Timestamp", "🌐 URL", "🛡️ Threat Level", "📊 Score"])
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch) # URL stretches
        self.table.setAlternatingRowColors(True)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.verticalHeader().setVisible(False)
        
        hist_layout.addWidget(self.table)
        
        hist_main_layout.addWidget(hist_left_widget, 3)

        # Right: Statistics Chart
        self.stats_chart = PhishingStatsChart()
        hist_main_layout.addWidget(self.stats_chart, 1)

        layout.addWidget(hist_group, 1) # Give history more space

        # Load initial history
        self.load_history()

    def reset_ui(self):
        """Clears all inputs and results to start fresh."""
        self.url_input.clear()
        self.result_frame.hide()
        self.progress_bar.hide()
        self.progress_bar.setValue(0)

    def start_scan(self):
        url = self.url_input.text().strip()
        if not url:
            QMessageBox.warning(self, "Input Error", "Please enter a valid URL.")
            return

        # Basic validation
        if not (url.startswith("http://") or url.startswith("https://")):
            url = "http://" + url
            self.url_input.setText(url)

        self.btn_scan.setEnabled(False)
        self.btn_scan.setText("Scanning...")
        
        # Start Worker
        self.worker = PhishingScannerWorker(url)
        self.worker.scan_complete.connect(self.on_scan_complete)
        self.worker.error_occurred.connect(self.on_scan_error)
        self.worker.start()

    def on_scan_complete(self, result):
        self.btn_scan.setEnabled(True)
        self.btn_scan.setText("🔍 Scan URL")
        self.display_result(result)
        self.save_result(result)
        self.load_history() # Refresh table

    def on_scan_error(self, error_msg):
        self.btn_scan.setEnabled(True)
        self.btn_scan.setText("🔍 Scan URL")
        QMessageBox.critical(self, "Scan Error", f"An error occurred: {error_msg}")

    def import_batch(self):
        path, _ = QFileDialog.getOpenFileName(self, "Import URLs", "", "Text Files (*.txt)")
        if not path:
            return

        try:
            with open(path, 'r') as f:
                urls = [line.strip() for line in f if line.strip()]
            
            if not urls:
                QMessageBox.warning(self, "Empty File", "No URLs found in file.")
                return

            self.progress_bar.show()
            self.progress_bar.setValue(0)
            self.btn_batch.setEnabled(False)
            
            self.batch_worker = BatchPhishingWorker(urls)
            self.batch_worker.progress.connect(lambda c, t: self.progress_bar.setValue(int((c/t)*100)))
            self.batch_worker.result_ready.connect(self.save_result) # Save silently
            self.batch_worker.finished_batch.connect(self.on_batch_complete)
            self.batch_worker.start()
            
        except Exception as e:
            QMessageBox.critical(self, "Import Error", str(e))

    def on_batch_complete(self):
        self.btn_batch.setEnabled(True)
        self.progress_bar.hide()
        self.load_history()
        QMessageBox.information(self, "Batch Complete", "Batch scan finished successfully.")

    def display_result(self, result):
        self.result_frame.show()
        
        level = result['level']
        score = result['score']
        
        # Update Labels
        self.lbl_threat_level.setText(f"🛡️ Threat Level: {level}")
        self.lbl_method.setText(f"⚙️ Method: {result['method']}")
        self.lbl_timestamp.setText(f"🕒 Time: {result['timestamp']}")
        
        reasons_text = " • ".join(result['reasons']) if result['reasons'] else "No specific threats detected."
        self.lbl_reasons.setText(f"📝 Analysis: {reasons_text}")

        # Display Details
        details = result.get('details', {})
        detail_html = "<b>URL Details:</b><br>"
        for k, v in details.items():
            if v:
                detail_html += f"<b>{k}:</b> {v}<br>"
        self.lbl_details.setText(detail_html)

        # Styling based on risk
        safe_level = level.replace(" ", "")
        self.score_bar.setValue(int(score))
        self.score_bar.setProperty("risk", safe_level)
        self.lbl_threat_level.setProperty("risk", safe_level)
        
        self.score_bar.style().unpolish(self.score_bar); self.score_bar.style().polish(self.score_bar)
        self.lbl_threat_level.style().unpolish(self.lbl_threat_level); self.lbl_threat_level.style().polish(self.lbl_threat_level)

    def save_result(self, result):
        try:
            cursor = self.conn.cursor()
            details_json = json.dumps(result.get('details', {}))
            reasons_json = json.dumps(result.get('reasons', []))
            
            cursor.execute("INSERT INTO phishing_history (url, threat_level, score, timestamp, details, reasons) VALUES (?, ?, ?, ?, ?, ?)",
                           (result['url'], result['level'], result['score'], result['timestamp'], details_json, reasons_json))
            self.conn.commit()
        except sqlite3.Error as e:
            print(f"DB Save Error: {e}")

    def load_history(self):
        try:
            cursor = self.conn.cursor()
            cursor.execute("SELECT timestamp, url, threat_level, score FROM phishing_history ORDER BY id DESC")
            rows = cursor.fetchall()
            
            stats = {"Safe": 0, "Low Risk": 0, "Medium Risk": 0, "High Risk": 0}
            
            self.table.setRowCount(len(rows))
            for i, row in enumerate(rows):
                self.table.setItem(i, 0, QTableWidgetItem(row[0]))
                self.table.setItem(i, 1, QTableWidgetItem(row[1]))
                
                level_item = QTableWidgetItem(row[2])
                if "High" in row[2]:
                    stats["High Risk"] += 1
                    level_item.setForeground(QBrush(QColor("#dc3545")))
                elif "Medium" in row[2]:
                    stats["Medium Risk"] += 1
                    level_item.setForeground(QBrush(QColor("#ffc107")))
                elif "Low" in row[2]:
                    stats["Low Risk"] += 1
                    level_item.setForeground(QBrush(QColor("#17a2b8")))
                elif "Safe" in row[2]:
                    stats["Safe"] += 1
                    level_item.setForeground(QBrush(QColor("#28a745")))
                self.table.setItem(i, 2, level_item)
                
                self.table.setItem(i, 3, QTableWidgetItem(f"{row[3]:.1f}"))
            
            self.stats_chart.update_stats(stats)
            
        except sqlite3.Error:
            pass

    def clear_history(self):
        reply = QMessageBox.question(self, "Confirm", "Clear all scan history?", 
                                     QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if reply == QMessageBox.StandardButton.Yes:
            try:
                self.conn.cursor().execute("DELETE FROM phishing_history")
                self.conn.commit()
                self.load_history()
            except sqlite3.Error as e:
                QMessageBox.warning(self, "Error", str(e))

    def export_history(self):
        import tempfile
        import os
        
        try:
            # Create a temporary unencrypted PDF
            temp_fd, temp_path = tempfile.mkstemp(suffix=".pdf")
            os.close(temp_fd)
            
            printer = QPrinter(QPrinter.PrinterMode.HighResolution)
            printer.setOutputFormat(QPrinter.OutputFormat.PdfFormat)
            printer.setOutputFileName(temp_path)

            cursor = self.conn.cursor()
            cursor.execute("SELECT timestamp, url, threat_level, score, details, reasons FROM phishing_history ORDER BY id DESC")
            rows = cursor.fetchall()

            html = "<h1>Phishing Scan History</h1><table border='1' cellspacing='0' cellpadding='5' width='100%'>"
            html += "<thead><tr><th>Time</th><th>URL</th><th>Threat Level</th><th>Score</th><th>Analysis Details</th></tr></thead><tbody>"
            for row in rows:
                ts, url, level, score, details_json, reasons_json = row
                
                analysis_html = ""
                
                # Parse Reasons
                if reasons_json:
                    try:
                        reasons = json.loads(reasons_json)
                        if reasons:
                            analysis_html += "<b>Reasons:</b><br>" + "<br>".join(f"• {r}" for r in reasons) + "<br><br>"
                    except:
                        pass
                
                # Parse Details
                if details_json:
                    try:
                        details = json.loads(details_json)
                        if details:
                            analysis_html += "<b>URL Details:</b><br>"
                            for k, v in details.items():
                                if v:
                                    analysis_html += f"<b>{k}:</b> {v}<br>"
                    except:
                        pass

                html += f"<tr><td>{ts}</td><td>{url}</td><td>{level}</td><td>{score:.1f}</td><td>{analysis_html}</td></tr>"
            html += "</tbody></table>"

            doc = QTextDocument()
            doc.setHtml(html)
            doc.print(printer)
            
            # Read back bytes and pipe into Secure Vault FMS
            with open(temp_path, "rb") as f:
                pdf_bytes = f.read()
            os.remove(temp_path)
            
            if self.session and hasattr(self.session, 'file_manager'):
                self.session.file_manager.export_file(
                    filename="phishing_history.pdf", 
                    content=pdf_bytes, 
                    module_source="Phishing Detector", 
                    file_type="PDF", 
                    tags="Warning"
                )
                QMessageBox.information(self, "Vaulted", "Phishing History PDF securely vaulted in FMS.")
            else:
                QMessageBox.warning(self, "Warning", "FMS not available, file not saved.")
                
        except Exception as e:
            QMessageBox.critical(self, "Export Error", str(e))