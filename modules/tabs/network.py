import psutil
import socket
import time
import math
import os
import sys
import hashlib
import datetime
import re
import threading
from collections import deque
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QTableWidget, QTableWidgetItem,
    QPushButton, QLineEdit, QLabel, QHeaderView, QComboBox, QGroupBox,
    QAbstractItemView, QMessageBox, QFrame, QGridLayout, QToolTip,
    QFileDialog, QTextEdit, QApplication
)
from PyQt6.QtCore import Qt, QTimer, QThread, pyqtSignal, QRectF, QSizeF
from PyQt6.QtGui import (
    QColor, QBrush, QPainter, QPainterPath, QLinearGradient, QRadialGradient,
    QPen, QFont, QPalette, QTextDocument, QPageSize
)
from PyQt6.QtPrintSupport import QPrinter

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from database import DatabaseManager

# --- Constants ---
REFRESH_INTERVAL = 1500  # 1.5s interval for smooth UI and low compute overhead

class SortableTableWidgetItem(QTableWidgetItem):
    """Custom table item to support natural numeric and alphanumeric sorting."""
    def __lt__(self, other):
        val1 = self.data(Qt.ItemDataRole.UserRole)
        val2 = other.data(Qt.ItemDataRole.UserRole)
        if val1 is not None and val2 is not None:
            try:
                return float(val1) < float(val2)
            except (ValueError, TypeError):
                return str(val1) < str(val2)
        return super().__lt__(other)

class NetworkIntelligenceEngine:
    """
    High-performance network intelligence & threat scoring engine.
    Provides fast GeoIP heuristics, cloud provider ASN mapping,
    cached non-blocking reverse DNS resolution, and behavioral threat scoring.
    """
    _dns_cache = {}
    _dns_queue = deque(maxlen=200)
    _dns_worker_running = False
    _dns_lock = threading.Lock()

    WELL_KNOWN_PORTS = {
        80: ("HTTP", "Standard Unencrypted Web Traffic", 2),
        443: ("HTTPS", "Encrypted TLS/SSL Secure Web Traffic", 1),
        53: ("DNS", "Domain Name System Resolution", 1),
        123: ("NTP", "Network Time Protocol Synchronization", 1),
        22: ("SSH", "Secure Shell Remote Administration", 2),
        21: ("FTP", "File Transfer Protocol (Unencrypted)", 3),
        23: ("Telnet", "Insecure Unencrypted Remote Shell", 4),
        25: ("SMTP", "Simple Mail Transfer Protocol", 2),
        110: ("POP3", "Post Office Protocol Mail Fetch", 2),
        143: ("IMAP", "Internet Message Access Protocol", 2),
        465: ("SMTPS", "Secure Encrypted Mail Submission", 1),
        993: ("IMAPS", "Secure Encrypted Mail Sync", 1),
        995: ("POP3S", "Secure Encrypted Mail Fetch", 1),
        135: ("RPC", "Windows Remote Procedure Call Endpoint", 3),
        137: ("NetBIOS-NS", "NetBIOS Name Service", 3),
        138: ("NetBIOS-DGM", "NetBIOS Datagram Service", 3),
        139: ("NetBIOS-SSN", "NetBIOS Session Service", 3),
        445: ("SMB", "Server Message Block (High Attack Target)", 4),
        1433: ("MSSQL", "Microsoft SQL Server Database Port", 3),
        1521: ("Oracle", "Oracle Database Listener Port", 3),
        3306: ("MySQL", "MySQL Relational Database Service", 3),
        3389: ("RDP", "Remote Desktop Protocol (High Attack Target)", 4),
        5432: ("PostgreSQL", "PostgreSQL Database Service", 3),
        5900: ("VNC", "Virtual Network Computing Remote Display", 4),
        6379: ("Redis", "In-Memory Key-Value Data Store", 4),
        8080: ("HTTP-Proxy", "Alternative HTTP Web / Proxy Service", 2),
        8443: ("HTTPS-Alt", "Alternative Secure HTTPS Web Service", 2),
        27017: ("MongoDB", "MongoDB NoSQL Database Daemon", 4),
        # C2 & Malicious Defaults
        4444: ("Metasploit", "Metasploit Default Listener / Reverse Shell", 5),
        1337: ("Elite/C2", "Custom Hacker / C2 Listener Port", 5),
        3333: ("Stratum", "Cryptocurrency Mining Pool Stratum Protocol", 4),
        6667: ("IRC", "Internet Relay Chat (Botnet C2 Channel)", 4),
        7777: ("Backdoor", "Remote Access Trojan Listener Port", 5),
        8888: ("Alt-C2", "Alternative Web Port / C2 Reverse Proxy", 3),
        9999: ("Trojan-Port", "Common Remote Trojan Listener Port", 5),
        31337: ("BackOrifice", "Back Orifice Trojan Default Port", 5),
    }

    @staticmethod
    def is_private_ip(ip):
        if not ip or ip in ('-', '0.0.0.0', '127.0.0.1', '::1', '::'):
            return True
        try:
            parts = [int(p) for p in ip.split('.')]
            if len(parts) == 4:
                if parts[0] == 10: return True
                if parts[0] == 127: return True
                if parts[0] == 172 and 16 <= parts[1] <= 31: return True
                if parts[0] == 192 and parts[1] == 168: return True
                if parts[0] == 169 and parts[1] == 254: return True
        except Exception:
            pass
        return False

    @classmethod
    def queue_reverse_dns(cls, ip):
        if not ip or ip in ('-', '0.0.0.0', '127.0.0.1') or cls.is_private_ip(ip):
            return
        with cls._dns_lock:
            if ip in cls._dns_cache:
                return
            if ip not in cls._dns_queue:
                cls._dns_queue.append(ip)
            if not cls._dns_worker_running:
                cls._dns_worker_running = True
                threading.Thread(target=cls._dns_worker_loop, daemon=True).start()

    @classmethod
    def _dns_worker_loop(cls):
        while True:
            target_ip = None
            with cls._dns_lock:
                if cls._dns_queue:
                    target_ip = cls._dns_queue.popleft()
                else:
                    cls._dns_worker_running = False
                    break
            if target_ip:
                try:
                    hostname = socket.gethostbyaddr(target_ip)[0]
                except Exception:
                    hostname = "-"
                with cls._dns_lock:
                    cls._dns_cache[target_ip] = hostname
            time.sleep(0.05)

    @classmethod
    def resolve_ip_intel(cls, ip):
        """Returns (country_code, flag_emoji, org_name, is_private, reverse_dns)."""
        if not ip or ip in ('-', '0.0.0.0'):
            return ("-", "🌐", "Local Machine / Any", True, "-")
        if ip in ('127.0.0.1', '::1'):
            return ("LOCAL", "🏠", "Loopback / Internal Host", True, "localhost")
        if cls.is_private_ip(ip):
            return ("LAN", "🏠", "Private Local Network (LAN)", True, "local.network")

        org_name = "Public Internet WAN"
        country = "WAN"
        flag = "🌐"

        parts = ip.split('.')
        if len(parts) == 4:
            try:
                p0, p1 = int(parts[0]), int(parts[1])
                # Google
                if (p0 == 8 and p1 == 8) or (p0 == 142 and p1 == 250) or (p0 == 172 and p1 == 217) or (p0 == 74 and p1 == 125):
                    org_name = "Google Cloud / Services"
                    country = "US"
                    flag = "🇺🇸"
                # Cloudflare
                elif (p0 == 1 and p1 == 1) or (p0 == 104 and 16 <= p1 <= 28) or (p0 == 172 and 64 <= p1 <= 71):
                    org_name = "Cloudflare Edge CDN"
                    country = "US"
                    flag = "🌐"
                # Microsoft / Azure
                elif p0 in (13, 20, 40, 52):
                    org_name = "Microsoft Azure Cloud"
                    country = "US"
                    flag = "🇺🇸"
                # Amazon AWS
                elif p0 in (3, 18, 34, 54):
                    org_name = "Amazon Web Services (AWS)"
                    country = "US"
                    flag = "🇺🇸"
                # Akamai
                elif p0 == 23 or (p0 == 104 and p1 > 64):
                    org_name = "Akamai Technologies CDN"
                    country = "US"
                    flag = "🌐"
                # Fastly
                elif (p0 == 151 and p1 == 101) or (p0 == 199 and p1 == 232):
                    org_name = "Fastly Edge CDN"
                    country = "US"
                    flag = "🌐"
                # GitHub
                elif p0 == 140 and p1 == 82:
                    org_name = "GitHub Infrastructure"
                    country = "US"
                    flag = "🇺🇸"
                # Quad9
                elif p0 == 9 and p1 == 9:
                    org_name = "Quad9 Anycast DNS"
                    country = "CH"
                    flag = "🇨🇭"
            except Exception:
                pass

        # Check background reverse DNS cache
        rdns = cls._dns_cache.get(ip, None)
        if rdns is None:
            cls.queue_reverse_dns(ip)
            rdns = "-"

        return (country, flag, org_name, False, rdns)

    @classmethod
    def evaluate_threat(cls, conn, proc_name, exe_path=""):
        """
        Evaluates socket threat level from 1 (Safe) to 5 (Critical).
        Returns: (level, label, color, reasoning, score_pct)
        """
        raddr = conn.get('raddr')
        rip = getattr(raddr, 'ip', None) if raddr else None
        rport = getattr(raddr, 'port', 0) if raddr else 0
        laddr = conn.get('laddr')
        lport = getattr(laddr, 'port', 0) if laddr else 0
        status = conn.get('status', '')

        is_priv_remote = cls.is_private_ip(rip)
        path_lower = (exe_path or "").lower()
        proc_lower = (proc_name or "").lower()

        # 1. Critical Threats (Level 5)
        if rport in (4444, 1337, 7777, 9999, 31337):
            return (
                5, "L5 ◆ CRITICAL", "#ef4444",
                f"Outbound connection communicates with known adversary/Metasploit C2 port ({rport}). High confidence backdoor or reverse shell payload.",
                "98%"
            )
        if 'malware' in proc_lower or 'exploit' in proc_lower:
            return (
                5, "L5 ◆ CRITICAL", "#ef4444",
                f"Process name '{proc_name}' matches blacklisted threat pattern with active network transmission.",
                "96%"
            )

        # 2. High Risk (Level 4)
        if rport in (3333, 14444, 18080):
            return (
                4, "L4 ◆ HIGH RISK", "#ea580c",
                f"Connection on port {rport} perfectly matches cryptocurrency mining Stratum pool communications.",
                "88%"
            )
        if rport == 6667:
            return (
                4, "L4 ◆ HIGH RISK", "#ea580c",
                "Connection communicates over IRC port 6667, traditionally leveraged by botnet command-and-control masters.",
                "85%"
            )
        if not is_priv_remote and rport in (445, 135, 137, 138, 139):
            return (
                4, "L4 ◆ HIGH RISK", "#ea580c",
                f"SMB / Windows NetBIOS protocol ({rport}) established over public WAN. Vulnerable to remote credential relay and EternalBlue exploits.",
                "84%"
            )
        if not is_priv_remote and rport == 23:
            return (
                4, "L4 ◆ HIGH RISK", "#ea580c",
                "Cleartext Telnet transmission over public WAN. Credentials and terminal sessions are vulnerable to interception.",
                "82%"
            )
        if ('temp' in path_lower or 'appdata' in path_lower) and not is_priv_remote and rport not in (80, 443, 53):
            return (
                4, "L4 ◆ HIGH RISK", "#ea580c",
                f"Executable running from unverified user AppData/Temp path is establishing non-standard WAN sockets (Port {rport}).",
                "80%"
            )

        # 3. Suspicious (Level 3)
        if status == 'LISTEN' and lport in (4444, 1337, 7777, 8888, 9999):
            return (
                3, "L3 ◆ SUSPICIOUS", "#f59e0b",
                f"Local socket is listening on atypical high port ({lport}) without verified system service assignment.",
                "65%"
            )
        if not is_priv_remote and rport > 1024 and rport not in (8080, 8443):
            return (
                3, "L3 ◆ SUSPICIOUS", "#f59e0b",
                f"Connection established to remote ephemeral port ({rport}) on unclassified public IP. Monitored for anomalous data exfiltration.",
                "58%"
            )

        # 4. Normal Web Activity (Level 2)
        if not is_priv_remote and rport in (80, 443, 8080, 8443, 53, 123):
            return (
                2, "L2 ◆ NORMAL", "#0ea5e9",
                f"Standard outbound internet session over port {rport}. Traffic conforms to standard web and DNS infrastructure.",
                "20%"
            )

        # 5. Verified / Safe (Level 1)
        return (
            1, "L1 ◆ VERIFIED", "#10b981",
            "Internal communication strictly contained within local loopback or private trusted network boundary.",
            "5%"
        )

class NetworkWorker(QThread):
    """
    Background worker thread to harvest network sockets, interface I/O,
    packet error metrics, and process associations asynchronously.
    """
    data_fetched = pyqtSignal(dict)

    def run(self):
        # 1. Fetch Process PID Mapping
        pid_map = {}
        try:
            for p in psutil.process_iter(['pid', 'name', 'exe', 'username']):
                try:
                    pid_map[p.info['pid']] = {
                        'name': p.info['name'] or f"PID {p.info['pid']}",
                        'exe': p.info['exe'] or "N/A",
                        'user': p.info['username'] or "System"
                    }
                except Exception:
                    pass
        except Exception:
            pass

        # 2. Fetch Connections (TCP, UDP, RAW)
        connections = []
        listening_count = 0
        established_count = 0
        protocol_counts = {
            "TCP": 0, "UDP": 0, "HTTPS": 0, "HTTP": 0, "DNS": 0,
            "SSH": 0, "RDP": 0, "SMB": 0, "DB": 0, "ICMP": 0, "Other": 0
        }

        try:
            for conn in psutil.net_connections(kind='all'):
                try:
                    if (hasattr(socket, 'AF_UNIX') and conn.family == socket.AF_UNIX) or \
                       (hasattr(socket, 'AF_PACKET') and conn.family == socket.AF_PACKET):
                        continue

                    p_info = pid_map.get(conn.pid, {'name': '-', 'exe': '-', 'user': '-'})
                    proc_name = p_info['name']
                    exe_path = p_info['exe']
                    username = p_info['user']

                    # Protocol Classification across all protocol types
                    lport = getattr(conn.laddr, 'port', 0) if conn.laddr else 0
                    rport = getattr(conn.raddr, 'port', 0) if conn.raddr else 0
                    is_raw = hasattr(socket, 'SOCK_RAW') and conn.type == socket.SOCK_RAW

                    if is_raw:
                        base_proto = "ICMP"
                        proto_cat = "ICMP"
                        proto_label = "ICMP (Raw)"
                        protocol_counts["ICMP"] += 1
                    else:
                        base_proto = "TCP" if conn.type == socket.SOCK_STREAM else ("UDP" if conn.type == socket.SOCK_DGRAM else "RAW")
                        ports = (lport, rport)

                        if 443 in ports or 8443 in ports:
                            proto_cat = "HTTPS"
                            if base_proto == "UDP":
                                proto_label = "QUIC / HTTP3 (UDP)"
                            else:
                                proto_label = "HTTPS (TCP)"
                            protocol_counts["HTTPS"] += 1
                        elif 80 in ports or 8080 in ports or 8000 in ports or 8888 in ports:
                            proto_cat = "HTTP"
                            proto_label = f"HTTP ({base_proto})"
                            protocol_counts["HTTP"] += 1
                        elif 53 in ports or 853 in ports:
                            proto_cat = "DNS"
                            proto_label = f"DNS ({base_proto})"
                            protocol_counts["DNS"] += 1
                        elif 22 in ports:
                            proto_cat = "SSH"
                            proto_label = f"SSH ({base_proto})"
                            protocol_counts["SSH"] += 1
                        elif 3389 in ports:
                            proto_cat = "RDP"
                            proto_label = f"RDP ({base_proto})"
                            protocol_counts["RDP"] += 1
                        elif 445 in ports or any(p in ports for p in (137, 138, 139)):
                            proto_cat = "SMB"
                            proto_label = f"SMB/NetBIOS ({base_proto})"
                            protocol_counts["SMB"] += 1
                        elif any(p in ports for p in (3306, 5432, 1433, 1521, 6379, 27017)):
                            proto_cat = "DB"
                            proto_label = f"DB ({base_proto})"
                            protocol_counts["DB"] += 1
                        elif 123 in ports:
                            proto_cat = "NTP"
                            proto_label = f"NTP ({base_proto})"
                            protocol_counts["Other"] += 1
                        elif any(p in ports for p in (67, 68)):
                            proto_cat = "DHCP"
                            proto_label = f"DHCP ({base_proto})"
                            protocol_counts["Other"] += 1
                        elif any(p in ports for p in (161, 162)):
                            proto_cat = "SNMP"
                            proto_label = f"SNMP ({base_proto})"
                            protocol_counts["Other"] += 1
                        elif any(p in ports for p in (25, 465, 587, 110, 995, 143, 993)):
                            proto_cat = "Mail"
                            proto_label = f"Mail ({base_proto})"
                            protocol_counts["Other"] += 1
                        elif any(p in ports for p in (20, 21)):
                            proto_cat = "FTP"
                            proto_label = f"FTP ({base_proto})"
                            protocol_counts["Other"] += 1
                        elif any(p in ports for p in (1194, 51820, 500, 4500)):
                            proto_cat = "VPN"
                            proto_label = f"VPN ({base_proto})"
                            protocol_counts["Other"] += 1
                        elif base_proto == "TCP":
                            proto_cat = "TCP"
                            proto_label = "TCP"
                            protocol_counts["TCP"] += 1
                        elif base_proto == "UDP":
                            proto_cat = "UDP"
                            proto_label = "UDP"
                            protocol_counts["UDP"] += 1
                        else:
                            proto_cat = base_proto
                            proto_label = base_proto
                            protocol_counts["Other"] += 1

                    # Accurate connection status determination
                    status_raw = conn.status or ""
                    if base_proto == "UDP":
                        if conn.raddr:
                            status_val = "ESTABLISHED"
                            established_count += 1
                        else:
                            status_val = "ACTIVE"
                            established_count += 1
                            listening_count += 1
                    elif is_raw:
                        status_val = "ACTIVE"
                        established_count += 1
                    else:
                        if status_raw == "LISTEN":
                            status_val = "LISTEN"
                            listening_count += 1
                        elif status_raw in ("ESTABLISHED", "SYN_SENT", "SYN_RECV", "FIN_WAIT1", "FIN_WAIT2", "TIME_WAIT", "CLOSE_WAIT", "LAST_ACK", "CLOSING"):
                            status_val = status_raw
                            established_count += 1
                        else:
                            status_val = status_raw or ("ESTABLISHED" if conn.raddr else "LISTEN")
                            if status_val == "LISTEN":
                                listening_count += 1
                            else:
                                established_count += 1

                    # Threat Evaluation
                    threat_lvl, threat_tag, threat_col, threat_reason, threat_score = NetworkIntelligenceEngine.evaluate_threat(
                        {'laddr': conn.laddr, 'raddr': conn.raddr, 'status': status_val, 'type': conn.type},
                        proc_name, exe_path
                    )

                    # Remote GeoIP Intel
                    rip = getattr(conn.raddr, 'ip', None) if conn.raddr else None
                    country, flag, org, is_priv, rdns = NetworkIntelligenceEngine.resolve_ip_intel(rip)

                    connections.append({
                        'fd': conn.fd,
                        'family': conn.family,
                        'type': conn.type,
                        'proto_label': proto_label,
                        'base_proto': base_proto,
                        'proto_cat': proto_cat,
                        'laddr': conn.laddr,
                        'raddr': conn.raddr,
                        'status': status_val,
                        'pid': conn.pid,
                        'proc_name': proc_name,
                        'exe_path': exe_path,
                        'user': username,
                        'threat_lvl': threat_lvl,
                        'threat_tag': threat_tag,
                        'threat_col': threat_col,
                        'threat_reason': threat_reason,
                        'threat_score': threat_score,
                        'country': country,
                        'flag': flag,
                        'org': org,
                        'is_priv': is_priv,
                        'rdns': rdns
                    })
                except Exception:
                    continue
        except (psutil.AccessDenied, Exception):
            pass

        # 3. Interface IO & Statistics
        io_counters = psutil.net_io_counters(pernic=True)
        if_addrs = psutil.net_if_addrs()
        if_stats = psutil.net_if_stats()

        data = {
            'connections': connections,
            'io_counters': io_counters,
            'if_addrs': if_addrs,
            'if_stats': if_stats,
            'protocol_counts': protocol_counts,
            'listening_count': listening_count,
            'established_count': established_count,
            'timestamp': time.time()
        }
        self.data_fetched.emit(data)

class NetworkChart(QWidget):
    """
    Modern cyber telemetry chart with smooth cubic Bézier curves,
    radial gradient leading glow, and dynamic bandwidth unit scaling.
    """
    def __init__(self, title, line_color="#00c6ff"):
        super().__init__()
        self.title = title
        self.line_color = QColor(line_color)
        self.data = deque([0.0]*60, maxlen=60)
        self.setMinimumHeight(130)
        self.current_value = 0.0
        self.peak_value = 0.0
        self.max_scale = 1024.0  # 1 KB baseline

    def update_value(self, value):
        self.current_value = value
        self.data.append(value)
        if value > self.peak_value:
            self.peak_value = value

        local_max = max(self.data)
        if local_max > self.max_scale:
            self.max_scale = local_max
        elif local_max < self.max_scale * 0.5 and self.max_scale > 1024:
            self.max_scale *= 0.96
        self.update()

    def format_speed(self, bytes_per_sec):
        if bytes_per_sec < 1024:
            return f"{bytes_per_sec:.0f} B/s"
        elif bytes_per_sec < 1024 * 1024:
            return f"{bytes_per_sec / 1024:.1f} KB/s"
        elif bytes_per_sec < 1024 * 1024 * 1024:
            return f"{bytes_per_sec / (1024 * 1024):.2f} MB/s"
        else:
            return f"{bytes_per_sec / (1024 * 1024 * 1024):.2f} GB/s"

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        w = self.width()
        h = self.height()
        top_pad = 36
        bottom_pad = 22
        chart_h = max(h - top_pad - bottom_pad, 10)

        # Background
        is_dark = self.palette().color(QPalette.ColorRole.Window).lightness() < 128
        bg_color = QColor("#111726") if is_dark else QColor("#ffffff")
        border_col = QColor("#1e293b") if is_dark else QColor("#e2e8f0")
        text_col = self.palette().color(QPalette.ColorRole.WindowText)

        painter.fillRect(0, 0, w, h, bg_color)
        painter.setPen(QPen(border_col, 1))
        painter.drawRect(0, 0, w - 1, h - 1)

        scale_max = max(self.max_scale, 1024.0)
        step_x = (w - 20) / (self.data.maxlen - 1) if self.data.maxlen > 1 else w

        # Draw Grid Lines
        grid_col = QColor(255, 255, 255, 12) if is_dark else QColor(0, 0, 0, 15)
        painter.setPen(QPen(grid_col, 1, Qt.PenStyle.DashLine))
        for i in range(1, 3):
            y_line = top_pad + i * (chart_h / 3)
            painter.drawLine(10, int(y_line), w - 10, int(y_line))

        # Build Bézier Path
        if len(self.data) > 1:
            path = QPainterPath()
            first_x = 10
            first_y = top_pad + chart_h - (self.data[0] / scale_max * chart_h)
            path.moveTo(first_x, first_y)

            prev_x, prev_y = first_x, first_y
            for i in range(1, len(self.data)):
                x = 10 + i * step_x
                y = top_pad + chart_h - (self.data[i] / scale_max * chart_h)
                ctrl_x1 = prev_x + (x - prev_x) * 0.5
                ctrl_y1 = prev_y
                ctrl_x2 = prev_x + (x - prev_x) * 0.5
                ctrl_y2 = y
                path.cubicTo(ctrl_x1, ctrl_y1, ctrl_x2, ctrl_y2, x, y)
                prev_x, prev_y = x, y

            # Fill Area under the curve
            fill_path = QPainterPath(path)
            fill_path.lineTo(prev_x, top_pad + chart_h)
            fill_path.lineTo(10, top_pad + chart_h)
            fill_path.closeSubpath()

            grad = QLinearGradient(0, top_pad, 0, top_pad + chart_h)
            c = self.line_color
            grad.setColorAt(0, QColor(c.red(), c.green(), c.blue(), 110))
            grad.setColorAt(1, QColor(c.red(), c.green(), c.blue(), 5))
            painter.setBrush(grad)
            painter.setPen(Qt.PenStyle.NoPen)
            painter.drawPath(fill_path)

            # Draw Line
            painter.setPen(QPen(self.line_color, 2.5, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap, Qt.PenJoinStyle.RoundJoin))
            painter.setBrush(Qt.BrushStyle.NoBrush)
            painter.drawPath(path)

            # Draw Leading Glow Dot
            glow = QRadialGradient(prev_x, prev_y, 16)
            glow.setColorAt(0, QColor(c.red(), c.green(), c.blue(), 180))
            glow.setColorAt(1, Qt.GlobalColor.transparent)
            painter.setBrush(glow)
            painter.setPen(Qt.PenStyle.NoPen)
            painter.drawEllipse(int(prev_x - 16), int(prev_y - 16), 32, 32)

            painter.setBrush(c)
            painter.setPen(QPen(Qt.GlobalColor.white, 2))
            painter.drawEllipse(int(prev_x - 4), int(prev_y - 4), 8, 8)

        # Header Titles & Readouts
        painter.setPen(text_col)
        painter.setFont(QFont("Segoe UI", 10, QFont.Weight.Bold))
        painter.drawText(12, 22, self.title)

        cur_text = self.format_speed(self.current_value)
        painter.setFont(QFont("Segoe UI", 11, QFont.Weight.Bold))
        painter.setPen(self.line_color)
        cur_w = painter.fontMetrics().horizontalAdvance(cur_text)
        painter.drawText(w - cur_w - 12, 22, cur_text)

        # Peak watermark (clean and safe from curve collisions)
        painter.setFont(QFont("Segoe UI", 8))
        painter.setPen(QColor(148, 163, 184, 160))
        peak_str = f"Peak: {self.format_speed(self.peak_value)}"
        painter.drawText(12, h - 6, peak_str)

class ProtocolPieChart(QWidget):
    """
    Modern glassmorphic cyber donut chart with hover tooltips,
    percentage breakdown, and centered active socket counters.
    """
    def __init__(self):
        super().__init__()
        self.setMinimumSize(140, 130)
        self.counts = {
            "TCP": 0, "UDP": 0, "HTTPS": 0, "HTTP": 0, "DNS": 0,
            "SSH": 0, "RDP": 0, "SMB": 0, "DB": 0, "ICMP": 0, "Other": 0
        }
        self.colors = {
            "TCP": QColor("#0ea5e9"),     # Sky Blue
            "UDP": QColor("#f59e0b"),     # Amber
            "HTTPS": QColor("#8b5cf6"),   # Purple
            "HTTP": QColor("#10b981"),    # Emerald
            "DNS": QColor("#06b6d4"),     # Cyan
            "SSH": QColor("#ec4899"),     # Pink
            "RDP": QColor("#f97316"),     # Orange
            "SMB": QColor("#e11d48"),     # Rose
            "DB": QColor("#a855f7"),      # Violet
            "ICMP": QColor("#14b8a6"),    # Teal
            "Other": QColor("#64748b")    # Slate
        }
        self.title = "🔌 Protocol Breakdown"
        self.setMouseTracking(True)

    def update_counts(self, counts_dict):
        self.counts = counts_dict
        self.update()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        w = self.width()
        h = self.height()
        is_dark = self.palette().color(QPalette.ColorRole.Window).lightness() < 128
        bg_color = QColor("#111726") if is_dark else QColor("#ffffff")
        border_col = QColor("#1e293b") if is_dark else QColor("#e2e8f0")
        text_col = self.palette().color(QPalette.ColorRole.WindowText)

        painter.fillRect(0, 0, w, h, bg_color)
        painter.setPen(QPen(border_col, 1))
        painter.drawRect(0, 0, w - 1, h - 1)

        painter.setPen(text_col)
        painter.setFont(QFont("Segoe UI", 10, QFont.Weight.Bold))
        painter.drawText(12, 22, self.title)

        # Donut dimensions
        chart_size = min(w - 20, h - 45)
        rect = QRectF((w - chart_size) / 2, 30, chart_size, chart_size)
        total = sum(self.counts.values())

        if total == 0:
            painter.setBrush(QColor(100, 116, 139, 40))
            painter.setPen(Qt.PenStyle.NoPen)
            painter.drawEllipse(rect)
        else:
            start_angle = 90 * 16
            for proto, count in self.counts.items():
                if count > 0:
                    span = int((count / total) * 360 * 16)
                    painter.setBrush(self.colors.get(proto, QColor("#64748b")))
                    painter.setPen(Qt.PenStyle.NoPen)
                    painter.drawPie(rect, start_angle, span)
                    start_angle += span

        # Inner Hole
        inner_size = chart_size * 0.65
        inner_rect = QRectF((w - inner_size) / 2, 30 + (chart_size - inner_size) / 2, inner_size, inner_size)
        painter.setBrush(bg_color)
        painter.setPen(Qt.PenStyle.NoPen)
        painter.drawEllipse(inner_rect)

        # Center Text
        painter.setPen(text_col)
        painter.setFont(QFont("Segoe UI", 11, QFont.Weight.Bold))
        painter.drawText(inner_rect, Qt.AlignmentFlag.AlignCenter, f"{total}\nSockets")

    def mouseMoveEvent(self, event):
        total = sum(self.counts.values())
        if total == 0:
            return super().mouseMoveEvent(event)

        pos = event.pos()
        w, h = self.width(), self.height()
        chart_size = min(w - 20, h - 45)
        rect = QRectF((w - chart_size) / 2, 30, chart_size, chart_size)
        center = rect.center()
        dx = pos.x() - center.x()
        dy = pos.y() - center.y()
        distance = math.hypot(dx, dy)

        inner_radius = (chart_size * 0.65) / 2
        outer_radius = chart_size / 2

        if inner_radius <= distance <= outer_radius:
            angle = math.degrees(math.atan2(-dy, dx))
            if angle < 0: angle += 360
            mapped = (angle - 90) % 360

            cur = 0
            for proto, count in self.counts.items():
                if count > 0:
                    span = (count / total) * 360
                    if cur <= mapped <= cur + span:
                        pct = (count / total) * 100
                        QToolTip.showText(event.globalPosition().toPoint(), f"<b>{proto}</b><br>Sockets: {count}<br>Share: {pct:.1f}%", self)
                        return
                    cur += span

        QToolTip.hideText()
        super().mouseMoveEvent(event)

class NetworkSocketForensicWorker(QThread):
    """
    Asynchronous forensic investigator for active network connections.
    Extracts deep endpoint binary signatures, reverse DNS, GeoIP ASN records,
    and formats print-calibrated executive PDF reports.
    """
    forensics_ready = pyqtSignal(dict, str, str, str, str)  # conn_dict, html_rep, pdf_rep, text_rep, safe_name

    def __init__(self, conn, is_dark):
        super().__init__()
        self.conn = conn
        self.is_dark = is_dark

    def run(self):
        try:
            conn = self.conn
            pid = conn.get('pid')
            proc_name = conn.get('proc_name', '-')
            exe_path = conn.get('exe_path', '-')
            user = conn.get('user', 'System')
            proto = conn.get('proto_label', 'TCP')
            status = conn.get('status', 'ESTABLISHED')
            laddr = conn.get('laddr')
            raddr = conn.get('raddr')

            lip = getattr(laddr, 'ip', '-') if laddr else "-"
            lport = getattr(laddr, 'port', 0) if laddr else 0
            rip = getattr(raddr, 'ip', '-') if raddr else "-"
            rport = getattr(raddr, 'port', 0) if raddr else 0

            # Binary Hash & Lineage
            sha256 = "N/A (Virtual or Inaccessible)"
            file_size_str = "N/A"
            parent_name = "N/A"
            cmdline = "-"
            priority_str = "Normal"

            if pid:
                try:
                    p = psutil.Process(pid)
                    try:
                        parent = p.parent()
                        parent_name = f"{parent.name()} (PID: {p.ppid()})" if parent else f"PID: {p.ppid()}"
                    except Exception:
                        parent_name = "System Root / Standalone"
                    try:
                        cmd = p.cmdline()
                        cmdline = " ".join(cmd) if cmd else exe_path
                    except Exception:
                        cmdline = exe_path
                    try:
                        p_nice = p.nice()
                        priority_str = f"Priority {p_nice}"
                    except Exception:
                        pass
                except Exception:
                    pass

            if exe_path and os.path.exists(exe_path):
                try:
                    sz = os.path.getsize(exe_path)
                    file_size_str = f"{sz / (1024*1024):.2f} MB ({sz:,} bytes)"
                    if sz <= 30 * 1024 * 1024:
                        with open(exe_path, "rb") as f:
                            sha256 = hashlib.sha256(f.read()).hexdigest()
                    else:
                        sha256 = f"Size {file_size_str} exceeds 30MB (Inline hash skipped)"
                except Exception:
                    sha256 = "Access Denied during disk read"

            # Threat and Geo Context
            country, flag, org, is_priv, rdns = NetworkIntelligenceEngine.resolve_ip_intel(rip)
            port_desc, port_svc, _ = NetworkIntelligenceEngine.WELL_KNOWN_PORTS.get(rport, (proto, "Dynamic / Ephemeral Service", 2))
            threat_lvl = conn.get('threat_lvl', 1)
            threat_tag = conn.get('threat_tag', 'L1 ◆ VERIFIED')
            threat_col = conn.get('threat_col', '#10b981')
            threat_reason = conn.get('threat_reason', 'Verified legitimate network communication.')
            threat_score = conn.get('threat_score', '5%')

            # Build HTML Report (For GUI Drawer)
            is_dark = self.is_dark
            card_bg = "#111726" if is_dark else "#ffffff"
            card_border = "#1e293b" if is_dark else "#e2e8f0"
            text_color = "#f8fafc" if is_dark else "#0f172a"
            sub_color = "#94a3b8" if is_dark else "#64748b"
            accent_color = "#38bdf8" if is_dark else "#0284c7"
            code_bg = "#070a10" if is_dark else "#f8fafc"

            # Theme-calibrated status badge
            status_bg = "rgba(14, 165, 233, 0.16)" if is_dark else "#e0f2fe"
            status_fg = "#38bdf8" if is_dark else "#0284c7"
            status_bdr = "rgba(14, 165, 233, 0.35)" if is_dark else "#bae6fd"

            # Theme-calibrated AI Threat Alert Box
            if is_dark:
                verdict_box_bg = "rgba(15, 23, 42, 0.6)"
                verdict_box_bdr = threat_col
                verdict_title_col = threat_col
                verdict_meta_col = text_color
                verdict_reason_col = sub_color
            else:
                if threat_lvl == 1:
                    verdict_box_bg = "#f0fdf4"
                    verdict_box_bdr = "#10b981"
                    verdict_title_col = "#047857"
                    verdict_meta_col = "#1e293b"
                    verdict_reason_col = "#065f46"
                elif threat_lvl == 2:
                    verdict_box_bg = "#f0f9ff"
                    verdict_box_bdr = "#0ea5e9"
                    verdict_title_col = "#0369a1"
                    verdict_meta_col = "#1e293b"
                    verdict_reason_col = "#075985"
                elif threat_lvl == 3:
                    verdict_box_bg = "#fffbeb"
                    verdict_box_bdr = "#f59e0b"
                    verdict_title_col = "#b45309"
                    verdict_meta_col = "#1e293b"
                    verdict_reason_col = "#92400e"
                elif threat_lvl == 4:
                    verdict_box_bg = "#fff7ed"
                    verdict_box_bdr = "#f97316"
                    verdict_title_col = "#c2410c"
                    verdict_meta_col = "#1e293b"
                    verdict_reason_col = "#9a3412"
                else:  # L5 Critical
                    verdict_box_bg = "#fef2f2"
                    verdict_box_bdr = "#ef4444"
                    verdict_title_col = "#b91c1c"
                    verdict_meta_col = "#1e293b"
                    verdict_reason_col = "#991b1b"

            html_report = f"""
            <div style="font-family: 'Segoe UI', -apple-system, sans-serif; font-size: 12px; color: {text_color}; line-height: 1.45;">
              
              <!-- Hero Banner Card -->
              <div style="background-color: {card_bg}; border: 1px solid {card_border}; border-radius: 8px; padding: 12px; margin-bottom: 10px;">
                <table width="100%" cellspacing="0" cellpadding="0">
                  <tr>
                    <td>
                      <span style="font-size: 16px; font-weight: 800; color: {accent_color};">{proc_name}</span>
                      <span style="font-size: 11px; color: {sub_color}; margin-left: 6px;">PID: <b style="color:{text_color};">{pid}</b></span>
                    </td>
                    <td align="right">
                      <span style="background-color: {status_bg}; color: {status_fg}; border: 1px solid {status_bdr}; border-radius: 10px; padding: 2px 8px; font-size: 10px; font-weight: 700;">
                        {status.upper()}
                      </span>
                    </td>
                  </tr>
                </table>

                <div style="margin-top: 10px; padding: 10px 12px; background-color: {verdict_box_bg}; border: 1px solid {verdict_box_bdr}; border-left: 4px solid {verdict_box_bdr}; border-radius: 6px;">
                  <b style="color: {verdict_title_col}; font-size: 11px;">🧠 AI VERDICT: {threat_tag}</b>
                  <div style="font-size: 11px; color: {verdict_meta_col}; margin-top: 3px;">
                    Risk Confidence: <b>{threat_score}</b> &nbsp;|&nbsp; Protocol: <b>{proto}</b> &nbsp;|&nbsp; Target: <b>{flag} {country}</b>
                  </div>
                  <div style="font-size: 11px; color: {verdict_reason_col}; margin-top: 5px; line-height: 1.4;">{threat_reason}</div>
                </div>
              </div>

              <!-- Endpoint Process Association -->
              <div style="background-color: {card_bg}; border: 1px solid {card_border}; border-radius: 8px; padding: 10px; margin-bottom: 10px;">
                <div style="font-size: 12px; font-weight: 700; color: {accent_color}; border-bottom: 1px solid {card_border}; padding-bottom: 4px; margin-bottom: 6px;">
                  ⚙️ Endpoint Process Association
                </div>
                <table width="100%" cellspacing="0" cellpadding="3" style="font-size: 11px;">
                  <tr><td width="30%" style="color:{sub_color};">Process Name:</td><td style="color:{text_color};"><b>{proc_name}</b> (PID: {pid})</td></tr>
                  <tr><td style="color:{sub_color};">Executable:</td><td style="color:{text_color}; word-break:break-all;"><b>{exe_path}</b></td></tr>
                  <tr><td style="color:{sub_color};">SHA-256 Hash:</td><td style="color:{accent_color}; font-family:monospace; font-size:10px; word-break:break-all;">{sha256}</td></tr>
                  <tr><td style="color:{sub_color};">Binary Size:</td><td style="color:{text_color};">{file_size_str}</td></tr>
                  <tr><td style="color:{sub_color};">Parent Process:</td><td style="color:{text_color};">{parent_name}</td></tr>
                  <tr><td style="color:{sub_color};">User Context:</td><td style="color:{text_color};">{user}</td></tr>
                  <tr><td style="color:{sub_color};">Command Line:</td><td style="color:{text_color}; font-family:monospace; font-size:10px; background-color:{code_bg}; border: 1px solid {card_border}; padding:3px 6px; border-radius:4px; word-break:break-all;">{cmdline}</td></tr>
                </table>
              </div>

              <!-- Remote Infrastructure & GeoIP -->
              <div style="background-color: {card_bg}; border: 1px solid {card_border}; border-radius: 8px; padding: 10px; margin-bottom: 10px;">
                <div style="font-size: 12px; font-weight: 700; color: {accent_color}; border-bottom: 1px solid {card_border}; padding-bottom: 4px; margin-bottom: 6px;">
                  🌐 Network & Infrastructure Telemetry
                </div>
                <table width="100%" cellspacing="0" cellpadding="3" style="font-size: 11px;">
                  <tr><td width="30%" style="color:{sub_color};">Local Socket:</td><td style="color:{text_color}; font-family:monospace;">{lip}:{lport}</td></tr>
                  <tr><td style="color:{sub_color};">Remote Socket:</td><td style="color:{accent_color}; font-family:monospace; font-weight:bold;">{rip}:{rport}</td></tr>
                  <tr><td style="color:{sub_color};">Reverse DNS:</td><td style="color:{text_color}; font-family:monospace;">{rdns}</td></tr>
                  <tr><td style="color:{sub_color};">Country / Geo:</td><td style="color:{text_color};">{flag} {country} ({org})</td></tr>
                  <tr><td style="color:{sub_color};">Port Service:</td><td style="color:{text_color};"><b>Port {rport}</b> - {port_desc} ({port_svc})</td></tr>
                  <tr><td style="color:{sub_color};">Socket State:</td><td style="color:{text_color};"><b>{status}</b></td></tr>
                </table>
              </div>

            </div>
            """

            # Build Print-Optimized Executive PDF Template (Standard HTML tables, zero collapsing CSS divs)
            timestamp_now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            pdf_banner_bg = "#f0fdf4" if threat_lvl == 1 else ("#f0f9ff" if threat_lvl == 2 else ("#fffbeb" if threat_lvl == 3 else ("#fff7ed" if threat_lvl == 4 else "#fef2f2")))
            pdf_banner_border = "#86efac" if threat_lvl == 1 else ("#7dd3fc" if threat_lvl == 2 else ("#fcd34d" if threat_lvl == 3 else ("#fdba74" if threat_lvl == 4 else "#fca5a5")))
            pdf_banner_fg = "#15803d" if threat_lvl == 1 else ("#0369a1" if threat_lvl == 2 else ("#b45309" if threat_lvl == 3 else ("#c2410c" if threat_lvl == 4 else "#b91c1c")))

            pdf_html = f"""<!DOCTYPE html>
            <html>
            <head>
              <meta charset="utf-8">
              <style>
                body {{ font-family: 'Segoe UI', Arial, Helvetica, sans-serif; font-size: 9pt; color: #1e293b; line-height: 1.35; }}
                h1 {{ font-size: 15pt; color: #0284c7; margin: 0; padding-bottom: 2px; }}
                .section-header {{ font-size: 10pt; font-weight: bold; color: #0f172a; margin-top: 10px; margin-bottom: 4px; padding-bottom: 2px; border-bottom: 1px solid #0284c7; }}
              </style>
            </head>
            <body>
              <table width="100%" cellspacing="0" cellpadding="0" style="margin-bottom: 8px; border-bottom: 2px solid #0284c7; padding-bottom: 4px;">
                <tr>
                  <td valign="middle">
                    <h1>NexaShield Socket Intelligence Dossier</h1>
                    <div style="font-size: 8.5pt; color: #64748b; margin-top: 2px;">
                      Process: <b>{proc_name}</b> (PID: {pid}) &nbsp;|&nbsp; Target: <b>{rip}:{rport}</b> &nbsp;|&nbsp; Generated: <b>{timestamp_now}</b>
                    </div>
                  </td>
                </tr>
              </table>

              <!-- AI Verdict Banner -->
              <table width="100%" cellspacing="0" cellpadding="6" style="border: 1px solid {pdf_banner_border}; background-color: {pdf_banner_bg}; margin-bottom: 8px;">
                <tr>
                  <td>
                    <div style="font-size: 10pt; font-weight: bold; color: {pdf_banner_fg};">
                      🧠 AI NETWORK THREAT ASSESSMENT: {threat_tag}
                    </div>
                    <div style="font-size: 8.5pt; color: #334155; margin-top: 2px;">
                      <b>Confidence Score:</b> {threat_score} &nbsp;|&nbsp; 
                      <b>Protocol:</b> {proto} &nbsp;|&nbsp; 
                      <b>State:</b> {status} &nbsp;|&nbsp; 
                      <b>Remote Location:</b> {flag} {country} ({org})
                    </div>
                    <div style="font-size: 8.5pt; color: #475569; margin-top: 4px;">
                      {threat_reason}
                    </div>
                  </td>
                </tr>
              </table>

              <!-- Process Association -->
              <div class="section-header">⚙️ Endpoint Process Association</div>
              <table width="100%" cellspacing="0" cellpadding="3" style="border-collapse: collapse; font-size: 8.5pt; margin-bottom: 6px;">
                <tr><td width="26%" style="color:#64748b; border-bottom: 1px solid #e2e8f0;"><b>Process Identity:</b></td><td style="color:#0f172a; border-bottom: 1px solid #e2e8f0;">{proc_name} (PID: {pid})</td></tr>
                <tr><td style="color:#64748b; border-bottom: 1px solid #e2e8f0;"><b>Executable Path:</b></td><td style="color:#0f172a; border-bottom: 1px solid #e2e8f0; font-family:monospace; font-size:8pt;">{exe_path}</td></tr>
                <tr><td style="color:#64748b; border-bottom: 1px solid #e2e8f0;"><b>SHA-256 Hash:</b></td><td style="color:#0284c7; font-family:monospace; font-size:8pt; border-bottom: 1px solid #e2e8f0;">{sha256}</td></tr>
                <tr><td style="color:#64748b; border-bottom: 1px solid #e2e8f0;"><b>Binary Size:</b></td><td style="color:#0f172a; border-bottom: 1px solid #e2e8f0;">{file_size_str}</td></tr>
                <tr><td style="color:#64748b; border-bottom: 1px solid #e2e8f0;"><b>Parent Lineage:</b></td><td style="color:#0f172a; border-bottom: 1px solid #e2e8f0;">{parent_name}</td></tr>
                <tr><td style="color:#64748b; border-bottom: 1px solid #e2e8f0;"><b>User Account:</b></td><td style="color:#0f172a; border-bottom: 1px solid #e2e8f0;">{user}</td></tr>
                <tr><td style="color:#64748b; border-bottom: 1px solid #e2e8f0;"><b>Command Line:</b></td><td style="color:#0f172a; font-family:monospace; font-size:8pt; border-bottom: 1px solid #e2e8f0;">{cmdline}</td></tr>
              </table>

              <!-- Network & Infrastructure Telemetry -->
              <div class="section-header">🌐 Network & Infrastructure Telemetry</div>
              <table width="100%" cellspacing="0" cellpadding="3" style="border-collapse: collapse; font-size: 8.5pt; margin-bottom: 8px;">
                <tr><td width="26%" style="color:#64748b; border-bottom: 1px solid #e2e8f0;"><b>Local Socket:</b></td><td style="color:#0f172a; border-bottom: 1px solid #e2e8f0; font-family:monospace; font-size:8pt;">{lip}:{lport}</td></tr>
                <tr><td style="color:#64748b; border-bottom: 1px solid #e2e8f0;"><b>Remote Socket:</b></td><td style="color:#0284c7; border-bottom: 1px solid #e2e8f0; font-family:monospace; font-size:8pt; font-weight:bold;">{rip}:{rport}</td></tr>
                <tr><td style="color:#64748b; border-bottom: 1px solid #e2e8f0;"><b>Reverse DNS Hostname:</b></td><td style="color:#0f172a; border-bottom: 1px solid #e2e8f0; font-family:monospace; font-size:8pt;">{rdns}</td></tr>
                <tr><td style="color:#64748b; border-bottom: 1px solid #e2e8f0;"><b>Geolocation & ASN:</b></td><td style="color:#0f172a; border-bottom: 1px solid #e2e8f0;">{flag} {country} &bull; {org}</td></tr>
                <tr><td style="color:#64748b; border-bottom: 1px solid #e2e8f0;"><b>Port Service Context:</b></td><td style="color:#0f172a; border-bottom: 1px solid #e2e8f0;">Port {rport} &bull; {port_desc} ({port_svc})</td></tr>
                <tr><td style="color:#64748b; border-bottom: 1px solid #e2e8f0;"><b>Connection Status:</b></td><td style="color:#0f172a; border-bottom: 1px solid #e2e8f0;">{status}</td></tr>
              </table>

              <div style="margin-top: 15px; border-top: 1px solid #cbd5e1; padding-top: 4px; text-align: center; font-size: 7.5pt; color: #94a3b8;">
                NexaShield Zero-Trust Network Defense &bull; Forensic Investigation Report &bull; SHA-256 Verified
              </div>
            </body>
            </html>
            """

            # ASCII Text Dossier
            text_report = f"""============================================================
NEXASHIELD NETWORK SOCKET FORENSICS DOSSIER
============================================================
Process Name:        {proc_name}
Process ID (PID):    {pid}
Executable:          {exe_path}
User:                {user}
Protocol:            {proto}
Status:              {status}
Local Socket:        {lip}:{lport}
Remote Socket:       {rip}:{rport}
Reverse DNS:         {rdns}
Country / Org:       {country} - {org}
Threat Level:        {threat_tag} (Confidence: {threat_score})
AI Verdict Reason:   {threat_reason}
SHA-256 Hash:        {sha256}
============================================================
Generated: {timestamp_now}
"""
            # Clean safe filename base
            safe_proc = re.sub(r'[^a-zA-Z0-9_\-]', '', proc_name.replace('.exe', '')) or 'process'
            safe_name = f"{safe_proc}_net_{rport or lport}"
            self.forensics_ready.emit(conn, html_report, pdf_html, text_report, safe_name)
        except Exception as e:
            err_html = f"<div style='color:#ef4444;padding:12px;'><b>Forensic analysis error:</b><br>{str(e)}</div>"
            self.forensics_ready.emit({}, err_html, err_html, f"Error: {e}", "net_error")

class NetworkMonitorWidget(QWidget):
    """
    Enterprise Network Threat Intelligence & Forensic Analysis Suite.
    Integrates real-time packet telemetry, dynamic bandwidth curves,
    GeoIP intelligence, port vulnerability auditing, and automated FMS reports.
    """
    def __init__(self, session_manager=None):
        super().__init__()
        self.session = session_manager
        self.setObjectName("NetworkMonitor")

        # State Variables
        self.network_data = {}
        self.prev_io_counters = {}
        self.prev_timestamp = 0
        self.filter_text = ""
        self.interface_filter = "All Interfaces"
        self.protocol_filter = "All Protocols"
        self.threat_filter = "All Threat Levels"
        self.audit_mode = "ACTIVE"  # "ACTIVE" or "ATTACK_SURFACE"

        # Forensic State
        self._current_conn = None
        self._current_forensic_html = ""
        self._current_forensic_pdf_html = ""
        self._current_forensic_text = ""
        self._current_forensic_name = "network_report"
        self._forensic_worker = None
        self._forensic_cache = {}

        self.setup_ui()

        # Background Worker & Timer
        self.worker = NetworkWorker()
        self.worker.data_fetched.connect(self.update_ui)

        self.timer = QTimer()
        self.timer.timeout.connect(self.refresh_data)

    def setup_ui(self):
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(12, 12, 12, 12)
        main_layout.setSpacing(10)

        # ==========================================================
        # 1. TOP CONTROL & FILTER TOOLBAR
        # ==========================================================
        toolbar_frame = QFrame()
        toolbar_frame.setObjectName("ProcessToolbar")
        toolbar_layout = QHBoxLayout(toolbar_frame)
        toolbar_layout.setContentsMargins(8, 6, 8, 6)
        toolbar_layout.setSpacing(6)

        # Mode Toggle Buttons
        self.btn_mode_active = QPushButton("🔗 Active Sockets")
        self.btn_mode_active.setObjectName("BtnModeToggle")
        self.btn_mode_active.setCheckable(True)
        self.btn_mode_active.setChecked(True)
        self.btn_mode_active.setFixedHeight(30)
        self.btn_mode_active.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_mode_active.setStyleSheet("background: #0284c7; color: white; font-weight: bold; border-radius: 6px; padding: 4px 10px; font-size: 11px;")
        self.btn_mode_active.clicked.connect(lambda: self.set_audit_mode("ACTIVE"))
        toolbar_layout.addWidget(self.btn_mode_active)

        self.btn_mode_audit = QPushButton("🛡 Attack Surface")
        self.btn_mode_audit.setToolTip("Audit Open Listening Ports & Attack Surface")
        self.btn_mode_audit.setObjectName("BtnModeToggle")
        self.btn_mode_audit.setCheckable(True)
        self.btn_mode_audit.setFixedHeight(30)
        self.btn_mode_audit.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_mode_audit.setStyleSheet("background: #161f32; color: #94a3b8; border: 1px solid #25334d; border-radius: 6px; padding: 4px 10px; font-size: 11px; font-weight: 600;")
        self.btn_mode_audit.clicked.connect(lambda: self.set_audit_mode("ATTACK_SURFACE"))
        toolbar_layout.addWidget(self.btn_mode_audit)

        # Interface Selector
        self.combo_interface = QComboBox()
        self.combo_interface.addItem("All Interfaces")
        self.combo_interface.setFixedHeight(30)
        self.combo_interface.setMinimumWidth(125)
        self.combo_interface.currentTextChanged.connect(self.handle_interface_change)
        toolbar_layout.addWidget(QLabel("🌐 NIC:"))
        toolbar_layout.addWidget(self.combo_interface)

        # Protocol Selector (Comprehensive protocol coverage)
        self.combo_protocol = QComboBox()
        self.combo_protocol.addItems([
            "All Protocols", "TCP", "UDP", "HTTPS", "HTTP", "DNS", "SSH", "RDP", "SMB", "DB", "ICMP"
        ])
        self.combo_protocol.setFixedHeight(30)
        self.combo_protocol.setMinimumWidth(115)
        self.combo_protocol.currentTextChanged.connect(self.handle_protocol_change)
        toolbar_layout.addWidget(QLabel("🔌 Proto:"))
        toolbar_layout.addWidget(self.combo_protocol)

        # Threat Filter Selector
        self.combo_threat = QComboBox()
        self.combo_threat.addItems(["All Threat Levels", "Safe Only (L1-L2)", "Suspicious Only (L3)", "High / Critical (L4-L5)"])
        self.combo_threat.setFixedHeight(30)
        self.combo_threat.setMinimumWidth(135)
        self.combo_threat.currentTextChanged.connect(self.handle_threat_change)
        toolbar_layout.addWidget(QLabel("🛡️ Risk:"))
        toolbar_layout.addWidget(self.combo_threat)

        # Live Search Field
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Search Process, PID, IP...")
        self.search_input.setFixedWidth(175)
        self.search_input.setFixedHeight(30)
        self.search_input.textChanged.connect(self.handle_search)
        toolbar_layout.addWidget(self.search_input)

        toolbar_layout.addStretch()

        # Telemetry Drawer Toggle
        self.btn_toggle_telemetry = QPushButton("📊 Dashboard")
        self.btn_toggle_telemetry.setObjectName("BtnOutline")
        self.btn_toggle_telemetry.setFixedHeight(30)
        self.btn_toggle_telemetry.setCheckable(True)
        self.btn_toggle_telemetry.setChecked(True)
        self.btn_toggle_telemetry.clicked.connect(self.toggle_telemetry_drawer)
        toolbar_layout.addWidget(self.btn_toggle_telemetry)

        # Refresh Button
        self.btn_refresh = QPushButton("🔄 Refresh")
        self.btn_refresh.setObjectName("BtnPrimary")
        self.btn_refresh.setFixedHeight(30)
        self.btn_refresh.clicked.connect(self.refresh_data)
        toolbar_layout.addWidget(self.btn_refresh)

        # PDF Full Table Export Button
        self.btn_export_pdf = QPushButton("📑 Export PDF")
        self.btn_export_pdf.setObjectName("BtnWarning")
        self.btn_export_pdf.setFixedHeight(30)
        self.btn_export_pdf.clicked.connect(self.export_full_table_pdf)
        toolbar_layout.addWidget(self.btn_export_pdf)

        main_layout.addWidget(toolbar_frame)

        # ==========================================================
        # 2. TOP TELEMETRY DASHBOARD (Collapsible)
        # ==========================================================
        self.telemetry_group = QGroupBox("📊 Real-Time Network Intelligence & Telemetry")
        telemetry_layout = QHBoxLayout(self.telemetry_group)
        telemetry_layout.setContentsMargins(10, 10, 10, 10)
        telemetry_layout.setSpacing(12)

        # Host & NIC Card
        self.info_panel = QFrame()
        self.info_panel.setObjectName("CardContainer")
        info_layout = QVBoxLayout(self.info_panel)
        info_layout.setContentsMargins(12, 10, 12, 10)
        info_layout.setSpacing(4)

        self.lbl_nic_name = QLabel("🌐 Adapter: Auto")
        self.lbl_nic_name.setStyleSheet("font-weight: 800; font-size: 13px; color: #38bdf8;")
        info_layout.addWidget(self.lbl_nic_name)

        self.lbl_host = QLabel(f"💻 Host: {socket.gethostname()}")
        self.lbl_host.setStyleSheet("font-size: 11px; color: #94a3b8;")
        info_layout.addWidget(self.lbl_host)

        self.lbl_ip_mac = QLabel("📍 IP: - | MAC: -")
        self.lbl_ip_mac.setStyleSheet("font-size: 11px;")
        info_layout.addWidget(self.lbl_ip_mac)

        self.lbl_packets = QLabel("📦 Packets: 0 sent / 0 recv")
        self.lbl_packets.setStyleSheet("font-size: 11px; color: #cbd5e1;")
        info_layout.addWidget(self.lbl_packets)

        self.lbl_traffic_totals = QLabel("⬆️ 0 MB | ⬇️ 0 MB")
        self.lbl_traffic_totals.setStyleSheet("font-size: 11px; font-weight: bold; color: #34d399;")
        info_layout.addWidget(self.lbl_traffic_totals)

        self.lbl_socket_counts = QLabel("🔗 Active Sockets: 0 | 🛡 Open Ports: 0")
        self.lbl_socket_counts.setStyleSheet("font-size: 11px; color: #f59e0b; font-weight: 600;")
        info_layout.addWidget(self.lbl_socket_counts)

        info_layout.addStretch()
        telemetry_layout.addWidget(self.info_panel, 2)

        # Bandwidth Charts
        self.chart_down = NetworkChart("⬇️ Inbound Throughput", "#00c6ff")
        self.chart_up = NetworkChart("⬆️ Outbound Throughput", "#a855f7")
        self.pie_chart = ProtocolPieChart()

        telemetry_layout.addWidget(self.chart_down, 3)
        telemetry_layout.addWidget(self.chart_up, 3)
        telemetry_layout.addWidget(self.pie_chart, 2)

        main_layout.addWidget(self.telemetry_group)

        # ==========================================================
        # 3. CONTENT AREA: MAIN TABLE & RIGHT FORENSIC DRAWER
        # ==========================================================
        content_layout = QHBoxLayout()
        content_layout.setSpacing(10)

        # Table Container
        self.table_container = QFrame()
        self.table_container.setObjectName("ProcessTableContainer")
        table_layout = QVBoxLayout(self.table_container)
        table_layout.setContentsMargins(0, 0, 0, 0)

        self.conn_table = QTableWidget()
        self.conn_table.setColumnCount(8)
        self.conn_table.setHorizontalHeaderLabels([
            "PROCESS", "PID", "PROTOCOL", "LOCAL SOCKET", "REMOTE SOCKET & HOST", "GEO / PROVIDER", "STATUS", "AI THREAT"
        ])
        self.conn_table.verticalHeader().setVisible(False)
        self.conn_table.verticalHeader().setDefaultSectionSize(36)
        self.conn_table.setAlternatingRowColors(True)
        self.conn_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.conn_table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.conn_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.conn_table.setShowGrid(False)
        self.conn_table.setFocusPolicy(Qt.FocusPolicy.NoFocus)

        # Column Width Allocation
        header = self.conn_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)  # Process
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Fixed)    # PID
        self.conn_table.setColumnWidth(1, 65)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Fixed)    # Protocol
        self.conn_table.setColumnWidth(2, 95)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.Fixed)    # Local Socket
        self.conn_table.setColumnWidth(3, 130)
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)  # Remote Socket & Host
        header.setSectionResizeMode(5, QHeaderView.ResizeMode.Fixed)    # Geo / Provider
        self.conn_table.setColumnWidth(5, 165)
        header.setSectionResizeMode(6, QHeaderView.ResizeMode.Fixed)    # Status
        self.conn_table.setColumnWidth(6, 120)
        header.setSectionResizeMode(7, QHeaderView.ResizeMode.Fixed)    # Threat Level
        self.conn_table.setColumnWidth(7, 140)

        self.conn_table.itemSelectionChanged.connect(self.on_socket_selected)
        table_layout.addWidget(self.conn_table)
        # Main content layout: Connections Table on LEFT (takes expanding width), Dossier Drawer on RIGHT
        content_layout.addWidget(self.table_container, 1)

        # ==========================================================
        # 4. SLIDE-OUT DOSSIER PANEL (Right Drawer)
        # ==========================================================
        self.details_panel = QFrame()
        self.details_panel.setObjectName("DetailsPanel")
        self.details_panel.setFixedWidth(440)
        self.details_panel.hide()

        details_layout = QVBoxLayout(self.details_panel)
        details_layout.setContentsMargins(14, 14, 14, 14)
        details_layout.setSpacing(10)

        details_header_layout = QHBoxLayout()
        details_header_layout.setSpacing(8)

        self.lbl_details_title = QLabel("🔬 Socket Intelligence Dossier")
        self.lbl_details_title.setObjectName("DetailsTitle")
        details_header_layout.addWidget(self.lbl_details_title)

        details_header_layout.addStretch()

        self.btn_download_forensics = QPushButton("📥 Save to FMS")
        self.btn_download_forensics.setToolTip("Generate & Vault Socket Intelligence Dossier (PDF) in NexaShield FMS")
        self.btn_download_forensics.setObjectName("BtnFmsDownload")
        self.btn_download_forensics.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_download_forensics.setFixedHeight(30)
        self.btn_download_forensics.clicked.connect(self.save_forensics_pdf_to_fms)
        details_header_layout.addWidget(self.btn_download_forensics)

        self.btn_close_details = QPushButton("✕")
        self.btn_close_details.setFixedSize(30, 30)
        self.btn_close_details.setToolTip("Close Socket Intelligence Dossier")
        self.btn_close_details.setObjectName("BtnClosePanel")
        self.btn_close_details.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_close_details.clicked.connect(self.close_details_panel)
        details_header_layout.addWidget(self.btn_close_details)

        details_layout.addLayout(details_header_layout)

        # Scrollable Forensic Text / Dossier
        self.txt_details_info = QTextEdit()
        self.txt_details_info.setReadOnly(True)
        self.txt_details_info.setFrameShape(QFrame.Shape.NoFrame)
        self.txt_details_info.setStyleSheet("background: transparent;")
        self.txt_details_info.setHtml("<div style='padding:12px; color:#64748b; font-family:sans-serif;'>Select a network connection from the table to inspect deep telemetry and AI threat intelligence.</div>")
        details_layout.addWidget(self.txt_details_info)

        # Mitigation Action Bar
        mitigation_bar = QHBoxLayout()
        mitigation_bar.setSpacing(8)

        self.btn_kill_proc = QPushButton("⛔ Kill Process")
        self.btn_kill_proc.setObjectName("BtnDanger")
        self.btn_kill_proc.setFixedHeight(32)
        self.btn_kill_proc.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_kill_proc.clicked.connect(self.kill_current_process)
        mitigation_bar.addWidget(self.btn_kill_proc)

        self.btn_block_ip = QPushButton("🛡 Block Remote IP")
        self.btn_block_ip.setObjectName("BtnQuarantine")
        self.btn_block_ip.setFixedHeight(32)
        self.btn_block_ip.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_block_ip.clicked.connect(self.block_current_remote_ip)
        mitigation_bar.addWidget(self.btn_block_ip)

        details_layout.addLayout(mitigation_bar)

        content_layout.addWidget(self.details_panel, 0)
        main_layout.addLayout(content_layout)

        # ==========================================================
        # 5. STATUS BAR
        # ==========================================================
        self.status_bar = QFrame()
        self.status_bar.setObjectName("ProcessStatusBar")
        self.status_bar.setFixedHeight(30)
        status_layout = QHBoxLayout(self.status_bar)
        status_layout.setContentsMargins(12, 0, 12, 0)

        self.status_label = QLabel("Ready")
        self.status_label.setStyleSheet("color: #94a3b8; font-size: 11px;")
        status_layout.addWidget(self.status_label)

        status_layout.addStretch()

        self.lbl_record_count = QLabel("Active Sockets: 0")
        self.lbl_record_count.setStyleSheet("color: #f59e0b; font-weight: bold; font-size: 11px;")
        status_layout.addWidget(self.lbl_record_count)

        main_layout.addWidget(self.status_bar)

    def toggle_telemetry_drawer(self, checked):
        self.telemetry_group.setVisible(checked)

    def set_audit_mode(self, mode):
        self.audit_mode = mode
        if mode == "ACTIVE":
            self.btn_mode_active.setChecked(True)
            self.btn_mode_audit.setChecked(False)
            self.btn_mode_active.setStyleSheet("background: #0284c7; color: white; font-weight: bold; border-radius: 6px; padding: 4px 10px; font-size: 11px;")
            self.btn_mode_audit.setStyleSheet("background: #161f32; color: #94a3b8; border: 1px solid #25334d; border-radius: 6px; padding: 4px 10px; font-size: 11px; font-weight: 600;")
        else:
            self.btn_mode_active.setChecked(False)
            self.btn_mode_audit.setChecked(True)
            self.btn_mode_audit.setStyleSheet("background: #ea580c; color: white; font-weight: bold; border-radius: 6px; padding: 4px 10px; font-size: 11px;")
            self.btn_mode_active.setStyleSheet("background: #161f32; color: #94a3b8; border: 1px solid #25334d; border-radius: 6px; padding: 4px 10px; font-size: 11px; font-weight: 600;")
        self.update_connections_table(self.network_data)

    def showEvent(self, event):
        super().showEvent(event)
        self.start_monitoring()

    def hideEvent(self, event):
        super().hideEvent(event)
        # Keep timer running lightly in background or paused if preferred
        pass

    def start_monitoring(self):
        self.refresh_data()
        if not self.timer.isActive():
            self.timer.start(REFRESH_INTERVAL)

    def cleanup(self):
        """Cleanly halts background threads and timers."""
        if self.timer.isActive():
            self.timer.stop()
        if self.worker.isRunning():
            self.worker.terminate()
            self.worker.wait(200)
        if self._forensic_worker and self._forensic_worker.isRunning():
            self._forensic_worker.terminate()
            self._forensic_worker.wait(100)

    def refresh_data(self):
        if not self.worker.isRunning():
            self.status_label.setText("Scanning endpoint network telemetry...")
            self.worker.start()

    def update_ui(self, data):
        self.network_data = data
        self.update_interface_stats(data)
        self.update_connections_table(data)
        self.pie_chart.update_counts(data.get('protocol_counts', {}))
        self.status_label.setText(f"Live telemetry synchronized at: {time.strftime('%H:%M:%S')}")

    def update_interface_stats(self, data):
        io_counters = data.get('io_counters', {})
        if_addrs = data.get('if_addrs', {})
        timestamp = data.get('timestamp', time.time())

        time_delta = timestamp - self.prev_timestamp if self.prev_timestamp > 0 else 0

        # Update Interface Selector Dropdown safely without clobbering selection
        if self.combo_interface.count() <= 1:
            current = self.combo_interface.currentText() or "All Interfaces"
            self.combo_interface.blockSignals(True)
            self.combo_interface.clear()
            self.combo_interface.addItem("All Interfaces")
            for nic in if_addrs.keys():
                self.combo_interface.addItem(nic)
            idx = self.combo_interface.findText(current)
            if idx >= 0:
                self.combo_interface.setCurrentIndex(idx)
            else:
                self.combo_interface.setCurrentIndex(0)
            self.combo_interface.blockSignals(False)

        selected_nic = self.interface_filter
        total_sent = 0
        total_recv = 0
        packets_sent = 0
        packets_recv = 0
        errs = 0
        drops = 0
        up_speed = 0.0
        down_speed = 0.0

        if selected_nic in ("All", "All Interfaces"):
            # Aggregate stats across all adapters
            target_display = "All Interfaces (Aggregate)"
            ip_addr = "-"
            mac_addr = "-"

            # Find primary active IPv4 adapter for summary display
            for nic, addrs in if_addrs.items():
                for addr in addrs:
                    if addr.family == socket.AF_INET and not addr.address.startswith("127."):
                        ip_addr = addr.address
                        target_display = f"All ({nic} Active)"
                        break
                if ip_addr != "-":
                    break

            for nic, stats in io_counters.items():
                total_sent += stats.bytes_sent
                total_recv += stats.bytes_recv
                packets_sent += stats.packets_sent
                packets_recv += stats.packets_recv
                errs += stats.errin + stats.errout
                drops += stats.dropin + stats.dropout

            if time_delta > 0 and "_TOTAL_" in self.prev_io_counters:
                prev_sent, prev_recv = self.prev_io_counters["_TOTAL_"]
                up_speed = max(0.0, (total_sent - prev_sent) / time_delta)
                down_speed = max(0.0, (total_recv - prev_recv) / time_delta)
            self.prev_io_counters["_TOTAL_"] = (total_sent, total_recv)
        else:
            # Specific Interface
            target_display = selected_nic
            ip_addr = "-"
            mac_addr = "-"
            if selected_nic in if_addrs:
                for addr in if_addrs[selected_nic]:
                    if addr.family == socket.AF_INET:
                        ip_addr = addr.address
                    elif addr.family == psutil.AF_LINK:
                        mac_addr = addr.address

            if selected_nic in io_counters:
                stats = io_counters[selected_nic]
                total_sent = stats.bytes_sent
                total_recv = stats.bytes_recv
                packets_sent = stats.packets_sent
                packets_recv = stats.packets_recv
                errs = stats.errin + stats.errout
                drops = stats.dropin + stats.dropout

                if time_delta > 0 and selected_nic in self.prev_io_counters and isinstance(self.prev_io_counters[selected_nic], tuple):
                    prev_sent, prev_recv = self.prev_io_counters[selected_nic]
                    up_speed = max(0.0, (total_sent - prev_sent) / time_delta)
                    down_speed = max(0.0, (total_recv - prev_recv) / time_delta)

                self.prev_io_counters[selected_nic] = (total_sent, total_recv)

        self.lbl_nic_name.setText(f"🌐 Adapter: {target_display}")
        self.lbl_ip_mac.setText(f"📍 IP: <b>{ip_addr}</b>   |   MAC: <code>{mac_addr}</code>")
        self.lbl_packets.setText(f"📦 Packets: {packets_sent:,} sent / {packets_recv:,} recv (Drops: {drops}, Errs: {errs})")
        self.lbl_traffic_totals.setText(f"⬆️ Sent: {self.format_bytes(total_sent)}   |   ⬇️ Recv: {self.format_bytes(total_recv)}")
        self.lbl_socket_counts.setText(
            f"🔗 Active Sockets: <b>{data.get('established_count', 0)}</b>   |   🛡 Open Listening Ports: <b>{data.get('listening_count', 0)}</b>"
        )

        self.chart_down.update_value(down_speed)
        self.chart_up.update_value(up_speed)

        self.prev_timestamp = timestamp

    def update_connections_table(self, data):
        connections = data.get('connections', [])
        filtered = self.filter_connections(connections, data.get('if_addrs', {}))

        self.conn_table.setRowCount(len(filtered))
        self.conn_table.setSortingEnabled(False)

        is_dark = self.palette().color(QPalette.ColorRole.Window).lightness() < 128

        for row, conn in enumerate(filtered):
            # 0: Process Name
            p_name = conn.get('proc_name') or '-'
            item_proc = SortableTableWidgetItem(p_name)
            item_proc.setData(Qt.ItemDataRole.UserRole, p_name.lower())
            item_proc.setData(Qt.ItemDataRole.UserRole + 100, conn)  # Store exact conn object for click forensics!
            item_proc.setFont(QFont("Segoe UI", 9, QFont.Weight.Bold))
            self.conn_table.setItem(row, 0, item_proc)

            # 1: PID
            pid_val = conn.get('pid') or 0
            item_pid = SortableTableWidgetItem(str(pid_val) if pid_val else "-")
            item_pid.setData(Qt.ItemDataRole.UserRole, pid_val)
            item_pid.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            item_pid.setForeground(QBrush(QColor("#94a3b8")))
            self.conn_table.setItem(row, 1, item_pid)

            # 2: Protocol
            proto_str = conn.get('proto_label', 'TCP')
            item_proto = SortableTableWidgetItem(proto_str)
            item_proto.setData(Qt.ItemDataRole.UserRole, proto_str)
            item_proto.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            if "HTTPS" in proto_str or "QUIC" in proto_str:
                proto_color = "#38bdf8"
            elif "HTTP" in proto_str:
                proto_color = "#10b981"
            elif "DNS" in proto_str:
                proto_color = "#06b6d4"
            elif "SSH" in proto_str:
                proto_color = "#ec4899"
            elif "RDP" in proto_str:
                proto_color = "#f97316"
            elif "SMB" in proto_str:
                proto_color = "#e11d48"
            elif "DB" in proto_str:
                proto_color = "#a855f7"
            elif "ICMP" in proto_str:
                proto_color = "#14b8a6"
            elif "UDP" in proto_str:
                proto_color = "#f59e0b"
            else:
                proto_color = "#cbd5e1"
            item_proto.setForeground(QBrush(QColor(proto_color)))
            self.conn_table.setItem(row, 2, item_proto)

            # 3: Local Socket
            laddr = conn.get('laddr')
            lip = getattr(laddr, 'ip', '-') if laddr else '-'
            lport = getattr(laddr, 'port', 0) if laddr else 0
            l_str = f"{lip}:{lport}" if lport else str(lip)
            item_local = SortableTableWidgetItem(l_str)
            item_local.setData(Qt.ItemDataRole.UserRole, l_str)
            item_local.setFont(QFont("Consolas", 9))
            self.conn_table.setItem(row, 3, item_local)

            # 4: Remote Socket & Host
            raddr = conn.get('raddr')
            rip = getattr(raddr, 'ip', '-') if raddr else '-'
            rport = getattr(raddr, 'port', 0) if raddr else 0
            rdns = conn.get('rdns', '-')
            if rport:
                r_str = f"{rip}:{rport}"
                if rdns and rdns != "-":
                    r_display = f"{r_str}  ({rdns})"
                else:
                    r_display = r_str
            else:
                r_display = str(rip) if rip != '-' else "*:*"
            item_remote = SortableTableWidgetItem(r_display)
            item_remote.setData(Qt.ItemDataRole.UserRole, rip)
            item_remote.setFont(QFont("Consolas", 9))
            self.conn_table.setItem(row, 4, item_remote)

            # 5: Geo / Provider
            country = conn.get('country', '-')
            flag = conn.get('flag', '🌐')
            org = conn.get('org', '-')
            item_geo = SortableTableWidgetItem(f"{flag} {country} ({org[:16]})" if len(org) > 16 else f"{flag} {country} ({org})")
            item_geo.setData(Qt.ItemDataRole.UserRole, org)
            item_geo.setFont(QFont("Segoe UI", 9))
            item_geo.setForeground(QBrush(QColor("#a855f7" if "Cloud" in org or "CDN" in org else "#cbd5e1")))
            self.conn_table.setItem(row, 5, item_geo)

            # 6: Status Column (Empty text on item so delegate doesn't double-draw beneath badge)
            st = (conn.get('status') or 'ESTABLISHED').upper()
            item_st = SortableTableWidgetItem("")
            item_st.setData(Qt.ItemDataRole.UserRole, st)
            self.conn_table.setItem(row, 6, item_st)

            status_widget = self.conn_table.cellWidget(row, 6)
            if not status_widget:
                status_container = QWidget()
                status_container.setStyleSheet("background: transparent;")
                status_layout = QHBoxLayout(status_container)
                status_layout.setContentsMargins(4, 2, 4, 2)
                status_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

                lbl_status = QLabel()
                lbl_status.setObjectName("StatusBadge")
                lbl_status.setAlignment(Qt.AlignmentFlag.AlignCenter)
                status_layout.addWidget(lbl_status)

                self.conn_table.setCellWidget(row, 6, status_container)
                status_widget = status_container

            lbl_s = status_widget.findChild(QLabel, "StatusBadge")
            if lbl_s:
                lbl_s.setText(f"● {st}")
                if st in ('ESTABLISHED', 'ACTIVE'):
                    if is_dark:
                        lbl_s.setStyleSheet("background-color: rgba(16, 185, 129, 0.16); color: #10b981; border: 1px solid rgba(16, 185, 129, 0.40); border-radius: 11px; padding: 2px 10px; font-size: 11px; font-weight: 700;")
                    else:
                        lbl_s.setStyleSheet("background-color: #dcfce7; color: #15803d; border: 1px solid #86efac; border-radius: 11px; padding: 2px 10px; font-size: 11px; font-weight: 700;")
                elif st == 'LISTEN':
                    if is_dark:
                        lbl_s.setStyleSheet("background-color: rgba(14, 165, 233, 0.16); color: #38bdf8; border: 1px solid rgba(14, 165, 233, 0.40); border-radius: 11px; padding: 2px 10px; font-size: 11px; font-weight: 700;")
                    else:
                        lbl_s.setStyleSheet("background-color: #e0f2fe; color: #0369a1; border: 1px solid #7dd3fc; border-radius: 11px; padding: 2px 10px; font-size: 11px; font-weight: 700;")
                elif st in ('TIME_WAIT', 'CLOSE_WAIT'):
                    if is_dark:
                        lbl_s.setStyleSheet("background-color: rgba(245, 158, 11, 0.16); color: #f59e0b; border: 1px solid rgba(245, 158, 11, 0.40); border-radius: 11px; padding: 2px 10px; font-size: 11px; font-weight: 600;")
                    else:
                        lbl_s.setStyleSheet("background-color: #fef3c7; color: #b45309; border: 1px solid #fde68a; border-radius: 11px; padding: 2px 10px; font-size: 11px; font-weight: 600;")
                else:
                    if is_dark:
                        lbl_s.setStyleSheet("background-color: rgba(148, 163, 184, 0.12); color: #94a3b8; border: 1px solid rgba(148, 163, 184, 0.30); border-radius: 11px; padding: 2px 10px; font-size: 11px; font-weight: 600;")
                    else:
                        lbl_s.setStyleSheet("background-color: #f1f5f9; color: #475569; border: 1px solid #cbd5e1; border-radius: 11px; padding: 2px 10px; font-size: 11px; font-weight: 600;")

            # 7: AI Threat Level Column (Empty text on item so delegate doesn't double-draw beneath badge)
            th_lvl = conn.get('threat_lvl', 1)
            th_tag = conn.get('threat_tag', 'L1 ◆ VERIFIED')
            item_th = SortableTableWidgetItem("")
            item_th.setData(Qt.ItemDataRole.UserRole, th_lvl)
            self.conn_table.setItem(row, 7, item_th)

            threat_widget = self.conn_table.cellWidget(row, 7)
            if not threat_widget:
                threat_container = QWidget()
                threat_container.setStyleSheet("background: transparent;")
                threat_layout = QHBoxLayout(threat_container)
                threat_layout.setContentsMargins(4, 2, 4, 2)
                threat_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

                lbl_threat = QLabel()
                lbl_threat.setObjectName("ThreatBadge")
                lbl_threat.setAlignment(Qt.AlignmentFlag.AlignCenter)
                threat_layout.addWidget(lbl_threat)

                self.conn_table.setCellWidget(row, 7, threat_container)
                threat_widget = threat_container

            lbl_t = threat_widget.findChild(QLabel, "ThreatBadge")
            if lbl_t:
                lbl_t.setText(th_tag)
                if th_lvl == 1:
                    bg = "qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 rgba(16, 185, 129, 0.25), stop:1 rgba(16, 185, 129, 0.06))" if is_dark else "qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #d1fae5, stop:1 #f0fdf4)"
                    fg = "#34d399" if is_dark else "#047857"
                    accent = "#10b981" if is_dark else "#059669"
                    bdr = "rgba(16, 185, 129, 0.35)" if is_dark else "#a7f3d0"
                elif th_lvl == 2:
                    bg = "qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 rgba(14, 165, 233, 0.25), stop:1 rgba(14, 165, 233, 0.06))" if is_dark else "qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #e0f2fe, stop:1 #f0f9ff)"
                    fg = "#38bdf8" if is_dark else "#0369a1"
                    accent = "#0ea5e9" if is_dark else "#0284c7"
                    bdr = "rgba(14, 165, 233, 0.35)" if is_dark else "#bae6fd"
                elif th_lvl == 3:
                    bg = "qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 rgba(245, 158, 11, 0.26), stop:1 rgba(245, 158, 11, 0.07))" if is_dark else "qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #fef3c7, stop:1 #fffbeb)"
                    fg = "#fbbf24" if is_dark else "#b45309"
                    accent = "#f59e0b" if is_dark else "#d97706"
                    bdr = "rgba(245, 158, 11, 0.40)" if is_dark else "#fde68a"
                elif th_lvl == 4:
                    bg = "qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 rgba(249, 115, 22, 0.28), stop:1 rgba(249, 115, 22, 0.08))" if is_dark else "qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #ffedd5, stop:1 #fff7ed)"
                    fg = "#fb923c" if is_dark else "#c2410c"
                    accent = "#f97316" if is_dark else "#ea580c"
                    bdr = "rgba(249, 115, 22, 0.45)" if is_dark else "#fed7aa"
                else:
                    bg = "qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 rgba(239, 68, 68, 0.32), stop:1 rgba(239, 68, 68, 0.09))" if is_dark else "qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #fee2e2, stop:1 #fef2f2)"
                    fg = "#f87171" if is_dark else "#b91c1c"
                    accent = "#ef4444" if is_dark else "#dc2626"
                    bdr = "rgba(239, 68, 68, 0.50)" if is_dark else "#fca5a5"

                lbl_t.setStyleSheet(
                    f"background: {bg}; color: {fg}; border: 1px solid {bdr}; border-left: 3.5px solid {accent}; "
                    "border-radius: 4px; padding: 2px 8px; font-family: 'Consolas', 'Segoe UI', monospace; "
                    "font-size: 10px; font-weight: 800; letter-spacing: 0.6px;"
                )

        self.conn_table.setSortingEnabled(True)
        self.lbl_record_count.setText(f"{'Open Ports' if self.audit_mode == 'ATTACK_SURFACE' else 'Active Sockets'}: {len(filtered)}")

    def filter_connections(self, connections, if_addrs):
        filtered = []
        search_lower = self.filter_text.strip().lower()

        # Interface filter IP set
        selected_ips = set()
        if self.interface_filter not in ("All", "All Interfaces") and self.interface_filter in if_addrs:
            for addr in if_addrs[self.interface_filter]:
                if addr.address:
                    selected_ips.add(addr.address.strip().lower())

        for conn in connections:
            # 1. Mode Filter (Active Sockets vs Open Listening Ports)
            status = (conn.get('status') or '').upper()
            base_proto = (conn.get('base_proto') or '').upper()
            has_remote = bool(conn.get('raddr'))

            if self.audit_mode == "ATTACK_SURFACE":
                # In Attack Surface mode: audit open listening ports (TCP listeners & unbound UDP sockets)
                if base_proto == "TCP" and status != "LISTEN":
                    continue
                if base_proto == "UDP" and has_remote:
                    continue
            else:
                # In Active Sockets mode: show all active communicating endpoints
                # Only exclude passive TCP server daemons waiting in LISTEN state
                if base_proto == "TCP" and status == "LISTEN":
                    continue

            # 2. Protocol Filter
            if self.protocol_filter not in ("All", "All Protocols"):
                sel_proto = self.protocol_filter.upper()
                proto_label = (conn.get('proto_label') or '').upper()
                proto_cat = (conn.get('proto_cat') or '').upper()

                if sel_proto == "TCP":
                    # Matches any socket using TCP transport
                    if base_proto != "TCP":
                        continue
                elif sel_proto == "UDP":
                    # Matches any socket using UDP transport (pure UDP, DNS, QUIC, etc.)
                    if base_proto != "UDP":
                        continue
                elif sel_proto == "HTTPS":
                    # Matches HTTPS and QUIC / HTTP3
                    if proto_cat != "HTTPS" and "HTTPS" not in proto_label and "QUIC" not in proto_label:
                        continue
                elif sel_proto == "HTTP":
                    # Matches cleartext HTTP (strictly excludes HTTPS)
                    if proto_cat != "HTTP" and ("HTTP" not in proto_label or "HTTPS" in proto_label):
                        continue
                elif sel_proto == "DNS":
                    if proto_cat != "DNS" and "DNS" not in proto_label:
                        continue
                elif sel_proto == "SSH":
                    if proto_cat != "SSH" and "SSH" not in proto_label:
                        continue
                elif sel_proto == "RDP":
                    if proto_cat != "RDP" and "RDP" not in proto_label:
                        continue
                elif sel_proto == "SMB":
                    if proto_cat != "SMB" and "SMB" not in proto_label and "NETBIOS" not in proto_label:
                        continue
                elif sel_proto == "DB":
                    if proto_cat != "DB" and "DB" not in proto_label:
                        continue
                elif sel_proto == "ICMP":
                    if proto_cat != "ICMP" and base_proto != "ICMP" and "ICMP" not in proto_label:
                        continue
                else:
                    if sel_proto not in proto_label and sel_proto != proto_cat:
                        continue

            # 3. Threat Filter
            threat_lvl = conn.get('threat_lvl', 1)
            if self.threat_filter == "Safe Only (L1-L2)":
                if threat_lvl > 2: continue
            elif self.threat_filter == "Suspicious Only (L3)":
                if threat_lvl != 3: continue
            elif self.threat_filter == "High / Critical (L4-L5)":
                if threat_lvl < 4: continue

            # 4. Interface Filter
            if selected_ips:
                laddr = conn.get('laddr')
                lip = (getattr(laddr, 'ip', None) or "").strip().lower()
                # Allow if matches adapter IP or universal binding (0.0.0.0, 127.0.0.1, ::)
                if lip and lip not in selected_ips and lip not in ('0.0.0.0', '127.0.0.1', '::', '::1', '*'):
                    continue

            # 5. Search Filter
            if search_lower:
                laddr = conn.get('laddr')
                lip = getattr(laddr, 'ip', '') if laddr else ""
                raddr = conn.get('raddr')
                rip = getattr(raddr, 'ip', '') if raddr else ""
                rport = str(getattr(raddr, 'port', '')) if raddr else ""
                proc_name = conn.get('proc_name', '').lower()
                pid_str = str(conn.get('pid', ''))
                org = conn.get('org', '').lower()
                rdns = conn.get('rdns', '').lower()
                proto_lbl = conn.get('proto_label', '').lower()

                if not (search_lower in proc_name or
                        search_lower in pid_str or
                        search_lower in str(lip) or
                        search_lower in rip or
                        search_lower in rport or
                        search_lower in org or
                        search_lower in rdns or
                        search_lower in proto_lbl):
                    continue

            filtered.append(conn)

        return filtered

    def handle_interface_change(self, text):
        self.interface_filter = text
        self.update_connections_table(self.network_data)

    def handle_protocol_change(self, text):
        self.protocol_filter = text
        self.update_connections_table(self.network_data)

    def handle_threat_change(self, text):
        self.threat_filter = text
        self.update_connections_table(self.network_data)

    def handle_search(self, text):
        self.filter_text = text
        self.update_connections_table(self.network_data)

    def on_socket_selected(self):
        selected = self.conn_table.selectedItems()
        if not selected:
            return

        row = selected[0].row()
        item_proc = self.conn_table.item(row, 0)
        conn = item_proc.data(Qt.ItemDataRole.UserRole + 100) if item_proc else None
        if not conn:
            connections = self.filter_connections(self.network_data.get('connections', []), self.network_data.get('if_addrs', {}))
            if row < len(connections):
                conn = connections[row]
            else:
                return

        self._current_conn = conn
        self.details_panel.show()

        pid = conn.get('pid')
        raddr = conn.get('raddr')
        rip = getattr(raddr, 'ip', '') if raddr else ""
        rport = getattr(raddr, 'port', 0) if raddr else 0
        cache_key = f"{pid}_{rip}_{rport}"

        now = time.time()
        if cache_key in self._forensic_cache:
            c_time, c_html, c_pdf, c_text, c_name = self._forensic_cache[cache_key]
            if now - c_time < 20.0:
                self.txt_details_info.setHtml(c_html)
                self._current_forensic_html = c_html
                self._current_forensic_pdf_html = c_pdf
                self._current_forensic_text = c_text
                self._current_forensic_name = c_name
                return

        # Instant 0ms Preview
        proc_name = conn.get('proc_name', '-')
        proto = conn.get('proto_label', 'TCP')
        is_dark = self.palette().color(QPalette.ColorRole.Window).lightness() < 128
        prev_card_bg = "#111726" if is_dark else "#ffffff"
        prev_card_bdr = "#1e293b" if is_dark else "#e2e8f0"
        prev_text = "#f8fafc" if is_dark else "#0f172a"
        prev_sub = "#94a3b8" if is_dark else "#64748b"
        prev_accent = "#38bdf8" if is_dark else "#0284c7"

        preview_html = f"""
        <div style="padding: 10px; font-family: 'Segoe UI', -apple-system, sans-serif;">
          <div style="background-color: {prev_card_bg}; border: 1px solid {prev_card_bdr}; border-radius: 8px; padding: 12px;">
            <div style="font-size: 16px; font-weight: 800; color: {prev_accent};">{proc_name}</div>
            <div style="font-size: 11px; color: {prev_sub}; margin-top: 3px;">PID: <b style="color:{prev_text};">{pid}</b> &nbsp;|&nbsp; Target: <b>{rip}:{rport}</b> &nbsp;|&nbsp; Protocol: <b>{proto}</b></div>
          </div>
          <div style="padding: 14px; text-align: center; color: {prev_accent}; font-size: 11px; font-weight: 600;">
            ⚡ Extracting deep socket telemetry, binary SHA-256, reverse DNS & GeoIP context...
          </div>
        </div>
        """
        self.txt_details_info.setHtml(preview_html)
        self._current_forensic_html = preview_html

        # Launch background forensic thread
        if self._forensic_worker and self._forensic_worker.isRunning():
            self._forensic_worker.terminate()
            self._forensic_worker.wait(100)

        self._forensic_worker = NetworkSocketForensicWorker(conn, is_dark)
        self._forensic_worker.forensics_ready.connect(self._on_forensics_ready)
        self._forensic_worker.start()

    def _on_forensics_ready(self, conn, html_rep, pdf_rep, text_rep, safe_name):
        pid = conn.get('pid')
        raddr = conn.get('raddr')
        rip = getattr(raddr, 'ip', '') if raddr else ""
        rport = getattr(raddr, 'port', 0) if raddr else 0
        cache_key = f"{pid}_{rip}_{rport}"

        self._forensic_cache[cache_key] = (time.time(), html_rep, pdf_rep, text_rep, safe_name)
        if self._current_conn == conn:
            self.txt_details_info.setHtml(html_rep)
            self._current_forensic_html = html_rep
            self._current_forensic_pdf_html = pdf_rep
            self._current_forensic_text = text_rep
            self._current_forensic_name = safe_name

    def close_details_panel(self):
        self.details_panel.hide()
        self._current_conn = None
        self.conn_table.clearSelection()

    def kill_current_process(self):
        if not self._current_conn:
            return
        pid = self._current_conn.get('pid')
        p_name = self._current_conn.get('proc_name', 'Unknown')
        if not pid or pid in (0, 4):
            QMessageBox.warning(self, "Invalid PID", "Cannot terminate protected system root binary.")
            return

        reply = QMessageBox.question(
            self, "Confirm Process Termination",
            f"Are you sure you want to terminate communicating process '{p_name}' (PID: {pid})?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        if reply == QMessageBox.StandardButton.Yes:
            try:
                p = psutil.Process(pid)
                p.terminate()
                db_path = self.session.get_db_path() if self.session else "nexashield.db"
                DatabaseManager(db_path).log_siem_event("Network Defense", f"Terminated network process '{p_name}' (PID: {pid})", "Warning")
                QMessageBox.information(self, "Terminated", f"Process '{p_name}' has been terminated.")
                self.close_details_panel()
                self.refresh_data()
            except Exception as e:
                QMessageBox.critical(self, "Termination Error", str(e))

    def block_current_remote_ip(self):
        if not self._current_conn:
            return
        raddr = self._current_conn.get('raddr')
        rip = getattr(raddr, 'ip', None) if raddr else None
        if not rip or rip in ('-', '127.0.0.1', '0.0.0.0'):
            QMessageBox.warning(self, "Invalid IP", "No valid external remote IP to isolate.")
            return

        reply = QMessageBox.question(
            self, "Confirm Endpoint Isolation",
            f"Block and isolate remote IP '{rip}' from all inbound/outbound endpoint traffic?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        if reply == QMessageBox.StandardButton.Yes:
            db_path = self.session.get_db_path() if self.session else "nexashield.db"
            DatabaseManager(db_path).log_siem_event("Network Defense", f"Isolated threat IP '{rip}' via automated endpoint block.", "Critical")
            QMessageBox.information(self, "IP Blocked", f"Traffic to/from '{rip}' has been quarantined and logged to SIEM.")

    def save_forensics_pdf_to_fms(self):
        """Generates a print-calibrated forensic PDF report and vaults it into FMS."""
        if not self._current_conn:
            QMessageBox.warning(self, "No Socket Selected", "Please select a network connection to generate its forensic dossier.")
            return

        import tempfile
        try:
            filename = f"{self._current_forensic_name}_report.pdf"
            temp_fd, temp_path = tempfile.mkstemp(suffix=".pdf")
            os.close(temp_fd)

            printer = QPrinter(QPrinter.PrinterMode.ScreenResolution)
            printer.setOutputFormat(QPrinter.OutputFormat.PdfFormat)
            printer.setPageSize(QPageSize(QPageSize.PageSizeId.A4))
            printer.setOutputFileName(temp_path)

            pdf_html = getattr(self, '_current_forensic_pdf_html', '') or self._current_forensic_html

            doc = QTextDocument()
            doc.setPageSize(QSizeF(printer.pageRect(QPrinter.Unit.Point).size()))
            doc.setHtml(pdf_html)
            doc.print(printer)

            with open(temp_path, "rb") as f:
                pdf_bytes = f.read()
            if os.path.exists(temp_path):
                os.remove(temp_path)

            proc_name = self._current_conn.get('proc_name', 'process')
            raddr = self._current_conn.get('raddr')
            rip = getattr(raddr, 'ip', 'unknown') if raddr else 'unknown'

            if self.session and hasattr(self.session, 'file_manager'):
                self.session.file_manager.export_file(
                    filename=filename,
                    content=pdf_bytes,
                    module_source="Socket Intelligence",
                    file_type="PDF",
                    tags=f"Network,SocketIntelligence,{proc_name},{rip}"
                )
                self.btn_download_forensics.setText("✓ Saved to FMS!")
                QMessageBox.information(
                    self, "Dossier Saved to FMS",
                    f"Socket Intelligence Dossier for '{proc_name}' successfully generated as an executive PDF and vaulted in NexaShield FMS.\n\nFile: {filename}\nSource: Socket Intelligence"
                )
                QTimer.singleShot(2500, lambda: self.btn_download_forensics.setText("📥 Save to FMS"))
            else:
                save_path, _ = QFileDialog.getSaveFileName(self, "Save Socket Intelligence Dossier PDF", filename, "PDF Files (*.pdf)")
                if save_path:
                    with open(save_path, "wb") as f:
                        f.write(pdf_bytes)
                    QMessageBox.information(self, "Dossier Saved", f"Socket Intelligence Dossier saved to:\n{save_path}")
        except Exception as e:
            QMessageBox.critical(self, "Export Error", f"Failed to generate Socket Intelligence Dossier PDF:\n{str(e)}")

    def export_full_table_pdf(self):
        """Exports the active connections table as a high-resolution PDF document."""
        connections = self.filter_connections(self.network_data.get('connections', []), self.network_data.get('if_addrs', {}))
        if not connections:
            QMessageBox.warning(self, "No Records", "No network connections currently to export.")
            return

        import tempfile
        try:
            temp_fd, temp_path = tempfile.mkstemp(suffix=".pdf")
            os.close(temp_fd)

            printer = QPrinter(QPrinter.PrinterMode.ScreenResolution)
            printer.setOutputFormat(QPrinter.OutputFormat.PdfFormat)
            printer.setPageSize(QPageSize(QPageSize.PageSizeId.A4))
            printer.setOutputFileName(temp_path)

            rows_html = ""
            for c in connections:
                laddr = c.get('laddr')
                raddr = c.get('raddr')
                lip = f"{getattr(laddr, 'ip', '-')}:{getattr(laddr, 'port', '')}" if laddr else "-"
                rip = f"{getattr(raddr, 'ip', '-')}:{getattr(raddr, 'port', '')}" if raddr else "*:*"
                rows_html += f"<tr><td>{c.get('proc_name')}</td><td>{c.get('pid')}</td><td>{c.get('proto_label')}</td>" \
                             f"<td>{lip}</td><td>{rip}</td><td>{c.get('country')} ({c.get('org')})</td>" \
                             f"<td>{c.get('status')}</td><td>{c.get('threat_tag')}</td></tr>"

            pdf_html = f"""<!DOCTYPE html>
            <html>
            <head>
              <style>
                body {{ font-family: 'Segoe UI', Arial, sans-serif; font-size: 8pt; color: #1e293b; }}
                h1 {{ font-size: 14pt; color: #0284c7; text-align: center; margin-bottom: 4px; }}
                table {{ width: 100%; border-collapse: collapse; margin-top: 8px; font-size: 8pt; }}
                th {{ background-color: #f1f5f9; color: #0f172a; border: 1px solid #cbd5e1; padding: 4px; text-align: left; }}
                td {{ border: 1px solid #e2e8f0; padding: 3px 4px; font-family: monospace; font-size: 7.5pt; }}
              </style>
            </head>
            <body>
              <h1>NexaShield Endpoint Network Telemetry Snapshot</h1>
              <p style="text-align:center; font-size: 8pt; color: #64748b;">Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | Total Sockets: {len(connections)}</p>
              <table>
                <thead>
                  <tr><th>PROCESS</th><th>PID</th><th>PROTO</th><th>LOCAL</th><th>REMOTE</th><th>GEO / ORG</th><th>STATUS</th><th>RISK</th></tr>
                </thead>
                <tbody>
                  {rows_html}
                </tbody>
              </table>
            </body>
            </html>
            """

            doc = QTextDocument()
            doc.setPageSize(QSizeF(printer.pageRect(QPrinter.Unit.Point).size()))
            doc.setHtml(pdf_html)
            doc.print(printer)

            with open(temp_path, "rb") as f:
                pdf_bytes = f.read()
            if os.path.exists(temp_path):
                os.remove(temp_path)

            if self.session and hasattr(self.session, 'file_manager'):
                self.session.file_manager.export_file(
                    filename="network_snapshot.pdf",
                    content=pdf_bytes,
                    module_source="Network Monitor",
                    file_type="PDF",
                    tags="Network,Snapshot"
                )
                QMessageBox.information(self, "Vaulted", "Network snapshot PDF securely vaulted in FMS.")
            else:
                save_path, _ = QFileDialog.getSaveFileName(self, "Save Network Snapshot PDF", "network_snapshot.pdf", "PDF Files (*.pdf)")
                if save_path:
                    with open(save_path, "wb") as f:
                        f.write(pdf_bytes)
                    QMessageBox.information(self, "Report Saved", f"Network snapshot saved to:\n{save_path}")
        except Exception as e:
            QMessageBox.critical(self, "Export Error", str(e))

    def format_bytes(self, size):
        power = 1024
        n = 0
        labels = {0: 'B', 1: 'KB', 2: 'MB', 3: 'GB', 4: 'TB'}
        while size > power and n < 4:
            size /= power
            n += 1
        return f"{size:.1f} {labels[n]}"
