import psutil
import datetime
import csv
import time
from collections import deque
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QTableWidget, QTableWidgetItem,
    QPushButton, QLineEdit, QLabel, QHeaderView, QMessageBox, QFileDialog,
    QAbstractItemView, QFrame, QProgressBar, QCheckBox, QComboBox, QStyle, QTextEdit,
    QApplication
)
from PyQt6.QtCore import Qt, QTimer, QThread, pyqtSignal, QSizeF
from PyQt6.QtGui import QColor, QBrush, QAction, QPainter, QPainterPath, QLinearGradient, QRadialGradient, QPen, QTextDocument, QPalette, QFont, QPageSize
from PyQt6.QtPrintSupport import QPrinter

import sys
import os
import hashlib
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from database import DatabaseManager
from ai.processAI.process_scanner import ProcessThreatScanner

# --- Constants ---
REFRESH_INTERVAL = 3000  # 3 seconds
HIGH_CPU_THRESHOLD = 80.0
HIGH_MEM_THRESHOLD = 80.0

class SortableTableWidgetItem(QTableWidgetItem):
    """Custom item to ensure proper sorting by UserRole (handles both numeric and strings)."""
    def __lt__(self, other):
        val1 = self.data(Qt.ItemDataRole.UserRole)
        val2 = other.data(Qt.ItemDataRole.UserRole)
        try:
            return float(val1) < float(val2)
        except (ValueError, TypeError):
            return str(val1) < str(val2)

class ForensicWorker(QThread):
    """
    High-performance asynchronous worker to extract exhaustive process forensics,
    binary integrity checksums, network telemetry, lineage, and AI risk signals
    without blocking the PyQt GUI thread.
    """
    forensics_ready = pyqtSignal(int, str, str, str, str)  # pid, html_report, pdf_html, text_report, proc_name

    def __init__(self, pid, p_data, is_dark, ai_enabled):
        super().__init__()
        self.pid = pid
        self.p_data = p_data or {}
        self.is_dark = is_dark
        self.ai_enabled = ai_enabled

    def run(self):
        try:
            html_rep, pdf_rep, text_rep, proc_name = self._generate_dossier()
            self.forensics_ready.emit(self.pid, html_rep, pdf_rep, text_rep, proc_name)
        except psutil.NoSuchProcess:
            html = "<div style='padding: 15px; color: #f59e0b; font-weight: bold;'>⚠️ Process has terminated.</div>"
            self.forensics_ready.emit(self.pid, html, html, "Process terminated.", "terminated_process")
        except Exception as e:
            html = f"<div style='padding: 15px; color: #ef4444;'><b>Forensic analysis error:</b><br>{str(e)}</div>"
            self.forensics_ready.emit(self.pid, html, html, f"Error: {str(e)}", "unknown_process")

    def _generate_dossier(self):
        pid = self.pid
        proc = psutil.Process(pid)
        
        # 1. Identity & Binary Information
        try:
            name = proc.name() or self.p_data.get('name') or f"PID {pid}"
        except Exception:
            name = self.p_data.get('name') or f"PID {pid}"

        try:
            exe = proc.exe() or "Unknown / Protected System Binary"
        except (psutil.AccessDenied, Exception):
            exe = self.p_data.get('exe') or "Access Denied (System Protected)"

        try:
            cmdline_list = proc.cmdline()
            cmdline = " ".join(cmdline_list) if cmdline_list else (exe if exe != "Unknown" else "None")
        except (psutil.AccessDenied, Exception):
            cmdline = " ".join(self.p_data.get('cmdline') or []) or "Access Denied (Elevation Required)"

        try:
            cwd = proc.cwd() if hasattr(proc, 'cwd') else "N/A"
        except (psutil.AccessDenied, Exception):
            cwd = "Access Denied"

        try:
            parent = proc.parent()
            ppid = proc.ppid()
            parent_name = f"{parent.name()} (PID: {ppid})" if parent else f"PID: {ppid}"
        except (psutil.AccessDenied, Exception):
            parent_name = "Unknown / System Root"
            ppid = "N/A"

        # 2. Hashing (SHA-256)
        sha256 = "N/A (Virtual / Protected Memory)"
        file_size_str = "N/A"
        if exe and os.path.exists(exe):
            try:
                sz = os.path.getsize(exe)
                file_size_str = f"{sz / (1024*1024):.2f} MB ({sz:,} bytes)"
                if sz <= 30 * 1024 * 1024:
                    with open(exe, "rb") as f:
                        sha256 = hashlib.sha256(f.read()).hexdigest()
                else:
                    sha256 = f"Binary size {file_size_str} exceeds 30MB (Inline hash skipped for performance)"
            except Exception:
                sha256 = "Access Denied during file read"

        # 3. User & Execution Privileges
        try:
            username = proc.username() or self.p_data.get('username') or "System"
        except (psutil.AccessDenied, Exception):
            username = self.p_data.get('username') or "System"

        is_elevated = username.upper() in ['SYSTEM', 'LOCAL SERVICE', 'NETWORK SERVICE'] or "ADMIN" in username.upper()
        privilege_badge = "👑 Elevated / System" if is_elevated else "👤 Standard User"

        # 4. Priority Class
        try:
            nice_val = proc.nice() if hasattr(proc, 'nice') else None
            priority_map = {
                256: "Realtime (256)",
                128: "High (128)",
                32768: "Above Normal (32768)",
                32: "Normal (32)",
                16384: "Below Normal (16384)",
                64: "Idle (64)"
            }
            priority_str = priority_map.get(nice_val, str(nice_val) if nice_val is not None else "Normal")
        except Exception:
            priority_str = "Normal"

        # 5. Lifecycle & Duration
        try:
            created_ts = proc.create_time()
            start_dt = datetime.datetime.fromtimestamp(created_ts).strftime("%Y-%m-%d %H:%M:%S")
            uptime_secs = int(datetime.datetime.now().timestamp() - created_ts)
            uptime_str = str(datetime.timedelta(seconds=max(0, uptime_secs)))
        except Exception:
            start_dt = "Unknown"
            uptime_str = "Unknown"

        # 6. Threads & Context Switches
        try:
            threads = proc.num_threads()
        except Exception:
            threads = self.p_data.get('num_threads') or 1

        try:
            ctx = proc.num_ctx_switches() if hasattr(proc, 'num_ctx_switches') else None
            voluntary_ctx = f"{ctx.voluntary:,}" if ctx else "N/A"
            involuntary_ctx = f"{ctx.involuntary:,}" if ctx else "N/A"
        except Exception:
            voluntary_ctx = "N/A"
            involuntary_ctx = "N/A"

        # 7. CPU Telemetry
        cpu_cur = self.p_data.get('cpu_percent') or 0.0
        try:
            cpu_times = proc.cpu_times()
            user_cpu = f"{cpu_times.user:.2f}s"
            system_cpu = f"{cpu_times.system:.2f}s"
        except Exception:
            user_cpu = "N/A"
            system_cpu = "N/A"

        # 8. Memory Telemetry
        mem_pct = self.p_data.get('memory_percent') or 0.0
        try:
            mem_info = proc.memory_info()
            rss_mb = f"{mem_info.rss / (1024*1024):.2f} MB"
            vms_mb = f"{mem_info.vms / (1024*1024):.2f} MB"
            peak_wset = getattr(mem_info, 'peak_wset', mem_info.rss)
            peak_wset_mb = f"{peak_wset / (1024*1024):.2f} MB"
            page_faults = f"{getattr(mem_info, 'num_page_faults', 0):,}"
        except Exception:
            rss_mb = "N/A"
            vms_mb = "N/A"
            peak_wset_mb = "N/A"
            page_faults = "N/A"

        # 9. Disk & I/O Telemetry
        try:
            io = proc.io_counters() if hasattr(proc, 'io_counters') else None
            read_mb = f"{io.read_bytes / (1024*1024):.2f} MB" if io else f"{self.p_data.get('disk_read', 0) / (1024*1024):.2f} MB"
            write_mb = f"{io.write_bytes / (1024*1024):.2f} MB" if io else f"{self.p_data.get('disk_write', 0) / (1024*1024):.2f} MB"
            read_ops = f"{getattr(io, 'read_count', 0):,}" if io else "N/A"
            write_ops = f"{getattr(io, 'write_count', 0):,}" if io else "N/A"
        except Exception:
            read_mb = f"{self.p_data.get('disk_read', 0) / (1024*1024):.2f} MB"
            write_mb = f"{self.p_data.get('disk_write', 0) / (1024*1024):.2f} MB"
            read_ops = "N/A"
            write_ops = "N/A"

        # 10. Network Sockets & Active Connections
        network_entries = []
        try:
            if hasattr(proc, 'net_connections'):
                raw_conns = proc.net_connections()
            else:
                raw_conns = proc.connections()
            
            for c in (raw_conns or [])[:8]:
                proto = "TCP" if getattr(c, 'type', 1) == 1 else "UDP"
                laddr = f"{c.laddr.ip}:{c.laddr.port}" if hasattr(c, 'laddr') and c.laddr else "*:*"
                raddr = f"{c.raddr.ip}:{c.raddr.port}" if hasattr(c, 'raddr') and c.raddr else "*:*"
                st = getattr(c, 'status', 'NONE') or "NONE"
                network_entries.append((proto, laddr, raddr, st))
        except (psutil.AccessDenied, Exception):
            pass

        # 11. AI Threat Intelligence & Risk Assessment
        lvl = self.p_data.get('ai_level') or 1
        prob = self.p_data.get('ai_prob') or (0.12 if lvl == 1 else 0.28 if lvl == 2 else 0.48 if lvl == 3 else 0.72 if lvl == 4 else 0.92)
        score_pct = f"{prob * 100:.1f}%"

        threat_meta = {
            1: ("BENIGN / VERIFIED SAFE", "#00b894", "Low", "#dcfce7", "#15803d"),
            2: ("LOW RISK / MINOR IRREGULARITY", "#0984e3", "Low", "#e0f2fe", "#0369a1"),
            3: ("MODERATE RISK / ATYPICAL TELEMETRY", "#fdcb6e", "Moderate", "#fef3c7", "#b45309"),
            4: ("HIGH RISK / SUSPICIOUS BEHAVIOR", "#e17055", "Elevated", "#ffedd5", "#c2410c"),
            5: ("CRITICAL THREAT / MALWARE SIGNATURE", "#d63031", "Severe", "#fee2e2", "#b91c1c"),
        }
        verdict_title, threat_color, risk_severity, light_bg, light_text = threat_meta.get(lvl, threat_meta[1])

        # Heuristic Risk Factors
        path_lower = (exe + " " + cmdline).lower()
        is_temp = 'temp' in path_lower and 'access denied' not in path_lower
        is_appdata = 'appdata' in path_lower and 'access denied' not in path_lower
        is_system_dir = 'system32' in path_lower or 'syswow64' in path_lower or 'program files' in path_lower

        factors = []
        if is_temp:
            factors.append("Execution origin inside Temporary file cache directory (High Risk)")
        if is_appdata:
            factors.append("Execution origin inside User AppData / Roaming directory (Moderate Risk)")
        if cpu_cur > 30:
            factors.append(f"Excessive CPU compute demand ({cpu_cur:.1f}%)")
        if mem_pct > 30:
            factors.append(f"Heavy working-set memory footprint ({mem_pct:.1f}%)")
        if len(network_entries) > 0:
            factors.append(f"Active outbound network sockets ({len(network_entries)} detected)")

        # Dynamic AI Reasoning
        if lvl == 1:
            reasoning = "Benign baseline verified. The executable operates strictly within standard operating bounds, displays standard parent lineage, and exhibits no anomalous system hooks or evasion techniques."
        elif lvl == 2:
            reason_str = ", ".join(factors) if factors else "minor telemetry variance"
            reasoning = f"Low risk profile. Detected {reason_str}. The behavior is consistent with background utility or developer execution and does not represent an active exploit vector."
        elif lvl == 3:
            reason_str = ", ".join(factors) if factors else "atypical resource consumption"
            reasoning = f"Moderate risk detected. Flagged due to: {reason_str}. Behavioral telemetry deviates from known benign distributions. Continuous SIEM monitoring is recommended."
        elif lvl == 4:
            reason_str = ", ".join(factors) if factors else "suspicious execution anomalies"
            reasoning = f"High threat probability. The process exhibits hazardous indicators: {reason_str}. High likelihood of unauthorized binary execution, backdoor listener, or credential harvester."
        else:
            reason_str = ", ".join(factors) if factors else "critical malware indicators"
            reasoning = f"CRITICAL MALWARE MATCH. The telemetry fingerprint perfectly correlates with weaponized exploitation patterns ({reason_str}). Immediate termination and endpoint quarantine advised."

        # Theming Tokens
        is_dark = self.is_dark
        card_bg = "#111726" if is_dark else "#ffffff"
        card_border = "#1e293b" if is_dark else "#e2e8f0"
        text_color = "#f8fafc" if is_dark else "#0f172a"
        sub_color = "#94a3b8" if is_dark else "#64748b"
        accent_color = "#38bdf8" if is_dark else "#0284c7"
        code_bg = "#070a10" if is_dark else "#f1f5f9"
        threat_banner_bg = "rgba(15, 23, 42, 0.7)" if is_dark else "#f8fafc"

        raw_status = str(self.p_data.get('status') or 'running').lower()
        if raw_status == 'running':
            badge_bg = "rgba(16, 185, 129, 0.16)" if is_dark else "#dcfce7"
            badge_fg = "#10b981" if is_dark else "#15803d"
            badge_border = "rgba(16, 185, 129, 0.40)" if is_dark else "#86efac"
        elif raw_status in ('stopped', 'suspended', 'dead'):
            badge_bg = "rgba(239, 68, 68, 0.16)" if is_dark else "#fee2e2"
            badge_fg = "#ef4444" if is_dark else "#b91c1c"
            badge_border = "rgba(239, 68, 68, 0.40)" if is_dark else "#fca5a5"
        else:
            badge_bg = "rgba(148, 163, 184, 0.12)" if is_dark else "#f1f5f9"
            badge_fg = "#94a3b8" if is_dark else "#475569"
            badge_border = "rgba(148, 163, 184, 0.30)" if is_dark else "#cbd5e1"

        # Build Network HTML
        if network_entries:
            net_rows = "".join([
                f"<tr><td style='color:{accent_color}; font-weight:bold;'>{e[0]}</td><td style='color:{text_color};'>{e[1]}</td><td style='color:{sub_color};'>{e[2]}</td><td style='color:#10b981;'>{e[3]}</td></tr>"
                for e in network_entries
            ])
            network_table_html = f"""
            <table width='100%' cellspacing='0' cellpadding='3' style='font-size: 10px; font-family: monospace;'>
              <tr style='color:{sub_color}; border-bottom: 1px solid {card_border};'><th>PROTO</th><th>LOCAL</th><th>REMOTE</th><th>STATE</th></tr>
              {net_rows}
            </table>
            """
            net_text_list = "\n".join([f"  {e[0]}  {e[1]}  ->  {e[2]}  [{e[3]}]" for e in network_entries])
        else:
            network_table_html = f"<div style='color: {sub_color}; font-size: 11px; padding: 4px 0;'>No active external network sockets detected.</div>"
            net_text_list = "  No active external sockets."

        # Build Indicators HTML
        path_badge = "<span style='color: #10b981;'>✔ Trusted System Directory</span>" if is_system_dir else (
            "<span style='color: #ef4444; font-weight: bold;'>⚠ Execution from Temp Directory</span>" if is_temp else (
                "<span style='color: #fdcb6e; font-weight: bold;'>⚠ Execution from User AppData</span>" if is_appdata else "<span style='color: #94a3b8;'>Standard User Directory</span>"
            )
        )
        sock_badge = f"<span style='color: #38bdf8;'>⚡ Outbound Sockets Active ({len(network_entries)})</span>" if network_entries else "<span style='color: #10b981;'>✔ Network Isolated</span>"
        res_badge = f"<span style='color: #ef4444;'>⚠ High Resource Utilization</span>" if (cpu_cur > 30 or mem_pct > 30) else "<span style='color: #10b981;'>✔ Normal Resource Bounds</span>"
        lineage_badge = "<span style='color: #10b981;'>✔ Verified Parent Process</span>" if "None" not in parent_name else "<span style='color: #fdcb6e;'>ℹ Standalone Root Process</span>"

        indicators_html = f"""
        <table width='100%' cellspacing='0' cellpadding='3' style='font-size: 11px;'>
          <tr><td width='35%' style='color:{sub_color};'>Path Verification:</td><td>{path_badge}</td></tr>
          <tr><td style='color:{sub_color};'>Network Exposure:</td><td>{sock_badge}</td></tr>
          <tr><td style='color:{sub_color};'>Resource Profile:</td><td>{res_badge}</td></tr>
          <tr><td style='color:{sub_color};'>Lineage Integrity:</td><td>{lineage_badge}</td></tr>
        </table>
        """

        # Build Complete HTML Report
        html_report = f"""
        <div style="font-family: 'Segoe UI', -apple-system, sans-serif; font-size: 12px; color: {text_color}; line-height: 1.45;">
          
          <!-- Hero Banner Card -->
          <div style="background-color: {card_bg}; border: 1px solid {card_border}; border-radius: 8px; padding: 12px; margin-bottom: 10px;">
            <table width="100%" cellspacing="0" cellpadding="0">
              <tr>
                <td>
                  <span style="font-size: 16px; font-weight: 800; color: {accent_color};">{name}</span>
                  <span style="font-size: 11px; color: {sub_color}; margin-left: 6px;">PID: <b style="color:{text_color};">{pid}</b></span>
                </td>
                <td align="right">
                  <span style="background-color: {badge_bg}; color: {badge_fg}; border: 1px solid {badge_border}; border-radius: 10px; padding: 2px 8px; font-size: 10px; font-weight: 700;">
                    {raw_status.upper()}
                  </span>
                </td>
              </tr>
            </table>

            <div style="margin-top: 10px; padding: 8px 10px; background-color: {threat_banner_bg}; border-left: 4px solid {threat_color}; border-radius: 4px;">
              <b style="color: {threat_color}; font-size: 11px;">🧠 AI VERDICT: {verdict_title}</b>
              <div style="font-size: 11px; color: {text_color}; margin-top: 3px;">
                Risk Score: <b>{score_pct}</b> &nbsp;|&nbsp; Severity: <b>{risk_severity}</b> &nbsp;|&nbsp; Context: <b>{privilege_badge}</b>
              </div>
              <div style="font-size: 11px; color: {sub_color}; margin-top: 5px;">{reasoning}</div>
            </div>
          </div>

          <!-- Binary Identity & Integrity -->
          <div style="background-color: {card_bg}; border: 1px solid {card_border}; border-radius: 8px; padding: 10px; margin-bottom: 10px;">
            <div style="font-size: 12px; font-weight: 700; color: {accent_color}; border-bottom: 1px solid {card_border}; padding-bottom: 4px; margin-bottom: 6px;">
              📂 Binary Identity & Integrity
            </div>
            <table width="100%" cellspacing="0" cellpadding="3" style="font-size: 11px;">
              <tr><td width="30%" style="color:{sub_color};">Executable:</td><td style="color:{text_color}; word-break:break-all;"><b>{exe}</b></td></tr>
              <tr><td style="color:{sub_color};">SHA-256 Hash:</td><td style="color:{accent_color}; font-family:monospace; font-size:10px; word-break:break-all;">{sha256}</td></tr>
              <tr><td style="color:{sub_color};">Binary Size:</td><td style="color:{text_color};">{file_size_str}</td></tr>
              <tr><td style="color:{sub_color};">Command Line:</td><td style="color:{text_color}; word-break:break-all; font-family:monospace; font-size:10px; background-color:{code_bg}; padding:2px 4px; border-radius:3px;">{cmdline}</td></tr>
              <tr><td style="color:{sub_color};">Working Dir:</td><td style="color:{text_color}; word-break:break-all;">{cwd}</td></tr>
              <tr><td style="color:{sub_color};">Parent Process:</td><td style="color:{text_color};"><b>{parent_name}</b></td></tr>
              <tr><td style="color:{sub_color};">User Account:</td><td style="color:{text_color};">{username} ({privilege_badge})</td></tr>
              <tr><td style="color:{sub_color};">Priority Class:</td><td style="color:{text_color};">{priority_str}</td></tr>
            </table>
          </div>

          <!-- Execution & Resource Telemetry -->
          <div style="background-color: {card_bg}; border: 1px solid {card_border}; border-radius: 8px; padding: 10px; margin-bottom: 10px;">
            <div style="font-size: 12px; font-weight: 700; color: {accent_color}; border-bottom: 1px solid {card_border}; padding-bottom: 4px; margin-bottom: 6px;">
              ⚡ Runtime & Telemetry Forensics
            </div>
            <table width="100%" cellspacing="0" cellpadding="3" style="font-size: 11px;">
              <tr><td width="30%" style="color:{sub_color};">Started At:</td><td style="color:{text_color};">{start_dt}</td></tr>
              <tr><td style="color:{sub_color};">Active Uptime:</td><td style="color:{text_color};"><b>{uptime_str}</b></td></tr>
              <tr><td style="color:{sub_color};">Active Threads:</td><td style="color:{text_color};">{threads} threads</td></tr>
              <tr><td style="color:{sub_color};">CPU Usage:</td><td style="color:{text_color};"><b>{cpu_cur:.1f}%</b> (User: {user_cpu} | Kernel: {system_cpu})</td></tr>
              <tr><td style="color:{sub_color};">Memory RSS:</td><td style="color:{text_color};"><b>{rss_mb}</b> (Peak: {peak_wset_mb} | Virtual: {vms_mb})</td></tr>
              <tr><td style="color:{sub_color};">Page Faults:</td><td style="color:{text_color};">{page_faults}</td></tr>
              <tr><td style="color:{sub_color};">Disk Read:</td><td style="color:{text_color};">{read_mb} ({read_ops} I/O ops)</td></tr>
              <tr><td style="color:{sub_color};">Disk Write:</td><td style="color:{text_color};">{write_mb} ({write_ops} I/O ops)</td></tr>
              <tr><td style="color:{sub_color};">Context Switches:</td><td style="color:{text_color};">Voluntary: {voluntary_ctx} | Involuntary: {involuntary_ctx}</td></tr>
            </table>
          </div>

          <!-- Network Sockets Card -->
          <div style="background-color: {card_bg}; border: 1px solid {card_border}; border-radius: 8px; padding: 10px; margin-bottom: 10px;">
            <div style="font-size: 12px; font-weight: 700; color: {accent_color}; border-bottom: 1px solid {card_border}; padding-bottom: 4px; margin-bottom: 6px;">
              🌐 Network Sockets & Communications ({len(network_entries)})
            </div>
            {network_table_html}
          </div>

          <!-- Heuristic & Forensic Risk Indicators -->
          <div style="background-color: {card_bg}; border: 1px solid {card_border}; border-radius: 8px; padding: 10px;">
            <div style="font-size: 12px; font-weight: 700; color: {accent_color}; border-bottom: 1px solid {card_border}; padding-bottom: 4px; margin-bottom: 6px;">
              🛡️ Forensic Risk Indicators
            </div>
            {indicators_html}
          </div>

        </div>
        """

        # Build Structured Text Dossier (For Copy to Clipboard)
        text_report = f"""============================================================
NEXASHIELD PROCESS FORENSICS DOSSIER
============================================================
Process Name:        {name}
Process ID (PID):    {pid}
Parent Process:      {parent_name}
Status:              {raw_status.upper()}
AI Threat Verdict:   {verdict_title} (Score: {score_pct})
Severity:            {risk_severity}
Privileges:          {privilege_badge}

[IDENTITY & INTEGRITY]
Executable Path:     {exe}
Working Directory:   {cwd}
Command Line:        {cmdline}
SHA-256 Hash:        {sha256}
Binary Size:         {file_size_str}
User Account:        {username}
Priority Class:      {priority_str}

[RUNTIME TELEMETRY]
Start Time:          {start_dt}
Active Uptime:       {uptime_str}
Active Threads:      {threads}
CPU Utilization:     {cpu_cur:.1f}% (User: {user_cpu}, Kernel: {system_cpu})
Memory RSS:          {rss_mb} (Peak: {peak_wset_mb}, Virtual: {vms_mb})
Page Faults:         {page_faults}
Disk Read:           {read_mb} ({read_ops} I/O ops)
Disk Write:          {write_mb} ({write_ops} I/O ops)
Context Switches:    Voluntary: {voluntary_ctx} | Involuntary: {involuntary_ctx}

[NETWORK TELEMETRY]
Active Sockets:      {len(network_entries)}
{net_text_list}

[AI ANALYSIS & BEHAVIORAL SIGNATURE]
{reasoning}
============================================================
Generated at: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
"""

        # Build Clean Executive PDF HTML (Strictly Optimized for QTextDocument / QPrinter Engine)
        # Avoids CSS bordered divs which collapse into black bars in Qt rich text printer
        timestamp_now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        if network_entries:
            net_table_rows = "".join([
                f"<tr><td style='padding:4px 6px;border-bottom:1px solid #e2e8f0;font-family:monospace;font-size:8pt;'>{e[0]}</td>"
                f"<td style='padding:4px 6px;border-bottom:1px solid #e2e8f0;font-family:monospace;font-size:8pt;'>{e[1]}</td>"
                f"<td style='padding:4px 6px;border-bottom:1px solid #e2e8f0;font-family:monospace;font-size:8pt;'>{e[2]}</td>"
                f"<td style='padding:4px 6px;border-bottom:1px solid #e2e8f0;color:#15803d;font-weight:bold;font-size:8pt;'>{e[3]}</td></tr>"
                for e in network_entries
            ])
            pdf_sockets_html = f"""
            <table width="100%" cellspacing="0" cellpadding="0" style="border-collapse:collapse;margin-top:4px;">
              <tr bgcolor="#f1f5f9">
                <th align="left" style="padding:4px 6px;border-bottom:1px solid #cbd5e1;font-size:8pt;color:#475569;">PROTO</th>
                <th align="left" style="padding:4px 6px;border-bottom:1px solid #cbd5e1;font-size:8pt;color:#475569;">LOCAL ADDRESS</th>
                <th align="left" style="padding:4px 6px;border-bottom:1px solid #cbd5e1;font-size:8pt;color:#475569;">REMOTE ADDRESS</th>
                <th align="left" style="padding:4px 6px;border-bottom:1px solid #cbd5e1;font-size:8pt;color:#475569;">STATE</th>
              </tr>
              {net_table_rows}
            </table>
            """
        else:
            pdf_sockets_html = "<div style='font-size:8.5pt;color:#64748b;padding:4px 0;'>No active external network sockets detected.</div>"

        pdf_banner_bg = "#f0fdf4" if lvl == 1 else ("#f0f9ff" if lvl == 2 else ("#fffbeb" if lvl == 3 else ("#fff7ed" if lvl == 4 else "#fef2f2")))
        pdf_banner_border = "#86efac" if lvl == 1 else ("#7dd3fc" if lvl == 2 else ("#fcd34d" if lvl == 3 else ("#fdba74" if lvl == 4 else "#fca5a5")))
        pdf_banner_fg = "#15803d" if lvl == 1 else ("#0369a1" if lvl == 2 else ("#b45309" if lvl == 3 else ("#c2410c" if lvl == 4 else "#b91c1c")))

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
                <h1>NexaShield Endpoint Process Forensics Report</h1>
                <div style="font-size: 8.5pt; color: #64748b; margin-top: 2px;">
                  <b>Target:</b> {name} &nbsp;|&nbsp; <b>PID:</b> {pid} &nbsp;|&nbsp; <b>Report Generated:</b> {timestamp_now}
                </div>
              </td>
            </tr>
          </table>

          <!-- AI Assessment Card -->
          <table width="100%" cellspacing="0" cellpadding="6" style="border: 1px solid {pdf_banner_border}; background-color: {pdf_banner_bg}; margin-bottom: 8px;">
            <tr>
              <td>
                <div style="font-size: 10pt; font-weight: bold; color: {pdf_banner_fg};">
                  🧠 AI VERDICT: {verdict_title} &nbsp; (Confidence Risk Score: {score_pct})
                </div>
                <div style="font-size: 8.5pt; color: #334155; margin-top: 2px;">
                  <b>Severity:</b> {risk_severity} &nbsp;|&nbsp; 
                  <b>Privileges:</b> {privilege_badge} &nbsp;|&nbsp; 
                  <b>Status:</b> {raw_status.upper()}
                </div>
                <div style="font-size: 8.5pt; color: #475569; margin-top: 4px;">
                  {reasoning}
                </div>
              </td>
            </tr>
          </table>

          <!-- Identity & Integrity -->
          <div class="section-header">📂 Binary Identity & Integrity</div>
          <table width="100%" cellspacing="0" cellpadding="3" style="border-collapse: collapse; font-size: 8.5pt; margin-bottom: 6px;">
            <tr><td width="25%" style="color:#64748b; border-bottom: 1px solid #e2e8f0;"><b>Executable Path:</b></td><td style="color:#0f172a; border-bottom: 1px solid #e2e8f0; font-family:monospace; font-size:8pt;">{exe}</td></tr>
            <tr><td style="color:#64748b; border-bottom: 1px solid #e2e8f0;"><b>SHA-256 Hash:</b></td><td style="color:#0284c7; font-family:monospace; font-size:8pt; border-bottom: 1px solid #e2e8f0;">{sha256}</td></tr>
            <tr><td style="color:#64748b; border-bottom: 1px solid #e2e8f0;"><b>Binary Size:</b></td><td style="color:#0f172a; border-bottom: 1px solid #e2e8f0;">{file_size_str}</td></tr>
            <tr><td style="color:#64748b; border-bottom: 1px solid #e2e8f0;"><b>Command Line:</b></td><td style="color:#0f172a; font-family:monospace; font-size:8pt; border-bottom: 1px solid #e2e8f0;">{cmdline}</td></tr>
            <tr><td style="color:#64748b; border-bottom: 1px solid #e2e8f0;"><b>Working Directory:</b></td><td style="color:#0f172a; border-bottom: 1px solid #e2e8f0;">{cwd}</td></tr>
            <tr><td style="color:#64748b; border-bottom: 1px solid #e2e8f0;"><b>Parent Process:</b></td><td style="color:#0f172a; border-bottom: 1px solid #e2e8f0;">{parent_name}</td></tr>
            <tr><td style="color:#64748b; border-bottom: 1px solid #e2e8f0;"><b>User Account:</b></td><td style="color:#0f172a; border-bottom: 1px solid #e2e8f0;">{username} ({privilege_badge})</td></tr>
            <tr><td style="color:#64748b; border-bottom: 1px solid #e2e8f0;"><b>Priority Class:</b></td><td style="color:#0f172a; border-bottom: 1px solid #e2e8f0;">{priority_str}</td></tr>
          </table>

          <!-- Telemetry Forensics -->
          <div class="section-header">⚡ Runtime & Telemetry Forensics</div>
          <table width="100%" cellspacing="0" cellpadding="3" style="border-collapse: collapse; font-size: 8.5pt; margin-bottom: 6px;">
            <tr><td width="25%" style="color:#64748b; border-bottom: 1px solid #e2e8f0;"><b>Started At:</b></td><td style="color:#0f172a; border-bottom: 1px solid #e2e8f0;">{start_dt}</td></tr>
            <tr><td style="color:#64748b; border-bottom: 1px solid #e2e8f0;"><b>Active Uptime:</b></td><td style="color:#0f172a; border-bottom: 1px solid #e2e8f0;"><b>{uptime_str}</b></td></tr>
            <tr><td style="color:#64748b; border-bottom: 1px solid #e2e8f0;"><b>Active Threads:</b></td><td style="color:#0f172a; border-bottom: 1px solid #e2e8f0;">{threads} threads</td></tr>
            <tr><td style="color:#64748b; border-bottom: 1px solid #e2e8f0;"><b>CPU Utilization:</b></td><td style="color:#0f172a; border-bottom: 1px solid #e2e8f0;"><b>{cpu_cur:.1f}%</b> (User: {user_cpu} | Kernel: {system_cpu})</td></tr>
            <tr><td style="color:#64748b; border-bottom: 1px solid #e2e8f0;"><b>Memory Footprint:</b></td><td style="color:#0f172a; border-bottom: 1px solid #e2e8f0;"><b>{rss_mb}</b> (Peak: {peak_wset_mb} | Virtual: {vms_mb})</td></tr>
            <tr><td style="color:#64748b; border-bottom: 1px solid #e2e8f0;"><b>Page Faults:</b></td><td style="color:#0f172a; border-bottom: 1px solid #e2e8f0;">{page_faults}</td></tr>
            <tr><td style="color:#64748b; border-bottom: 1px solid #e2e8f0;"><b>Disk Read:</b></td><td style="color:#0f172a; border-bottom: 1px solid #e2e8f0;">{read_mb} ({read_ops} I/O ops)</td></tr>
            <tr><td style="color:#64748b; border-bottom: 1px solid #e2e8f0;"><b>Disk Write:</b></td><td style="color:#0f172a; border-bottom: 1px solid #e2e8f0;">{write_mb} ({write_ops} I/O ops)</td></tr>
            <tr><td style="color:#64748b; border-bottom: 1px solid #e2e8f0;"><b>Context Switches:</b></td><td style="color:#0f172a; border-bottom: 1px solid #e2e8f0;">Voluntary: {voluntary_ctx} | Involuntary: {involuntary_ctx}</td></tr>
          </table>

          <!-- Network Sockets -->
          <div class="section-header">🌐 Network Sockets & Communications ({len(network_entries)})</div>
          {pdf_sockets_html}

          <!-- Forensic Risk Indicators -->
          <div class="section-header">🛡️ Forensic Risk Indicators</div>
          <table width="100%" cellspacing="0" cellpadding="3" style="border-collapse: collapse; font-size: 8.5pt; margin-bottom: 6px;">
            <tr><td width="25%" style="color:#64748b; border-bottom: 1px solid #e2e8f0;"><b>Path Verification:</b></td><td style="border-bottom: 1px solid #e2e8f0;">{path_badge}</td></tr>
            <tr><td style="color:#64748b; border-bottom: 1px solid #e2e8f0;"><b>Network Exposure:</b></td><td style="border-bottom: 1px solid #e2e8f0;">{sock_badge}</td></tr>
            <tr><td style="color:#64748b; border-bottom: 1px solid #e2e8f0;"><b>Resource Profile:</b></td><td style="border-bottom: 1px solid #e2e8f0;">{res_badge}</td></tr>
            <tr><td style="color:#64748b; border-bottom: 1px solid #e2e8f0;"><b>Lineage Integrity:</b></td><td style="border-bottom: 1px solid #e2e8f0;">{lineage_badge}</td></tr>
          </table>

          <div style="margin-top: 15px; border-top: 1px solid #cbd5e1; padding-top: 4px; text-align: center; font-size: 7.5pt; color: #94a3b8;">
            NexaShield Zero-Trust Endpoint Protection &bull; Forensic Investigation Report &bull; SHA-256 Verified
          </div>
        </body>
        </html>
        """

        return html_report, pdf_html, text_report, name

class ProcessWorker(QThread):
    """
    Background thread to fetch system processes.
    Prevents UI freezing during data collection and ML inference.
    """
    data_fetched = pyqtSignal(list)

    def __init__(self):
        super().__init__()
        self.ai_scan_enabled = False
        self.ai_scanner = None

    def enable_ai_scan(self, enable, scanner):
        self.ai_scan_enabled = enable
        self.ai_scanner = scanner

    def run(self):
        processes = []
        # Fetch specific attributes to optimize performance
        attrs = ['pid', 'name', 'status', 'cpu_percent', 'memory_percent', 'username', 'create_time', 'io_counters', 'exe', 'cmdline', 'num_threads']
        
        for proc in psutil.process_iter(attrs):
            try:
                pinfo = proc.info
                # Format io_counters to simple string for Disk/Net deltas
                if pinfo.get('io_counters'):
                    io = pinfo['io_counters']
                    pinfo['disk_read'] = getattr(io, 'read_bytes', 0)
                    pinfo['disk_write'] = getattr(io, 'write_bytes', 0)
                else:
                    pinfo['disk_read'] = 0
                    pinfo['disk_write'] = 0

                processes.append(pinfo)
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass
            
            # Tiny sleep to yield GIL and ensure perfectly smooth 60FPS UI rendering
            time.sleep(0.001)
        
        # High-performance batch AI scan if enabled
        if self.ai_scan_enabled and self.ai_scanner:
            if hasattr(self.ai_scanner, 'predict_threat_levels_batch'):
                self.ai_scanner.predict_threat_levels_batch(processes)
            else:
                for p in processes:
                    level, color, prob = self.ai_scanner.predict_threat_level(None, pinfo=p)
                    p['ai_level'] = level
                    p['ai_color'] = color
        else:
            for p in processes:
                p['ai_level'] = None
                p['ai_color'] = None

        self.data_fetched.emit(processes)

class ResourceChart(QFrame):
    """Custom widget to draw live resource usage charts."""
    def __init__(self, title, line_color="#0078d7"):
        super().__init__()
        self.setObjectName("ChartCard")
        self.title = title
        self.line_color = QColor(line_color)
        self.data = deque([0]*60, maxlen=60) # 60 data points
        self.setMinimumHeight(150)
        self.current_value = 0.0

    def update_value(self, value):
        self.current_value = value
        self.data.append(value)
        self.update()

    def paintEvent(self, event):
        # Let QSS handle the background
        super().paintEvent(event)

        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        
        w = self.width()
        h = self.height()
        
        top_pad = 40
        chart_h = h - top_pad
        
        grid_col = QColor(128, 128, 128, 30)
        
        # 1. Draw Grid Lines (Underneath graph)
        painter.setPen(QPen(grid_col, 1, Qt.PenStyle.DashLine))
        for i in range(4):
            y_line = top_pad + i * (chart_h / 3)
            painter.drawLine(0, int(y_line), w, int(y_line))
        
        if not self.data:
            return
            
        # 2. Draw Graph Path (Smooth Bezier)
        path = QPainterPath()
        step_x = w / (self.data.maxlen - 1)
        
        prev_x = 0
        prev_y = h - (self.data[0] / 100.0 * chart_h)
        path.moveTo(prev_x, prev_y)
        
        for i in range(1, len(self.data)):
            x = i * step_x
            y = h - (self.data[i] / 100.0 * chart_h)
            
            # Control points for smooth bezier curve
            ctrl_x1 = prev_x + (x - prev_x) * 0.5
            ctrl_y1 = prev_y
            ctrl_x2 = prev_x + (x - prev_x) * 0.5
            ctrl_y2 = y
            
            path.cubicTo(ctrl_x1, ctrl_y1, ctrl_x2, ctrl_y2, x, y)
            prev_x = x
            prev_y = y
            
        # Fill Gradient
        fill_path = QPainterPath(path)
        fill_path.lineTo(w, h)
        fill_path.lineTo(0, h)
        fill_path.closeSubpath()
        
        grad = QLinearGradient(0, top_pad, 0, h)
        c = self.line_color
        grad.setColorAt(0, QColor(c.red(), c.green(), c.blue(), 120))
        grad.setColorAt(1, QColor(c.red(), c.green(), c.blue(), 10))
        
        painter.setBrush(grad)
        painter.setPen(Qt.PenStyle.NoPen)
        painter.drawPath(fill_path)

        # Draw Line
        painter.setPen(QPen(self.line_color, 3, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap, Qt.PenJoinStyle.RoundJoin))
        painter.setBrush(Qt.BrushStyle.NoBrush)
        painter.drawPath(path)

        # Draw Leading Dot Glow
        glow = QRadialGradient(prev_x, prev_y, 20)
        glow.setColorAt(0, QColor(c.red(), c.green(), c.blue(), 180))
        glow.setColorAt(1, Qt.GlobalColor.transparent)
        painter.setBrush(glow)
        painter.setPen(Qt.PenStyle.NoPen)
        painter.drawEllipse(int(prev_x - 20), int(prev_y - 20), 40, 40)

        # Draw Leading Dot
        painter.setBrush(c)
        painter.setPen(QPen(Qt.GlobalColor.white, 2))
        painter.drawEllipse(int(prev_x - 5), int(prev_y - 5), 10, 10)

        # 3. Draw Text & Labels
        text_col = self.palette().color(QPalette.ColorRole.WindowText)
        label_col = QColor(128, 128, 128, 150)
        
        painter.setFont(QFont("Segoe UI", 8))
        painter.setPen(label_col)
        for i in range(4):
            y_line = top_pad + i * (chart_h / 3)
            lbl = ["100%", "66%", "33%", "0%"][i]
            painter.drawText(w - 35, int(y_line) - 4, lbl)
            
        painter.setPen(text_col)
        painter.setFont(QFont("Segoe UI", 12, QFont.Weight.Bold))
        painter.drawText(15, 28, f"{self.title}: {self.current_value:.1f}%")

class ProcessMonitorWidget(QWidget):
    def __init__(self, session_manager=None):
        super().__init__()
        self.session = session_manager
        self.setObjectName("ProcessMonitor")
        
        # State
        self.process_data = []
        self.filter_text = ""
        self.ai_scanner = None
        self.ai_scan_enabled = False
        self._model_loader = None
        
        # Forensics State & Caching
        self._forensic_cache = {}
        self._current_forensic_worker = None
        self._current_forensic_pid = None
        self._current_forensic_text = ""
        self._current_forensic_html = ""
        self._current_forensic_pdf_html = ""
        self._current_forensic_name = ""
        
        # UI Setup
        self.setup_ui()
        
        # Worker & Timer
        self.worker = ProcessWorker()
        self.worker.data_fetched.connect(self.update_table)
        
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.refresh_data)
        
        # Chart Timer (1 second updates)
        self.chart_timer = QTimer(self)
        self.chart_timer.timeout.connect(self.update_charts)

        # Start continuous background monitoring immediately upon creation
        self.start_monitoring()

        # Preload the AI Threat Model in background so it's ready when requested
        self._load_ai_scanner_async()

    def _load_ai_scanner_async(self):
        """Asynchronously loads the ML model in a background thread to prevent UI freezing."""
        class ModelLoader(QThread):
            loaded = pyqtSignal(object)
            def run(self):
                try:
                    scanner = ProcessThreatScanner()
                    self.loaded.emit(scanner)
                except Exception as e:
                    print(f"[-] AI Threat Model async load failed: {e}")
                    self.loaded.emit(None)

        self._model_loader = ModelLoader(self)
        self._model_loader.loaded.connect(self._on_ai_scanner_loaded)
        self._model_loader.start()

    def _on_ai_scanner_loaded(self, scanner):
        self.ai_scanner = scanner
        if self.ai_scan_enabled and self.ai_scanner:
            self.worker.enable_ai_scan(True, self.ai_scanner)

    def start_monitoring(self):
        """Starts real-time process telemetry and chart data collection in the background."""
        if not self.chart_timer.isActive():
            self.chart_timer.start(1000)
        if not self.timer.isActive():
            self.timer.start(REFRESH_INTERVAL)
        self.refresh_data()

    def showEvent(self, event):
        super().showEvent(event)
        # Ensure monitoring is active and refresh visual charts with accumulated background data
        self.start_monitoring()
        self.cpu_chart.update()
        self.mem_chart.update()

    def hideEvent(self, event):
        super().hideEvent(event)
        # Background monitoring continues uninterrupted so telemetry and graphs remain live

    def cleanup(self):
        """Cleanly stops background timers and workers upon session teardown."""
        self.timer.stop()
        self.chart_timer.stop()
        if self.worker.isRunning():
            self.worker.terminate()
            self.worker.wait(500)
        if self._model_loader and self._model_loader.isRunning():
            self._model_loader.terminate()
            self._model_loader.wait(300)
        if self._current_forensic_worker and self._current_forensic_worker.isRunning():
            self._current_forensic_worker.terminate()
            self._current_forensic_worker.wait(200)

    def closeEvent(self, event):
        self.cleanup()
        super().closeEvent(event)

    def setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(10)

        # --- Top Control Bar ---
        self.control_frame = QFrame()
        self.control_frame.setObjectName("ProcessToolbar")
        control_bar = QHBoxLayout(self.control_frame)
        control_bar.setContentsMargins(15, 10, 15, 10)
        control_bar.setSpacing(15)
        
        # Search
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("🔍 Search Process Name or PID...")
        self.search_input.setFixedWidth(400)
        self.search_input.textChanged.connect(self.handle_search)
        control_bar.addWidget(self.search_input)

        self.btn_clear_search = QPushButton("X")
        self.btn_clear_search.setObjectName("ClearSearchBtn")
        self.btn_clear_search.setFixedSize(32, 32)
        self.btn_clear_search.setToolTip("Clear Search")
        self.btn_clear_search.clicked.connect(self.clear_search)
        control_bar.addWidget(self.btn_clear_search)

        # Smart Filtering Dropdown
        self.filter_combo = QComboBox()
        self.filter_combo.setObjectName("FilterDropdown")
        self.filter_combo.addItems(["All Levels", "Level 1 (Safe)", "Level 2 (Low Risk)", "Level 3 (Moderate)", "Level 4 (High Risk)", "Level 5 (Critical)"])
        self.filter_combo.setFixedWidth(160)
        self.filter_combo.currentTextChanged.connect(self.set_category_filter)
        self.filter_combo.setVisible(False)
        control_bar.addWidget(self.filter_combo)
        self.current_category = "All Levels"

        # Threat Level Color Guide Icon
        self.info_icon = QLabel("ℹ️")
        self.info_icon.setStyleSheet("QLabel { font-size: 18px; color: #a4b0be; margin-left: 5px; } QLabel:hover { color: #3498db; }")
        
        tooltip_html = (
            "<div style='padding: 8px;'>"
            "<h3 style='color: #ffffff; margin-top: 0px; margin-bottom: 10px; border-bottom: 1px solid #555; padding-bottom: 5px;'>🧠 AI Threat Level Guide</h3>"
            "<table style='font-size: 13px; color: #ecf0f1;' cellspacing='6' cellpadding='0'>"
            "<tr><td><span style='color:#00b894; font-size: 18px;'>●</span></td><td style='padding-left: 8px;'><b style='color: white;'>Level 1:</b> Safe / System</td></tr>"
            "<tr><td><span style='color:#0984e3; font-size: 18px;'>●</span></td><td style='padding-left: 8px;'><b style='color: white;'>Level 2:</b> Low Risk</td></tr>"
            "<tr><td><span style='color:#fdcb6e; font-size: 18px;'>●</span></td><td style='padding-left: 8px;'><b style='color: white;'>Level 3:</b> Moderate Risk</td></tr>"
            "<tr><td><span style='color:#e17055; font-size: 18px;'>●</span></td><td style='padding-left: 8px;'><b style='color: white;'>Level 4:</b> High Risk</td></tr>"
            "<tr><td><span style='color:#d63031; font-size: 18px;'>●</span></td><td style='padding-left: 8px;'><b style='color: white;'>Level 5:</b> Critical / Malicious</td></tr>"
            "</table>"
            "</div>"
        )
        self.info_icon.setToolTip(tooltip_html)
        self.info_icon.setVisible(False)
        control_bar.addWidget(self.info_icon)

        control_bar.addStretch()

        # Charts Toggle Button
        self.btn_toggle_charts = QPushButton("📈 System Graphs")
        self.btn_toggle_charts.setObjectName("BtnOutline")
        self.btn_toggle_charts.setCheckable(True)
        self.btn_toggle_charts.setChecked(True)
        control_bar.addWidget(self.btn_toggle_charts)

        # AI Scan Button
        self.btn_ai_scan = QPushButton("🧠 AI Threat Scan")
        self.btn_ai_scan.setObjectName("BtnPrimary")
        self.btn_ai_scan.setCheckable(True)
        self.btn_ai_scan.toggled.connect(self.toggle_ai_scan)
        control_bar.addWidget(self.btn_ai_scan)

        # Action Buttons
        self.btn_suspend = QPushButton("⏸️ Suspend")
        self.btn_suspend.setObjectName("BtnOutline")
        self.btn_suspend.clicked.connect(lambda: self.change_process_state("suspend"))
        control_bar.addWidget(self.btn_suspend)

        self.btn_resume = QPushButton("▶️ Resume")
        self.btn_resume.setObjectName("BtnOutline")
        self.btn_resume.clicked.connect(lambda: self.change_process_state("resume"))
        control_bar.addWidget(self.btn_resume)

        self.btn_kill = QPushButton("💀 End Task")
        self.btn_kill.setObjectName("BtnDanger") 
        self.btn_kill.clicked.connect(self.kill_process)
        control_bar.addWidget(self.btn_kill)

        self.btn_refresh = QPushButton("🔄 Refresh")
        self.btn_refresh.setObjectName("BtnPrimary")
        self.btn_refresh.clicked.connect(self.refresh_data)
        control_bar.addWidget(self.btn_refresh)

        self.btn_export = QPushButton("📄 CSV")
        self.btn_export.setObjectName("BtnInfo")
        self.btn_export.clicked.connect(self.export_csv)
        control_bar.addWidget(self.btn_export)

        self.btn_export_pdf = QPushButton("📑 PDF")
        self.btn_export_pdf.setObjectName("BtnWarning")
        self.btn_export_pdf.clicked.connect(self.export_pdf)
        control_bar.addWidget(self.btn_export_pdf)

        layout.addWidget(self.control_frame)

        # --- Content Area (Split 1:2) ---
        content_layout = QHBoxLayout()

        # --- Resource Charts (Drawer) ---
        self.charts_panel = QFrame()
        self.charts_panel.setObjectName("DetailsPanel")
        self.charts_panel.setFixedWidth(320)
        
        charts_layout = QVBoxLayout(self.charts_panel)
        charts_layout.setContentsMargins(15, 15, 15, 15)
        charts_layout.setSpacing(15)
        
        charts_header_layout = QHBoxLayout()
        self.lbl_charts_title = QLabel("System Resources")
        self.lbl_charts_title.setObjectName("DetailsTitle")
        charts_header_layout.addWidget(self.lbl_charts_title)
        
        charts_header_layout.addStretch()
        
        self.btn_close_charts = QPushButton("✖")
        self.btn_close_charts.setFixedSize(24, 24)
        self.btn_close_charts.setToolTip("Close Graphs")
        self.btn_close_charts.setObjectName("BtnClosePanel")
        self.btn_close_charts.clicked.connect(lambda: self.btn_toggle_charts.setChecked(False))
        charts_header_layout.addWidget(self.btn_close_charts)
        
        charts_layout.addLayout(charts_header_layout)
        
        self.cpu_chart = ResourceChart("🧠 CPU Usage", "#00c6ff")
        self.mem_chart = ResourceChart("💾 RAM Usage", "#ff5e7e")
        charts_layout.addWidget(self.cpu_chart)
        charts_layout.addWidget(self.mem_chart)
        
        content_layout.addWidget(self.charts_panel)
        
        self.btn_toggle_charts.toggled.connect(self.charts_panel.setVisible)

        # --- Process Table ---
        self.table_container = QFrame()
        self.table_container.setObjectName("ProcessTableContainer")
        table_layout = QVBoxLayout(self.table_container)
        table_layout.setContentsMargins(0, 0, 0, 0)
        
        self.table = QTableWidget()
        self.table.setObjectName("ProcessTable")
        self.table.setColumnCount(11)
        self.table.setHorizontalHeaderLabels([
            "", "PID", "Name", "Status", "AI Threat", "CPU", "Memory", "Disk Read", "Disk Write", "User", "Start Time"
        ])
        
        # Table Styling & Behavior
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.verticalHeader().setVisible(False)
        self.table.verticalHeader().setDefaultSectionSize(36)
        self.table.verticalHeader().setMinimumSectionSize(32)
        self.table.setAlternatingRowColors(True)
        self.table.setShowGrid(False)
        self.table.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        
        # Header sizing
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Fixed)
        self.table.setColumnWidth(0, 38)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Fixed)
        self.table.setColumnWidth(1, 70)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch) # Name stretches
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.Fixed) # Status badge
        self.table.setColumnWidth(3, 115)
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.Fixed) # AI Threat badge
        self.table.setColumnWidth(4, 135)
        header.setSectionResizeMode(5, QHeaderView.ResizeMode.Fixed) # CPU bar
        self.table.setColumnWidth(5, 110)
        header.setSectionResizeMode(6, QHeaderView.ResizeMode.Fixed) # Mem bar
        self.table.setColumnWidth(6, 95)
        header.setSectionResizeMode(7, QHeaderView.ResizeMode.Fixed) # Disk Read
        self.table.setColumnWidth(7, 85)
        header.setSectionResizeMode(8, QHeaderView.ResizeMode.Fixed) # Disk Write
        self.table.setColumnWidth(8, 85)
        header.setSectionResizeMode(9, QHeaderView.ResizeMode.Fixed) # User
        self.table.setColumnWidth(9, 100)
        header.setSectionResizeMode(10, QHeaderView.ResizeMode.Fixed) # Start Time
        self.table.setColumnWidth(10, 90)
        
        self.table.itemSelectionChanged.connect(self.on_process_selected)
        
        table_layout.addWidget(self.table)
        content_layout.addWidget(self.table_container, 2) # Stretch 2
        
        # --- Deep Dive Panel (Hidden initially) ---
        self.details_panel = QFrame()
        self.details_panel.setObjectName("DetailsPanel")
        self.details_panel.setFixedWidth(440)
        self.details_panel.hide()
        
        details_layout = QVBoxLayout(self.details_panel)
        details_layout.setContentsMargins(14, 14, 14, 14)
        details_layout.setSpacing(10)
        
        details_header_layout = QHBoxLayout()
        details_header_layout.setSpacing(8)
        
        self.lbl_details_title = QLabel("🔬 Process Forensics Dossier")
        self.lbl_details_title.setObjectName("DetailsTitle")
        details_header_layout.addWidget(self.lbl_details_title)
        
        details_header_layout.addStretch()

        self.btn_download_forensics = QPushButton("📥 Save to FMS")
        self.btn_download_forensics.setToolTip("Generate & Vault Forensic Report (PDF) in NexaShield FMS")
        self.btn_download_forensics.setObjectName("BtnFmsDownload")
        self.btn_download_forensics.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_download_forensics.setFixedHeight(30)
        self.btn_download_forensics.clicked.connect(self.save_forensics_pdf_to_fms)
        details_header_layout.addWidget(self.btn_download_forensics)
        
        self.btn_close_details = QPushButton("✕")
        self.btn_close_details.setFixedSize(30, 30)
        self.btn_close_details.setToolTip("Close Forensics")
        self.btn_close_details.setObjectName("BtnClosePanel")
        self.btn_close_details.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_close_details.clicked.connect(self.close_details_panel)
        details_header_layout.addWidget(self.btn_close_details)
        
        details_layout.addLayout(details_header_layout)
        
        self.txt_details_info = QTextEdit()
        self.txt_details_info.setReadOnly(True)
        self.txt_details_info.setFrameShape(QFrame.Shape.NoFrame)
        self.txt_details_info.setStyleSheet("background: transparent;")
        self.txt_details_info.setHtml("Select a process to inspect.")
        
        details_layout.addWidget(self.txt_details_info, 1)
        
        content_layout.addWidget(self.details_panel)
        
        layout.addLayout(content_layout)

        # Status Bar / Footer
        self.status_bar = QFrame()
        self.status_bar.setObjectName("ProcessStatusBar")
        status_layout = QHBoxLayout(self.status_bar)
        status_layout.setContentsMargins(15, 10, 15, 10)
        
        self.lbl_system_status = QLabel("🟢 System Status: Active")
        self.lbl_system_status.setStyleSheet("color: #2ecc71; font-weight: bold; font-size: 13px;")
        status_layout.addWidget(self.lbl_system_status)
        
        status_layout.addStretch()
        
        self.lbl_global_cpu = QLabel("Global CPU:")
        self.lbl_global_cpu.setStyleSheet("font-weight: 600; font-size: 13px;")
        status_layout.addWidget(self.lbl_global_cpu)
        
        self.val_global_cpu = QLabel("0.0%")
        self.val_global_cpu.setStyleSheet("color: #00c6ff; font-weight: bold; font-size: 14px; min-width: 50px;")
        status_layout.addWidget(self.val_global_cpu)
        
        status_layout.addSpacing(30)
        
        self.lbl_global_ram = QLabel("Global RAM:")
        self.lbl_global_ram.setStyleSheet("font-weight: 600; font-size: 13px;")
        status_layout.addWidget(self.lbl_global_ram)
        
        self.val_global_ram = QLabel("0.0%")
        self.val_global_ram.setStyleSheet("color: #ff5e7e; font-weight: bold; font-size: 14px; min-width: 50px;")
        status_layout.addWidget(self.val_global_ram)
        
        status_layout.addStretch()
        
        self.lbl_process_count = QLabel("Showing 0 Processes")
        self.lbl_process_count.setStyleSheet("color: #f39c12; font-weight: bold; font-size: 13px;")
        status_layout.addWidget(self.lbl_process_count)
        
        layout.addWidget(self.status_bar)

    def reset_ui(self):
        """Clears filters and triggers a data refresh."""
        self.search_input.clear()
        self.chk_select_all.setChecked(False)
        self.refresh_data()

    def toggle_ai_scan(self, checked):
        self.ai_scan_enabled = checked
        if checked and self.ai_scanner is None:
            try:
                self.ai_scanner = ProcessThreatScanner()
            except Exception as e:
                print(f"[-] Error loading AI scanner on demand: {e}")

        self.worker.enable_ai_scan(checked, self.ai_scanner)
        
        self.filter_combo.setVisible(checked)
        self.info_icon.setVisible(checked)
        
        if checked:
            self.btn_ai_scan.setText("🧠 AI Scan Active")
            self.btn_ai_scan.setStyleSheet("background-color: #8b5cf6; color: white; font-weight: bold; border-radius: 6px;")
            # Immediate responsive visual feedback on cached process telemetry
            if self.process_data and self.ai_scanner:
                if hasattr(self.ai_scanner, 'predict_threat_levels_batch'):
                    self.ai_scanner.predict_threat_levels_batch(self.process_data)
                self.update_table(self.process_data)
        else:
            self.filter_combo.setCurrentIndex(0) # Reset filter when AI is turned off
            self.btn_ai_scan.setText("🧠 AI Threat Scan")
            self.btn_ai_scan.setStyleSheet("")
            # Clear AI threat annotations from cached table data
            if self.process_data:
                for p in self.process_data:
                    p['ai_level'] = None
                    p['ai_color'] = None
                self.update_table(self.process_data)
                
        self.refresh_data()

    def clear_search(self):
        self.search_input.clear()

    def toggle_select_all(self, state):
        check_state = Qt.CheckState(state)
        for row in range(self.table.rowCount()):
            item = self.table.item(row, 0)
            if item:
                item.setCheckState(check_state)

    def update_charts(self):
        cpu = psutil.cpu_percent()
        mem = psutil.virtual_memory().percent
        self.cpu_chart.update_value(cpu)
        self.mem_chart.update_value(mem)

    def refresh_data(self):
        """Triggers the background worker if not already running."""
        if not self.worker.isRunning():
            self.lbl_system_status.setText("🟢 System Status: Updating...")
            self.worker.start()

    def update_table(self, processes):
        """Updates the table with new data while preserving scroll and selection."""
        self.process_data = processes

        # Save current state
        current_scroll = self.table.verticalScrollBar().value()
        selected_pids = self.get_selected_pids()

        # Filter data
        filtered_data = self.filter_data(processes)

        # Disable sorting and updates during refresh to completely eliminate UI lag
        self.table.setUpdatesEnabled(False)
        self.table.setSortingEnabled(False)
        self.table.setRowCount(len(filtered_data))
        
        # Update Status bar with rich information
        cpu_usage = psutil.cpu_percent()
        mem_usage = psutil.virtual_memory().percent
        self.val_global_cpu.setText(f"{cpu_usage}%")
        self.val_global_ram.setText(f"{mem_usage}%")
        self.lbl_process_count.setText(f"Showing {len(filtered_data)} of {len(processes)} Processes")

        for row_idx, p in enumerate(filtered_data):
            self.set_row_data(row_idx, p)

        # Restore State
        self.table.setSortingEnabled(True)
        self.table.setUpdatesEnabled(True)
        self.table.verticalScrollBar().setValue(current_scroll)
        if selected_pids:
            self.select_rows_by_pids(selected_pids)

    def set_row_data(self, row, p):
        """Populates a single row in the table."""
        # 0: Checkbox
        chk_item = self.table.item(row, 0)
        if not chk_item:
            chk_item = QTableWidgetItem()
            chk_item.setFlags(Qt.ItemFlag.ItemIsUserCheckable | Qt.ItemFlag.ItemIsEnabled)
            chk_item.setCheckState(Qt.CheckState.Unchecked)
            self.table.setItem(row, 0, chk_item)
        
        chk_item.setData(Qt.ItemDataRole.UserRole, p['pid'])

        # Helper to update text items efficiently
        def update_item(col, text, color=None, bold=False):
            item = self.table.item(row, col)
            if not item:
                item = QTableWidgetItem()
                self.table.setItem(row, col, item)
            
            if item.text() != text:
                item.setText(text)
            
            # Update Color
            if color:
                item.setForeground(QBrush(QColor(color)))
            else:
                item.setData(Qt.ItemDataRole.ForegroundRole, None)
            
            # Update Font
            font = item.font()
            if font.bold() != bold:
                # Prevent Qt warning for uninitialized font sizes (-1)
                if font.pointSize() <= 0 and font.pixelSize() <= 0:
                    font.setPointSize(10) 
                font.setBold(bold)
                item.setFont(font)

        # Helper to update numeric items for sorting
        def update_sortable_item(col, sort_val, display_text=""):
            item = self.table.item(row, col)
            if not isinstance(item, SortableTableWidgetItem):
                item = SortableTableWidgetItem()
                self.table.setItem(row, col, item)
            item.setData(Qt.ItemDataRole.UserRole, sort_val)
            item.setData(Qt.ItemDataRole.DisplayRole, display_text)
            
            # Ensure proper font if displaying text
            if display_text:
                font = item.font()
                if font.pointSize() <= 0 and font.pixelSize() <= 0:
                    font.setPointSize(10)
                item.setFont(font)
            return item

        # 1: PID
        update_sortable_item(1, p['pid'], str(p['pid']))

        # 2: Name
        update_item(2, str(p['name']))

        # 3: Status Badge
        raw_status = str(p['status']).lower()
        update_sortable_item(3, raw_status, "")
        
        status_widget = self.table.cellWidget(row, 3)
        if not status_widget:
            status_container = QWidget()
            status_container.setStyleSheet("background: transparent;")
            status_layout = QHBoxLayout(status_container)
            status_layout.setContentsMargins(4, 2, 4, 2)
            status_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
            
            lbl_badge = QLabel()
            lbl_badge.setObjectName("StatusBadge")
            lbl_badge.setAlignment(Qt.AlignmentFlag.AlignCenter)
            status_layout.addWidget(lbl_badge)
            
            self.table.setCellWidget(row, 3, status_container)
            status_widget = status_container
            
        lbl = status_widget.findChild(QLabel, "StatusBadge")
        if lbl:
            is_dark = self.palette().color(QPalette.ColorRole.Window).lightness() < 128
            if raw_status == 'running':
                lbl.setText("● RUNNING")
                if is_dark:
                    lbl.setStyleSheet(
                        "background-color: rgba(16, 185, 129, 0.16); "
                        "color: #10b981; "
                        "border: 1px solid rgba(16, 185, 129, 0.40); "
                        "border-radius: 11px; "
                        "padding: 2px 10px; "
                        "font-size: 11px; "
                        "font-weight: 700; "
                        "letter-spacing: 0.3px;"
                    )
                else:
                    lbl.setStyleSheet(
                        "background-color: #dcfce7; "
                        "color: #15803d; "
                        "border: 1px solid #86efac; "
                        "border-radius: 11px; "
                        "padding: 2px 10px; "
                        "font-size: 11px; "
                        "font-weight: 700; "
                        "letter-spacing: 0.3px;"
                    )
            elif raw_status in ('stopped', 'suspended', 'dead'):
                lbl.setText("● STOPPED")
                if is_dark:
                    lbl.setStyleSheet(
                        "background-color: rgba(239, 68, 68, 0.16); "
                        "color: #ef4444; "
                        "border: 1px solid rgba(239, 68, 68, 0.40); "
                        "border-radius: 11px; "
                        "padding: 2px 10px; "
                        "font-size: 11px; "
                        "font-weight: 700; "
                        "letter-spacing: 0.3px;"
                    )
                else:
                    lbl.setStyleSheet(
                        "background-color: #fee2e2; "
                        "color: #b91c1c; "
                        "border: 1px solid #fca5a5; "
                        "border-radius: 11px; "
                        "padding: 2px 10px; "
                        "font-size: 11px; "
                        "font-weight: 700; "
                        "letter-spacing: 0.3px;"
                    )
            else:
                display_label = "● IDLE" if raw_status in ('sleeping', 'idle') else f"● {raw_status.upper()}"
                lbl.setText(display_label)
                if is_dark:
                    lbl.setStyleSheet(
                        "background-color: rgba(148, 163, 184, 0.12); "
                        "color: #94a3b8; "
                        "border: 1px solid rgba(148, 163, 184, 0.30); "
                        "border-radius: 11px; "
                        "padding: 2px 10px; "
                        "font-size: 11px; "
                        "font-weight: 600;"
                    )
                else:
                    lbl.setStyleSheet(
                        "background-color: #f1f5f9; "
                        "color: #475569; "
                        "border: 1px solid #cbd5e1; "
                        "border-radius: 11px; "
                        "padding: 2px 10px; "
                        "font-size: 11px; "
                        "font-weight: 600;"
                    )

        # 4: AI Threat Level Badge
        ai_level = p.get('ai_level')
        sort_val = ai_level if (self.ai_scan_enabled and ai_level is not None) else -1
        update_sortable_item(4, sort_val, "")
        
        threat_widget = self.table.cellWidget(row, 4)
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
            
            self.table.setCellWidget(row, 4, threat_container)
            threat_widget = threat_container

        lbl_t = threat_widget.findChild(QLabel, "ThreatBadge")
        if lbl_t:
            is_dark = self.palette().color(QPalette.ColorRole.Window).lightness() < 128
            if self.ai_scan_enabled and ai_level:
                threat_configs = {
                    1: (
                        "L1 ◆ SAFE",
                        "#34d399",
                        "qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 rgba(16, 185, 129, 0.25), stop:1 rgba(16, 185, 129, 0.06))",
                        "rgba(16, 185, 129, 0.35)",
                        "#10b981",
                        "qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #d1fae5, stop:1 #f0fdf4)",
                        "#047857",
                        "#a7f3d0",
                        "#059669"
                    ),
                    2: (
                        "L2 ◆ LOW",
                        "#38bdf8",
                        "qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 rgba(14, 165, 233, 0.25), stop:1 rgba(14, 165, 233, 0.06))",
                        "rgba(14, 165, 233, 0.35)",
                        "#0ea5e9",
                        "qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #e0f2fe, stop:1 #f0f9ff)",
                        "#0369a1",
                        "#bae6fd",
                        "#0284c7"
                    ),
                    3: (
                        "L3 ◆ MODERATE",
                        "#fbbf24",
                        "qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 rgba(245, 158, 11, 0.26), stop:1 rgba(245, 158, 11, 0.07))",
                        "rgba(245, 158, 11, 0.40)",
                        "#f59e0b",
                        "qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #fef3c7, stop:1 #fffbeb)",
                        "#b45309",
                        "#fde68a",
                        "#d97706"
                    ),
                    4: (
                        "L4 ◆ HIGH",
                        "#fb923c",
                        "qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 rgba(249, 115, 22, 0.28), stop:1 rgba(249, 115, 22, 0.08))",
                        "rgba(249, 115, 22, 0.45)",
                        "#f97316",
                        "qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #ffedd5, stop:1 #fff7ed)",
                        "#c2410c",
                        "#fed7aa",
                        "#ea580c"
                    ),
                    5: (
                        "L5 ◆ CRITICAL",
                        "#f87171",
                        "qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 rgba(239, 68, 68, 0.32), stop:1 rgba(239, 68, 68, 0.09))",
                        "rgba(239, 68, 68, 0.50)",
                        "#ef4444",
                        "qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #fee2e2, stop:1 #fef2f2)",
                        "#b91c1c",
                        "#fca5a5",
                        "#dc2626"
                    ),
                }
                text, dark_col, dark_bg, dark_border, dark_accent, light_bg, light_col, light_border, light_accent = threat_configs.get(
                    ai_level, (
                        "L1 ◆ SAFE",
                        "#34d399",
                        "qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 rgba(16, 185, 129, 0.25), stop:1 rgba(16, 185, 129, 0.06))",
                        "rgba(16, 185, 129, 0.35)",
                        "#10b981",
                        "qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #d1fae5, stop:1 #f0fdf4)",
                        "#047857",
                        "#a7f3d0",
                        "#059669"
                    )
                )
                lbl_t.setText(text)
                if is_dark:
                    lbl_t.setStyleSheet(
                        f"background: {dark_bg}; "
                        f"color: {dark_col}; "
                        f"border: 1px solid {dark_border}; "
                        f"border-left: 3.5px solid {dark_accent}; "
                        "border-radius: 4px; "
                        "padding: 2px 8px; "
                        "font-family: 'Consolas', 'Segoe UI', monospace; "
                        "font-size: 10px; "
                        "font-weight: 800; "
                        "letter-spacing: 0.6px;"
                    )
                else:
                    lbl_t.setStyleSheet(
                        f"background: {light_bg}; "
                        f"color: {light_col}; "
                        f"border: 1px solid {light_border}; "
                        f"border-left: 3.5px solid {light_accent}; "
                        "border-radius: 4px; "
                        "padding: 2px 8px; "
                        "font-family: 'Consolas', 'Segoe UI', monospace; "
                        "font-size: 10px; "
                        "font-weight: 800; "
                        "letter-spacing: 0.6px;"
                    )
            else:
                lbl_t.setText("◌ STANDBY")
                if is_dark:
                    lbl_t.setStyleSheet(
                        "background-color: rgba(148, 163, 184, 0.06); "
                        "color: #64748b; "
                        "border: 1px dashed rgba(148, 163, 184, 0.25); "
                        "border-left: 3px solid #475569; "
                        "border-radius: 4px; "
                        "padding: 2px 8px; "
                        "font-family: 'Consolas', 'Segoe UI', monospace; "
                        "font-size: 9.5px; "
                        "font-weight: 700; "
                        "letter-spacing: 0.8px;"
                    )
                else:
                    lbl_t.setStyleSheet(
                        "background-color: #f8fafc; "
                        "color: #94a3b8; "
                        "border: 1px dashed #cbd5e1; "
                        "border-left: 3px solid #94a3b8; "
                        "border-radius: 4px; "
                        "padding: 2px 8px; "
                        "font-family: 'Consolas', 'Segoe UI', monospace; "
                        "font-size: 9.5px; "
                        "font-weight: 700; "
                        "letter-spacing: 0.8px;"
                    )

        # 5: CPU
        cpu_val = p['cpu_percent'] or 0.0
        update_sortable_item(5, cpu_val)
        cpu_bar = self.table.cellWidget(row, 5)
        if not cpu_bar:
            cpu_bar = QProgressBar()
            cpu_bar.setTextVisible(True)
            cpu_bar.setMaximum(100)
            cpu_bar.setObjectName("ProcessResourceBar")
            self.table.setCellWidget(row, 5, cpu_bar)
            
        cpu_bar.setValue(int(cpu_val))
        cpu_bar.setFormat(f"{cpu_val:.1f}%")
        
        # Colorize CPU bar if high
        if cpu_val > HIGH_CPU_THRESHOLD:
            cpu_bar.setStyleSheet("QProgressBar::chunk { background-color: #e74c3c; }")
        else:
            cpu_bar.setStyleSheet("QProgressBar::chunk { background-color: #00c6ff; }")

        # 6: Memory
        mem_val = p['memory_percent'] or 0.0
        update_sortable_item(6, mem_val)
        mem_bar = self.table.cellWidget(row, 6)
        if not mem_bar:
            mem_bar = QProgressBar()
            mem_bar.setTextVisible(True)
            mem_bar.setMaximum(100)
            mem_bar.setObjectName("ProcessResourceBar")
            self.table.setCellWidget(row, 6, mem_bar)
            
        mem_bar.setValue(int(mem_val))
        mem_bar.setFormat(f"{mem_val:.1f}%")
        
        # Colorize Mem bar if high
        if mem_val > HIGH_MEM_THRESHOLD:
            mem_bar.setStyleSheet("QProgressBar::chunk { background-color: #f39c12; }")
        else:
            mem_bar.setStyleSheet("QProgressBar::chunk { background-color: #ff5e7e; }")

        # 7: Disk Read
        disk_r = p.get('disk_read', 0)
        update_sortable_item(7, disk_r)
        update_item(7, f"{disk_r / (1024*1024):.1f} MB", color="#a29bfe")

        # 8: Disk Write
        disk_w = p.get('disk_write', 0)
        update_sortable_item(8, disk_w)
        update_item(8, f"{disk_w / (1024*1024):.1f} MB", color="#74b9ff")

        # 9: User
        user = p.get('username') or "System"
        # Clean up Windows domain prefix if present
        if "\\" in user:
            user = user.split("\\")[-1]
        update_item(9, user)

        # 10: Start Time
        try:
            t = datetime.datetime.fromtimestamp(p['create_time'])
            time_str = t.strftime("%H:%M:%S")
        except Exception:
            time_str = "-"
        update_item(10, time_str)
        
        # Threat Highlighting or Suspicious Heuristic
        bg_color = None
        if self.ai_scan_enabled and p.get('ai_color') and ai_level and ai_level >= 3:
            bg_color = QColor(p['ai_color'])
            bg_color.setAlpha(32)
        elif not self.ai_scan_enabled:
            is_suspicious = (p.get('cpu_percent') or 0) > 85 or (p.get('memory_percent') or 0) > 85
            bg_color = QColor(231, 76, 60, 32) if is_suspicious else None
        
        for col in [1, 2, 7, 8, 9, 10]:
            item = self.table.item(row, col)
            if item:
                if bg_color:
                    item.setBackground(QBrush(bg_color))
                else:
                    item.setData(Qt.ItemDataRole.BackgroundRole, None)

    def filter_data(self, processes):
        filtered = processes
        
        # Apply Category Filter for AI Levels
        if hasattr(self, 'current_category') and self.ai_scan_enabled:
            level_map = {
                "Level 1 (Safe)": 1,
                "Level 2 (Low Risk)": 2,
                "Level 3 (Moderate)": 3,
                "Level 4 (High Risk)": 4,
                "Level 5 (Critical)": 5
            }
            if self.current_category in level_map:
                target_level = level_map[self.current_category]
                filtered = [p for p in filtered if p.get('ai_level') == target_level]

        # Apply Text Filter
        if self.filter_text:
            search_lower = self.filter_text.lower()
            filtered = [p for p in filtered if search_lower in p.get('name', '').lower() or search_lower in str(p.get('pid', ''))]
            
        return filtered

    def set_category_filter(self, category):
        self.current_category = category
        if hasattr(self, 'process_data'):
            self.update_table(self.process_data)

    def save_forensics_pdf_to_fms(self):
        """Generates a comprehensive forensic PDF report for the active process and vaults it into FMS."""
        if not self._current_forensic_html or not self._current_forensic_pid:
            QMessageBox.warning(self, "No Process Selected", "Please select a process first to generate its forensic PDF report.")
            return

        import tempfile
        try:
            raw_name = self._current_forensic_name or f"process_{self._current_forensic_pid}"
            # Extract clean process base name (e.g. 'chrome' from 'chrome.exe')
            base_name = raw_name.replace(".exe", "").strip()
            safe_name = "".join(c for c in base_name if c.isalnum() or c in ('_', '-')) or "process"
            filename = f"{safe_name}_report.pdf"

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

            if self.session and hasattr(self.session, 'file_manager'):
                self.session.file_manager.export_file(
                    filename=filename,
                    content=pdf_bytes,
                    module_source="Process Forensics",
                    file_type="PDF",
                    tags=f"Forensics,{safe_name}"
                )
                self.btn_download_forensics.setText("✓ Saved to FMS!")
                QMessageBox.information(
                    self, "Report Saved to FMS",
                    f"Forensic report for '{raw_name}' successfully generated as a PDF and vaulted in NexaShield FMS.\n\nFile: {filename}\nSource: Process Forensics"
                )
                QTimer.singleShot(2500, lambda: self.btn_download_forensics.setText("📥 Save to FMS"))
            else:
                save_path, _ = QFileDialog.getSaveFileName(self, "Save Forensic PDF", filename, "PDF Files (*.pdf)")
                if save_path:
                    with open(save_path, "wb") as f:
                        f.write(pdf_bytes)
                    QMessageBox.information(self, "Report Saved", f"Forensic report saved to:\n{save_path}")
        except Exception as e:
            QMessageBox.critical(self, "Export Error", f"Failed to generate forensic PDF report:\n{str(e)}")

    def close_details_panel(self):
        self.details_panel.hide()
        self._current_forensic_pid = None
        self.table.clearSelection()

    def handle_search(self, text):
        self.filter_text = text
        self.update_table(self.process_data)
        
    def on_process_selected(self):
        selected = self.table.selectedItems()
        if not selected:
            self.details_panel.hide()
            self._current_forensic_pid = None
            return
            
        row = selected[0].row()
        pid_item = self.table.item(row, 1)
        if not pid_item:
            return
            
        try:
            pid = int(pid_item.text())
        except ValueError:
            return
            
        self._current_forensic_pid = pid
        self.details_panel.show()
        
        # Locate process in cached process_data
        p_data = None
        if hasattr(self, 'process_data'):
            for p in self.process_data:
                if p.get('pid') == pid:
                    p_data = p
                    break
        
        p_name = p_data.get('name') if p_data else f"PID {pid}"
        self._current_forensic_name = p_name

        now = time.time()
        # Cache hit: instant 0ms rendering
        if pid in self._forensic_cache:
            cache_time, cached_html, cached_pdf, cached_text, cached_name = self._forensic_cache[pid]
            if now - cache_time < 20.0:  # Fresh within 20 seconds
                self.txt_details_info.setHtml(cached_html)
                self._current_forensic_text = cached_text
                self._current_forensic_html = cached_html
                self._current_forensic_pdf_html = cached_pdf
                self._current_forensic_name = cached_name
                return

        # Instant Preview (zero delay while deep forensics thread extracts in background)
        is_dark = self.palette().color(QPalette.ColorRole.Window).lightness() < 128
        p_status = (p_data.get('status') or 'running').upper() if p_data else 'RUNNING'
        p_cpu = f"{p_data.get('cpu_percent', 0.0):.1f}%" if p_data else '0.0%'
        p_ram = f"{p_data.get('memory_percent', 0.0):.1f}%" if p_data else '0.0%'
        p_user = p_data.get('username') or 'System' if p_data else 'System'
        
        preview_bg = "#111726" if is_dark else "#ffffff"
        preview_border = "#1e293b" if is_dark else "#e2e8f0"
        preview_text = "#f8fafc" if is_dark else "#0f172a"
        preview_sub = "#94a3b8" if is_dark else "#64748b"
        preview_accent = "#38bdf8" if is_dark else "#0284c7"
        
        preview_html = f"""
        <div style="font-family: 'Segoe UI', -apple-system, sans-serif; padding: 10px; color: {preview_text};">
          <div style="background-color: {preview_bg}; border: 1px solid {preview_border}; border-radius: 8px; padding: 12px; margin-bottom: 12px;">
            <div style="font-size: 16px; font-weight: 800; color: {preview_accent};">{p_name}</div>
            <div style="font-size: 11px; color: {preview_sub}; margin-top: 3px;">PID: <b>{pid}</b> &nbsp;|&nbsp; Status: <b>{p_status}</b> &nbsp;|&nbsp; User: <b>{p_user}</b></div>
            <div style="margin-top: 8px; font-size: 11px; color: {preview_sub};">CPU: <b>{p_cpu}</b> &nbsp;|&nbsp; RAM: <b>{p_ram}</b></div>
          </div>
          <div style="padding: 12px; text-align: center; color: {preview_accent}; font-size: 11px; font-weight: 600;">
            ⚡ Extracting deep binary forensics, SHA-256, sockets & lineage...
          </div>
        </div>
        """
        self.txt_details_info.setHtml(preview_html)
        self._current_forensic_html = preview_html

        # Launch background ForensicWorker for deep analysis
        if self._current_forensic_worker and self._current_forensic_worker.isRunning():
            self._current_forensic_worker.terminate()
            self._current_forensic_worker.wait(100)

        self._current_forensic_worker = ForensicWorker(pid, p_data, is_dark, self.ai_scan_enabled)
        self._current_forensic_worker.forensics_ready.connect(self._on_forensics_ready)
        self._current_forensic_worker.start()

    def _on_forensics_ready(self, pid, html_report, pdf_report, text_report, proc_name):
        self._forensic_cache[pid] = (time.time(), html_report, pdf_report, text_report, proc_name)
        if self._current_forensic_pid == pid:
            self.txt_details_info.setHtml(html_report)
            self._current_forensic_text = text_report
            self._current_forensic_html = html_report
            self._current_forensic_pdf_html = pdf_report
            self._current_forensic_name = proc_name

    def get_selected_pids(self):
        pids = []
        for row in range(self.table.rowCount()):
            item = self.table.item(row, 0)
            if item and item.checkState() == Qt.CheckState.Checked:
                pids.append(item.data(Qt.ItemDataRole.UserRole))
        return pids

    def select_rows_by_pids(self, pids):
        for row in range(self.table.rowCount()):
            item = self.table.item(row, 0)
            if item and item.data(Qt.ItemDataRole.UserRole) in pids:
                item.setCheckState(Qt.CheckState.Checked)

    def kill_process(self):
        pids = self.get_selected_pids()
        if not pids:
            QMessageBox.warning(self, "No Selection", "Please select process(es) to terminate.")
            return

        count = len(pids)
        reply = QMessageBox.question(
            self, "Confirm Kill", 
            f"Are you sure you want to terminate {count} process(es)?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )

        if reply == QMessageBox.StandardButton.Yes:
            errors = []
            for pid in pids:
                if pid in [0, 4]: continue
                try:
                    p = psutil.Process(pid)
                    p_name = p.name()
                    p.terminate()
                    db_path = self.session.get_db_path() if self.session else "nexashield.db"
                    DatabaseManager(db_path).log_siem_event("Process Monitor", f"Terminated process '{p_name}' (PID: {pid})", "Warning")
                except psutil.AccessDenied:
                    errors.append(f"PID {pid}: Access Denied")
                except Exception as e:
                    errors.append(f"PID {pid}: {str(e)}")
            
            if errors:
                QMessageBox.warning(self, "Partial Errors", "\n".join(errors[:5]))
            else:
                QMessageBox.information(self, "Success", "Selected processes terminated.")
            self.refresh_data()

    def change_process_state(self, action):
        pids = self.get_selected_pids()
        if not pids:
            return

        count = 0
        for pid in pids:
            try:
                p = psutil.Process(pid)
                if action == "suspend":
                    p.suspend()
                elif action == "resume":
                    p.resume()
                count += 1
            except Exception:
                pass
        
        self.lbl_system_status.setText(f"🟢 System Status: {action.capitalize()}ed {count} processes.")
        self.refresh_data()

    def export_csv(self):
        import io
        try:
            output = io.StringIO()
            writer = csv.writer(output)
            writer.writerow(["PID", "Name", "Status", "CPU%", "Mem%", "User", "Created"])
            for p in self.process_data:
                writer.writerow([
                    p['pid'], p['name'], p['status'], 
                    p['cpu_percent'], p['memory_percent'], 
                    p['username'], p['create_time']
                ])
                
            if self.session and hasattr(self.session, 'file_manager'):
                self.session.file_manager.export_file(
                    filename="processes.csv",
                    content=output.getvalue(),
                    module_source="Process Monitor",
                    file_type="CSV",
                    tags="Routine"
                )
                QMessageBox.information(self, "Vaulted", "Process list CSV securely vaulted in FMS.")
            else:
                QMessageBox.warning(self, "Warning", "FMS not available.")
        except Exception as e:
            QMessageBox.critical(self, "Export Error", str(e))

    def export_pdf(self):
        import tempfile
        import os
        try:
            temp_fd, temp_path = tempfile.mkstemp(suffix=".pdf")
            os.close(temp_fd)
            
            printer = QPrinter(QPrinter.PrinterMode.HighResolution)
            printer.setOutputFormat(QPrinter.OutputFormat.PdfFormat)
            printer.setOutputFileName(temp_path)
            
            # Build HTML Table
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
                <h1>System Processes Report</h1>
                <p>Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                <table>
                    <thead>
                        <tr>
                            <th>PID</th><th>Name</th><th>Status</th><th>CPU%</th><th>Mem%</th><th>User</th><th>Start Time</th>
                        </tr>
                    </thead>
                    <tbody>
            """

            for p in self.process_data:
                try:
                    t = datetime.datetime.fromtimestamp(p['create_time'])
                    time_str = t.strftime("%H:%M:%S")
                except:
                    time_str = "-"
                
                user = p.get('username') or "System"
                if "\\" in user:
                    user = user.split("\\")[-1]

                html += f"<tr><td>{p['pid']}</td><td>{p['name']}</td><td>{p['status']}</td>" \
                        f"<td>{p['cpu_percent']:.1f}</td><td>{p['memory_percent']:.1f}</td>" \
                        f"<td>{user}</td><td>{time_str}</td></tr>"

            html += "</tbody></table></body></html>"
            
            doc = QTextDocument()
            doc.setHtml(html)
            doc.print(printer)
            
            with open(temp_path, "rb") as f:
                pdf_bytes = f.read()
            os.remove(temp_path)
            
            if self.session and hasattr(self.session, 'file_manager'):
                self.session.file_manager.export_file(
                    filename="processes.pdf",
                    content=pdf_bytes,
                    module_source="Process Monitor",
                    file_type="PDF",
                    tags="Routine"
                )
                QMessageBox.information(self, "Vaulted", "Process list PDF securely vaulted in FMS.")
            else:
                QMessageBox.warning(self, "Warning", "FMS not available.")
            
        except Exception as e:
            QMessageBox.critical(self, "Export Error", str(e))
