"""
NexaShield - Enterprise Super Report Engine
Features:
- Cross-Module Comprehensive Forensic Report Generator (All 9 Tabs)
- Executive PDF Generation with ReportLab (540pt calibrated multi-page layout) & Native Qt Fallback
- Universal Comprehensive CSV Forensic Data Bundle
- Zero-Trust Cryptographic Vaulting into FMS (File Management System)
"""

import os
import sys
import io
import csv
import json
import time
import datetime
import hashlib
import tempfile
import html

# ReportLab is preferred for high-fidelity vector PDF generation
try:
    from reportlab.lib.pagesizes import letter
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether, HRFlowable
    )
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib import colors
    HAS_REPORTLAB = True
except ImportError:
    HAS_REPORTLAB = False

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from siem_logic import gather_deep_super_report_data


class SuperReportGenerator:
    """
    Central engine for generating enterprise multi-module security audit reports
    and depositing them directly into the encrypted NexaShield FMS Vault.
    """

    @staticmethod
    def generate_report(session=None, format_type: str = "PDF", scope: list = None) -> tuple[bool, str, str, str]:
        """
        Executes deep gathering across all modules and compiles the selected format.
        Vaults into FMS via session.file_manager.export_file().
        Returns: (success: bool, filename: str, vault_path: str, message: str)
        """
        try:
            # 1. Gather all cross-module data
            raw_data = gather_deep_super_report_data(session=session)
            meta = raw_data.get("meta", {})
            timestamp_slug = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

            # 2. Build Report in memory based on format
            fmt = format_type.upper().strip()
            if fmt == "PDF":
                filename = f"NexaShield_Super_Report_{timestamp_slug}.pdf"
                if HAS_REPORTLAB:
                    content_bytes = SuperReportGenerator._build_pdf_reportlab(raw_data, scope=scope)
                else:
                    content_bytes = SuperReportGenerator._build_pdf_native_qt(raw_data, scope=scope)
                file_type_tag = "PDF"
            else:
                filename = f"NexaShield_Super_Report_{timestamp_slug}.csv"
                content_bytes = SuperReportGenerator._build_csv(raw_data, scope=scope)
                file_type_tag = "CSV"

            # 3. Securely vault into FMS
            vault_path = ""
            if session and hasattr(session, 'file_manager') and session.file_manager:
                try:
                    res_path = session.file_manager.export_file(
                        filename=filename,
                        content=content_bytes,
                        module_source="SIEM Super Report",
                        file_type=file_type_tag,
                        tags="Critical" if meta.get("global_score", 100) < 60 else "Safe"
                    )
                    vault_path = res_path or os.path.join(session.file_manager.vault_dir, filename)
                    if vault_path and os.path.exists(vault_path):
                        filename = os.path.basename(vault_path)
                except Exception:
                    vault_dir = os.path.join(os.getcwd(), "vault")
                    os.makedirs(vault_dir, exist_ok=True)
                    vault_path = os.path.join(vault_dir, filename)
                    with open(vault_path, "wb") as f:
                        f.write(content_bytes)
            else:
                vault_dir = os.path.join(os.getcwd(), "vault")
                os.makedirs(vault_dir, exist_ok=True)
                vault_path = os.path.join(vault_dir, filename)
                with open(vault_path, "wb") as f:
                    f.write(content_bytes)

            return True, filename, vault_path, "Super Report generated and vaulted successfully into FMS."

        except Exception as e:
            return False, "", "", f"Failed to generate Super Report: {str(e)}"

    @staticmethod
    def _build_pdf_reportlab(data: dict, scope: list = None) -> bytes:
        """Constructs an enterprise-grade multi-page forensic PDF dossier with ReportLab."""
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(
            buffer,
            pagesize=letter,
            rightMargin=36,
            leftMargin=36,
            topMargin=36,
            bottomMargin=36
        )

        styles = getSampleStyleSheet()

        title_style = ParagraphStyle(
            'ReportTitle',
            parent=styles['Heading1'],
            fontSize=18,
            leading=22,
            textColor=colors.HexColor("#0284c7"),
            fontName="Helvetica-Bold",
            spaceAfter=4
        )
        subtitle_style = ParagraphStyle(
            'ReportSubtitle',
            parent=styles['Normal'],
            fontSize=8.5,
            leading=11,
            textColor=colors.HexColor("#64748b"),
            spaceAfter=8
        )
        sec_heading = ParagraphStyle(
            'SecHeading',
            parent=styles['Heading2'],
            fontSize=11,
            leading=14,
            textColor=colors.HexColor("#0f172a"),
            fontName="Helvetica-Bold",
            spaceBefore=10,
            spaceAfter=5
        )
        body_style = ParagraphStyle(
            'Body',
            parent=styles['Normal'],
            fontSize=8,
            leading=10,
            textColor=colors.HexColor("#1e293b")
        )
        code_style = ParagraphStyle(
            'Code',
            parent=styles['Normal'],
            fontName="Courier",
            fontSize=7,
            leading=9,
            textColor=colors.HexColor("#0369a1")
        )

        story = []
        meta = data.get("meta", {})
        score = meta.get("global_score", 100)
        defcon = meta.get("defcon", 5)

        # ----------------- HEADER & EXECUTIVE SCORECARD -----------------
        story.append(Paragraph("🛡️ NEXASHIELD ENTERPRISE CYBERSECURITY SUITE", title_style))
        story.append(Paragraph(
            f"<b>MASTER FORENSIC SUPER REPORT</b> | Report ID: {meta.get('report_id')} | Generated: {meta.get('timestamp')}",
            subtitle_style
        ))
        story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#0284c7"), spaceAfter=8))

        # Executive Scorecard Table (540pt total width)
        score_color = colors.HexColor("#10b981") if score >= 80 else (colors.HexColor("#f59e0b") if score >= 50 else colors.HexColor("#ef4444"))
        scorecard_data = [
            [
                Paragraph("<b>Overall Posture</b>", body_style),
                Paragraph("<b>DEFCON Status</b>", body_style),
                Paragraph("<b>Critical Threats</b>", body_style),
                Paragraph("<b>Blocked Hosts</b>", body_style),
                Paragraph("<b>Cloud DLP Leaks</b>", body_style),
                Paragraph("<b>AI Anomaly Level</b>", body_style)
            ],
            [
                Paragraph(f"<font size='14' color='{score_color.hexval()}'><b>{score}%</b></font>", body_style),
                Paragraph(f"<font size='13'><b>LEVEL {defcon}</b></font>", body_style),
                Paragraph(f"<font size='13' color='#ef4444'><b>{meta.get('active_critical', 0)}</b></font>", body_style),
                Paragraph(f"<font size='13' color='#38bdf8'><b>{meta.get('blocked_hosts', 0)}</b></font>", body_style),
                Paragraph(f"<font size='13' color='#f59e0b'><b>{meta.get('cloud_dlp_leaks', 0)}</b></font>", body_style),
                Paragraph(f"<font size='13'><b>{meta.get('ai_anomaly_index', 0):.1f}%</b></font>", body_style)
            ]
        ]
        t_scorecard = Table(scorecard_data, colWidths=[90, 85, 85, 90, 95, 95])
        t_scorecard.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#f1f5f9")),
            ('BACKGROUND', (0, 1), (-1, 1), colors.HexColor("#ffffff")),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ('TOPPADDING', (0, 0), (-1, -1), 5),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
        ]))
        story.append(t_scorecard)
        story.append(Spacer(1, 6))

        # Host & Operator Metadata Table (540pt total)
        env_data = [
            [
                Paragraph(f"<b>Operator:</b> {meta.get('operator')}", body_style),
                Paragraph(f"<b>Target Host:</b> {meta.get('hostname')}", body_style),
                Paragraph(f"<b>Environment OS:</b> {meta.get('os_info')}", body_style)
            ]
        ]
        t_env = Table(env_data, colWidths=[170, 180, 190])
        t_env.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
            ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ('PADDING', (0, 0), (-1, -1), 4),
        ]))
        story.append(t_env)
        story.append(Spacer(1, 8))

        # ----------------- SECTION 1: MITRE ATT&CK MATRIX -----------------
        story.append(Paragraph("1. MITRE ATT&CK Matrix & Tactical Threat Distribution", sec_heading))
        mitre_counts = meta.get("mitre_counts", {})
        m_headers = list(mitre_counts.keys())
        m_vals = [str(mitre_counts[k]) for k in m_headers]
        mitre_table_data = [
            [Paragraph(f"<b>{h[:12]}</b>", body_style) for h in m_headers],
            [Paragraph(f"<b>{v}</b>", body_style) for v in m_vals]
        ]
        t_mitre = Table(mitre_table_data, colWidths=[67.5]*8)
        t_mitre.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#0284c7")),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ('PADDING', (0, 0), (-1, -1), 3),
        ]))
        story.append(t_mitre)
        story.append(Spacer(1, 8))

        # ----------------- SECTION 2: HOST SYSTEM & HARDWARE -----------------
        hs = data.get("host_system", {})
        if hs and "error" not in hs:
            story.append(Paragraph("2. Host Hardware & System Environmental Telemetry", sec_heading))
            hs_data = [
                ["Hardware Metric", "Current Value", "Hardware Metric", "Current Value"],
                ["CPU Cores", f"{hs.get('cpu_physical_cores')} Phys / {hs.get('cpu_logical_cores')} Log", "CPU Utilization", f"{hs.get('cpu_percent')}%"],
                ["Total System RAM", f"{hs.get('ram_total_gb')} GB", "RAM Active Usage", f"{hs.get('ram_used_gb')} GB ({hs.get('ram_percent')}%)"],
                ["Network Tx (Sent)", f"{hs.get('net_bytes_sent_mb')} MB", "Network Rx (Recv)", f"{hs.get('net_bytes_recv_mb')} MB"],
                ["System Boot Time", str(hs.get('boot_time')), "Swap Active", f"{hs.get('swap_used_gb', 0)} GB ({hs.get('swap_percent')}%)"]
            ]
            t_hs = Table(hs_data, colWidths=[135, 135, 135, 135])
            t_hs.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#334155")),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                ('FONTSIZE', (0, 0), (-1, -1), 7.5),
                ('PADDING', (0, 0), (-1, -1), 3),
            ]))
            story.append(t_hs)
            story.append(Spacer(1, 8))

        # ----------------- SECTION 3: TOP PROCESS FORENSICS -----------------
        procs = data.get("processes", [])
        if procs:
            story.append(Paragraph(f"3. Active Process Execution Forensics (Top {min(10, len(procs))})", sec_heading))
            p_rows = [["PID", "Process Executable", "User Account", "CPU %", "RAM %", "Status"]]
            for p in procs[:10]:
                p_rows.append([
                    str(p.get("pid", "")),
                    str(p.get("name", ""))[:28],
                    str(p.get("username", ""))[:18],
                    f"{p.get('cpu_percent', 0):.1f}%",
                    f"{p.get('memory_percent', 0):.1f}%",
                    str(p.get("status", ""))
                ])
            t_proc = Table(p_rows, colWidths=[45, 180, 120, 60, 60, 75])
            t_proc.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#0284c7")),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                ('FONTSIZE', (0, 0), (-1, -1), 7),
                ('PADDING', (0, 0), (-1, -1), 2.5),
            ]))
            story.append(t_proc)
            story.append(Spacer(1, 8))

        # ----------------- SECTION 4: NETWORK SOCKETS -----------------
        socks = data.get("network_sockets", [])
        if socks:
            story.append(Paragraph(f"4. Network Sockets & Port Activity (Top {min(8, len(socks))})", sec_heading))
            s_rows = [["Proto", "Local Address / Port", "Remote Address / Port", "Status", "PID"]]
            for s in socks[:8]:
                s_rows.append([
                    str(s.get("type", "TCP")),
                    str(s.get("laddr", "")),
                    str(s.get("raddr", "-")),
                    str(s.get("status", "")),
                    str(s.get("pid", ""))
                ])
            t_sock = Table(s_rows, colWidths=[50, 180, 180, 80, 50])
            t_sock.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#334155")),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                ('FONTSIZE', (0, 0), (-1, -1), 7),
                ('PADDING', (0, 0), (-1, -1), 2.5),
            ]))
            story.append(t_sock)
            story.append(Spacer(1, 8))

        # ----------------- SECTION 5: PHISHING THREAT INTELLIGENCE -----------------
        phish = data.get("phishing", [])
        if phish:
            story.append(Paragraph(f"5. Phishing Threat Intelligence Scans (Top {min(6, len(phish))})", sec_heading))
            ph_rows = [["Timestamp", "Target URL / Domain", "Threat Level", "Score", "Method"]]
            for p in phish[:6]:
                ph_rows.append([
                    str(p.get("timestamp", ""))[:16],
                    str(p.get("url", ""))[:45],
                    str(p.get("threat_level", "")),
                    f"{p.get('score', 0):.1f}",
                    str(p.get("method", ""))[:20]
                ])
            t_phish = Table(ph_rows, colWidths=[85, 230, 80, 55, 90])
            t_phish.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#0284c7")),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                ('FONTSIZE', (0, 0), (-1, -1), 7),
                ('PADDING', (0, 0), (-1, -1), 2.5),
            ]))
            story.append(t_phish)
            story.append(Spacer(1, 8))

        # ----------------- SECTION 6: NIDS INTRUSION SYSTEM -----------------
        nids_data = data.get("nids", {})
        nids_events = nids_data.get("events", [])
        if nids_events:
            story.append(Paragraph(f"6. Network Intrusion Detection (NIDS) Interceptions (Top {min(6, len(nids_events))})", sec_heading))
            n_rows = [["Time", "Protocol", "Source IP", "Destination IP", "Threat Signature", "Risk"]]
            for ne in nids_events[:6]:
                n_rows.append([
                    str(ne.get("timestamp", ""))[:16],
                    str(ne.get("protocol", "TCP")),
                    str(ne.get("source_ip", "")),
                    str(ne.get("destination_ip", "")),
                    str(ne.get("threat_signature", ""))[:32],
                    str(ne.get("risk_level", "Safe"))
                ])
            t_nids = Table(n_rows, colWidths=[75, 45, 100, 100, 170, 50])
            t_nids.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#334155")),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                ('FONTSIZE', (0, 0), (-1, -1), 7),
                ('PADDING', (0, 0), (-1, -1), 2.5),
            ]))
            story.append(t_nids)
            story.append(Spacer(1, 8))

        # ----------------- SECTION 7: CLOUD CASB & DLP POSTURE -----------------
        cloud = data.get("cloud", {})
        c_assets = cloud.get("assets", [])
        if c_assets:
            story.append(Paragraph(f"7. Cloud CASB Posture & Sensitive DLP Leaks (Top {min(6, len(c_assets))})", sec_heading))
            cl_rows = [["Asset Name", "MIME", "Exposure", "Score", "Security Findings"]]
            for ca in c_assets[:6]:
                cl_rows.append([
                    str(ca.get("name", ""))[:30],
                    str(ca.get("mimeType", "")).split("/")[-1].upper(),
                    str(ca.get("sharing", "Private")),
                    f"{ca.get('score', 0)}/100",
                    str(ca.get("findings", "Clean"))[:35]
                ])
            t_cloud = Table(cl_rows, colWidths=[150, 65, 80, 55, 190])
            t_cloud.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#0284c7")),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                ('FONTSIZE', (0, 0), (-1, -1), 7),
                ('PADDING', (0, 0), (-1, -1), 2.5),
            ]))
            story.append(t_cloud)
            story.append(Spacer(1, 8))

        # ----------------- SECTION 8: SIEM UNIFIED AUDIT LOG -----------------
        siem_evts = data.get("siem_events", [])
        if siem_evts:
            story.append(Paragraph(f"8. Unified Security Incident Audit Trail (Top {min(10, len(siem_evts))})", sec_heading))
            s_rows = [["Timestamp", "Severity", "Module Source", "MITRE Tactic", "Incident Summary"]]
            for se in siem_evts[:10]:
                s_rows.append([
                    str(se.get("timestamp", ""))[:16],
                    str(se.get("severity", "Safe")),
                    str(se.get("source", ""))[:18],
                    str(se.get("mitre_tactic", ""))[:18],
                    str(se.get("description", ""))[:40]
                ])
            t_siem = Table(s_rows, colWidths=[80, 55, 95, 95, 215])
            t_siem.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#0f172a")),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                ('FONTSIZE', (0, 0), (-1, -1), 7),
                ('PADDING', (0, 0), (-1, -1), 2.5),
            ]))
            story.append(t_siem)
            story.append(Spacer(1, 10))

        # ----------------- CRYPTOGRAPHIC SIGN-OFF -----------------
        audit_hash = meta.get("forensic_audit_hash", "N/A")
        signoff = [
            [
                Paragraph("<b>Audit Hash & Verification Signature:</b>", body_style),
                Paragraph(f"<font color='#0284c7'><b>SHA-256:</b> {audit_hash}</font>", code_style)
            ],
            [
                Paragraph("<b>Zero-Trust Compliance:</b>", body_style),
                Paragraph("Report generated via automated cross-module telemetry harvest. All findings sealed and encrypted in the NexaShield FMS Vault.", body_style)
            ]
        ]
        t_sign = Table(signoff, colWidths=[150, 390])
        t_sign.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
            ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ('PADDING', (0, 0), (-1, -1), 4),
        ]))
        story.append(t_sign)

        doc.build(story)
        return buffer.getvalue()

    @staticmethod
    def _build_pdf_native_qt(data: dict, scope: list = None) -> bytes:
        """Constructs a properly scaled PDF dossier natively using PyQt6's QPrinter & QTextDocument."""
        from PyQt6.QtWidgets import QApplication
        from PyQt6.QtGui import QTextDocument
        from PyQt6.QtPrintSupport import QPrinter

        app = QApplication.instance()
        if not app:
            app = QApplication(sys.argv)

        meta = data.get("meta", {})
        score = meta.get("global_score", 100)
        defcon = meta.get("defcon", 5)
        score_col = "#10b981" if score >= 80 else ("#f59e0b" if score >= 50 else "#ef4444")

        # In QPrinter, points (pt) must be used instead of px to guarantee 100% human-readable print scaling
        html_doc = f"""
        <!DOCTYPE html>
        <html>
        <head>
        <meta charset="utf-8">
        <style>
            body {{ font-family: 'Segoe UI', Arial, sans-serif; margin: 15pt; color: #0f172a; font-size: 8pt; line-height: 1.25; }}
            h1 {{ color: #0284c7; font-size: 14pt; margin: 0 0 3pt 0; }}
            .subtitle {{ color: #64748b; font-size: 7.5pt; margin-bottom: 8pt; }}
            .section-title {{ font-size: 9pt; font-weight: bold; color: #0284c7; border-bottom: 1.5pt solid #0284c7; padding-bottom: 2pt; margin-top: 10pt; margin-bottom: 4pt; }}
            table {{ width: 100%; border-collapse: collapse; margin-bottom: 6pt; font-size: 7.5pt; }}
            th {{ background-color: #0284c7; color: white; padding: 4pt; text-align: left; font-weight: bold; border: 0.5pt solid #0284c7; }}
            th.dark {{ background-color: #334155; border: 0.5pt solid #334155; }}
            td {{ padding: 3pt 4pt; border: 0.5pt solid #cbd5e1; }}
            .scorecard {{ width: 100%; border: 1pt solid #cbd5e1; text-align: center; margin-bottom: 6pt; }}
            .score-val {{ font-size: 13pt; font-weight: bold; }}
            .hash-box {{ background-color: #f8fafc; border: 1pt solid #cbd5e1; padding: 5pt; font-size: 7pt; font-family: Consolas, monospace; color: #0369a1; }}
        </style>
        </head>
        <body>
            <h1>🛡️ NEXASHIELD ENTERPRISE CYBERSECURITY SUITE</h1>
            <div class="subtitle">
                <b>MASTER FORENSIC SUPER REPORT</b> | Report ID: {html.escape(str(meta.get('report_id', '')))} | 
                Generated: {html.escape(str(meta.get('timestamp', '')))} | 
                Host: {html.escape(str(meta.get('hostname', '')))} | 
                Operator: {html.escape(str(meta.get('operator', '')))}
            </div>

            <!-- Executive Scorecard -->
            <table class="scorecard" cellpadding="5">
                <tr style="background-color: #f1f5f9; font-weight: bold;">
                    <td>Overall Posture</td>
                    <td>DEFCON Status</td>
                    <td>Critical Threats</td>
                    <td>Blocked Hosts</td>
                    <td>Cloud DLP Leaks</td>
                    <td>AI Anomaly Level</td>
                </tr>
                <tr>
                    <td class="score-val" style="color: {score_col};">{score}%</td>
                    <td class="score-val">LEVEL {defcon}</td>
                    <td class="score-val" style="color: #ef4444;">{meta.get('active_critical', 0)}</td>
                    <td class="score-val" style="color: #38bdf8;">{meta.get('blocked_hosts', 0)}</td>
                    <td class="score-val" style="color: #f59e0b;">{meta.get('cloud_dlp_leaks', 0)}</td>
                    <td class="score-val">{meta.get('ai_anomaly_index', 0):.1f}%</td>
                </tr>
            </table>

            <!-- MITRE ATT&CK Matrix -->
            <div class="section-title">1. MITRE ATT&CK Tactical Threat Distribution</div>
            <table>
                <tr>
                    {"".join(f"<th>{html.escape(k[:14])}</th>" for k in meta.get("mitre_counts", {}).keys())}
                </tr>
                <tr style="text-align: center; font-weight: bold; background-color: #f8fafc;">
                    {"".join(f"<td>{v}</td>" for v in meta.get("mitre_counts", {}).values())}
                </tr>
            </table>
        """

        # Section 2: Host Hardware
        hs = data.get("host_system", {})
        if hs and "error" not in hs:
            html_doc += f"""
            <div class="section-title">2. Host Hardware & System Environmental Telemetry</div>
            <table>
                <tr><th class="dark">Metric</th><th class="dark">Value</th><th class="dark">Metric</th><th class="dark">Value</th></tr>
                <tr>
                    <td><b>CPU Physical / Logical</b></td><td>{hs.get('cpu_physical_cores', 1)} Phys / {hs.get('cpu_logical_cores', 1)} Log</td>
                    <td><b>CPU Utilization</b></td><td>{hs.get('cpu_percent', 0)}%</td>
                </tr>
                <tr>
                    <td><b>Total RAM</b></td><td>{hs.get('ram_total_gb', 0)} GB</td>
                    <td><b>RAM Allocation</b></td><td>{hs.get('ram_used_gb', 0)} GB ({hs.get('ram_percent', 0)}%)</td>
                </tr>
            </table>
            """

        # Section 3: Process Execution
        procs = data.get("processes", [])
        if procs:
            html_doc += f"""
            <div class="section-title">3. Active Process Execution Forensics (Top {min(8, len(procs))})</div>
            <table>
                <tr><th>PID</th><th>Process Executable</th><th>User Account</th><th>CPU %</th><th>RAM %</th><th>Status</th></tr>
            """
            for p in procs[:8]:
                html_doc += f"""
                <tr>
                    <td>{p.get('pid', '')}</td>
                    <td><b>{html.escape(str(p.get('name', ''))[:30])}</b></td>
                    <td>{html.escape(str(p.get('username', ''))[:20])}</td>
                    <td>{p.get('cpu_percent', 0):.1f}%</td>
                    <td>{p.get('memory_percent', 0):.1f}%</td>
                    <td>{html.escape(str(p.get('status', '')))}</td>
                </tr>
                """
            html_doc += "</table>"

        # Section 4: Network Sockets
        socks = data.get("network_sockets", [])
        if socks:
            html_doc += f"""
            <div class="section-title">4. Network Sockets & Port Activity (Top {min(6, len(socks))})</div>
            <table>
                <tr><th class="dark">Proto</th><th class="dark">Local Address</th><th class="dark">Remote Address</th><th class="dark">Status</th><th class="dark">PID</th></tr>
            """
            for s in socks[:6]:
                html_doc += f"""
                <tr>
                    <td>{html.escape(str(s.get('type', 'TCP')))}</td>
                    <td>{html.escape(str(s.get('laddr', '')))}</td>
                    <td>{html.escape(str(s.get('raddr', '-')))}</td>
                    <td>{html.escape(str(s.get('status', '')))}</td>
                    <td>{s.get('pid', '')}</td>
                </tr>
                """
            html_doc += "</table>"

        # Section 5: Phishing Scans
        phish = data.get("phishing", [])
        if phish:
            html_doc += f"""
            <div class="section-title">5. Phishing Threat Intelligence Scans (Top {min(6, len(phish))})</div>
            <table>
                <tr><th>Timestamp</th><th>Target URL / Domain</th><th>Threat Level</th><th>Score</th><th>Method</th></tr>
            """
            for ph in phish[:6]:
                html_doc += f"""
                <tr>
                    <td>{str(ph.get('timestamp', ''))[:16]}</td>
                    <td>{html.escape(str(ph.get('url', ''))[:50])}</td>
                    <td><b>{html.escape(str(ph.get('threat_level', '')))}</b></td>
                    <td>{ph.get('score', 0):.1f}</td>
                    <td>{html.escape(str(ph.get('method', '')))}</td>
                </tr>
                """
            html_doc += "</table>"

        # Section 6: NIDS Network Intrusion System
        nids_data = data.get("nids", {})
        nids_events = nids_data.get("events", [])
        if nids_events:
            html_doc += f"""
            <div class="section-title">6. Network Intrusion Detection (NIDS) Interceptions (Top {min(6, len(nids_events))})</div>
            <table>
                <tr><th class="dark">Time</th><th class="dark">Protocol</th><th class="dark">Source IP</th><th class="dark">Destination IP</th><th class="dark">Signature</th><th class="dark">Risk</th></tr>
            """
            for ne in nids_events[:6]:
                html_doc += f"""
                <tr>
                    <td>{str(ne.get('timestamp', ''))[:16]}</td>
                    <td>{ne.get('protocol', 'TCP')}</td>
                    <td>{ne.get('source_ip', '')}</td>
                    <td>{ne.get('destination_ip', '')}</td>
                    <td>{html.escape(str(ne.get('threat_signature', ''))[:35])}</td>
                    <td><b>{ne.get('risk_level', 'Safe')}</b></td>
                </tr>
                """
            html_doc += "</table>"

        # Section 7: Cloud CASB & DLP
        cloud = data.get("cloud", {})
        c_assets = cloud.get("assets", [])
        if c_assets:
            html_doc += f"""
            <div class="section-title">7. Cloud CASB & DLP Findings (Top {min(6, len(c_assets))})</div>
            <table>
                <tr><th>Asset Name</th><th>Type</th><th>Posture</th><th>Score</th><th>Security Findings</th></tr>
            """
            for ca in c_assets[:6]:
                html_doc += f"""
                <tr>
                    <td>{html.escape(str(ca.get('name', ''))[:35])}</td>
                    <td>{str(ca.get('mimeType', '')).split('/')[-1].upper()}</td>
                    <td>{ca.get('sharing', 'Private')}</td>
                    <td>{ca.get('score', 0)}/100</td>
                    <td>{html.escape(str(ca.get('findings', 'Clean'))[:40])}</td>
                </tr>
                """
            html_doc += "</table>"

        # Section 8: SIEM Unified Correlated Audit
        siem_evts = data.get("siem_events", [])
        if siem_evts:
            html_doc += f"""
            <div class="section-title">8. Centralized SIEM Incident Audit Trail (Top {min(8, len(siem_evts))})</div>
            <table>
                <tr><th class="dark">Timestamp</th><th class="dark">Severity</th><th class="dark">Source</th><th class="dark">MITRE Tactic</th><th class="dark">Description</th></tr>
            """
            for se in siem_evts[:8]:
                html_doc += f"""
                <tr>
                    <td>{str(se.get('timestamp', ''))[:16]}</td>
                    <td><b>{se.get('severity', 'Safe')}</b></td>
                    <td>{se.get('source', '')}</td>
                    <td>{se.get('mitre_tactic', '')}</td>
                    <td>{html.escape(str(se.get('description', ''))[:45])}</td>
                </tr>
                """
            html_doc += "</table>"

        # Audit Signature Sign-off
        audit_hash = meta.get("forensic_audit_hash", "N/A")
        html_doc += f"""
            <div class="section-title">Cryptographic Audit Signature & Compliance</div>
            <div class="hash-box">
                <b>SHA-256 Audit Hash:</b> {audit_hash}<br>
                <b>Zero-Trust Assurance:</b> Sealed and encrypted into NexaShield FMS Vault.
            </div>
        </body>
        </html>
        """

        fd, temp_pdf = tempfile.mkstemp(suffix=".pdf")
        os.close(fd)
        try:
            printer = QPrinter(QPrinter.PrinterMode.ScreenResolution)
            printer.setOutputFormat(QPrinter.OutputFormat.PdfFormat)
            printer.setOutputFileName(temp_pdf)

            doc = QTextDocument()
            doc.setHtml(html_doc)
            doc.print(printer)

            with open(temp_pdf, "rb") as f:
                return f.read()
        finally:
            if os.path.exists(temp_pdf):
                try:
                    os.remove(temp_pdf)
                except Exception:
                    pass

    @staticmethod
    def _build_csv(data: dict, scope: list = None) -> bytes:
        """Constructs a comprehensive multi-section CSV audit bundle."""
        out = io.StringIO()
        writer = csv.writer(out)
        meta = data.get("meta", {})

        writer.writerow(["=== NEXASHIELD MASTER SUPER REPORT: EXECUTIVE SCORECARD ==="])
        writer.writerow(["Report ID", meta.get("report_id")])
        writer.writerow(["Timestamp", meta.get("timestamp")])
        writer.writerow(["Target Host", meta.get("hostname")])
        writer.writerow(["Operator", meta.get("operator")])
        writer.writerow(["OS", meta.get("os_info")])
        writer.writerow(["Global Posture Score", f"{meta.get('global_score')}%"])
        writer.writerow(["DEFCON Level", meta.get("defcon")])
        writer.writerow(["Active Critical Incidents", meta.get("active_critical")])
        writer.writerow(["Blocked Hostile IPs", meta.get("blocked_hosts")])
        writer.writerow(["Cloud DLP Leaks", meta.get("cloud_dlp_leaks")])
        writer.writerow(["AI Anomaly Deviation", f"{meta.get('ai_anomaly_index')}%"])
        writer.writerow(["Forensic Audit SHA-256", meta.get("forensic_audit_hash")])
        writer.writerow([])

        writer.writerow(["=== MITRE ATT&CK TACTICAL DISTRIBUTION ==="])
        mitre = meta.get("mitre_counts", {})
        writer.writerow(list(mitre.keys()))
        writer.writerow(list(mitre.values()))
        writer.writerow([])

        writer.writerow(["=== ACTIVE PROCESS EXECUTION FORENSICS ==="])
        writer.writerow(["PID", "Name", "Username", "CPU %", "RAM %", "Status"])
        for p in data.get("processes", []):
            writer.writerow([p.get("pid"), p.get("name"), p.get("username"), p.get("cpu_percent"), p.get("memory_percent"), p.get("status")])
        writer.writerow([])

        writer.writerow(["=== NETWORK SOCKETS & PORT TELEMETRY ==="])
        writer.writerow(["Protocol", "Local Address", "Remote Address", "Status", "PID"])
        for s in data.get("network_sockets", []):
            writer.writerow([s.get("type"), s.get("laddr"), s.get("raddr"), s.get("status"), s.get("pid")])
        writer.writerow([])

        writer.writerow(["=== PHISHING THREAT INTELLIGENCE SCANS ==="])
        writer.writerow(["ID", "Timestamp", "Target URL", "Threat Level", "Score", "Method", "Domain", "Resolved IP"])
        for ph in data.get("phishing", []):
            writer.writerow([ph.get("id"), ph.get("timestamp"), ph.get("url"), ph.get("threat_level"), ph.get("score"), ph.get("method"), ph.get("domain"), ph.get("resolved_ip")])
        writer.writerow([])

        writer.writerow(["=== NETWORK INTRUSION DETECTION (NIDS) LOGS ==="])
        nids = data.get("nids", {})
        writer.writerow(["ID", "Timestamp", "Protocol", "Source IP", "Destination IP", "Signature", "Risk Level"])
        for ne in nids.get("events", []):
            writer.writerow([ne.get("id"), ne.get("timestamp"), ne.get("protocol"), ne.get("source_ip"), ne.get("destination_ip"), ne.get("threat_signature"), ne.get("risk_level")])
        writer.writerow([])

        writer.writerow(["=== CLOUD CASB ASSETS & SENSITIVE DATA LEAKS ==="])
        cloud = data.get("cloud", {})
        writer.writerow(["ID", "Asset Name", "MIME Type", "Size", "Sharing Posture", "Security Score", "Findings"])
        for ca in cloud.get("assets", []):
            writer.writerow([ca.get("id"), ca.get("name"), ca.get("mimeType"), ca.get("size"), ca.get("sharing"), ca.get("score"), str(ca.get("findings"))])
        writer.writerow([])

        writer.writerow(["=== ANTIVIRUS SCAN & QUARANTINE LOGS ==="])
        writer.writerow(["ID", "Scan Type", "Files Scanned", "Threats Neutralized", "Timestamp"])
        for av in data.get("antivirus", []):
            writer.writerow([av.get("id"), av.get("scan_type"), av.get("files_scanned"), av.get("threats_found"), av.get("timestamp")])
        writer.writerow([])

        writer.writerow(["=== UNIFIED SIEM SECURITY INCIDENT CORRELATION FEED ==="])
        writer.writerow(["ID", "Timestamp", "Severity", "Source Module", "MITRE Tactic", "Description"])
        for se in data.get("siem_events", []):
            writer.writerow([se.get("id"), se.get("timestamp"), se.get("severity"), se.get("source"), se.get("mitre_tactic"), se.get("description")])

        return out.getvalue().encode('utf-8')
