"""
NexaShield - Enterprise SIEM (Security Information & Event Management) Logic Engine
Features:
- Cross-Module Security Event Aggregation & Normalization (NIDS, Phishing, Cloud, Antivirus, Host)
- Dynamic MITRE ATT&CK Kill-Chain Mapping
- Unified Global Security Posture Scoring (0 - 100%)
- Deep Cross-Module Telemetry Gathering for the "SUPER REPORT" Engine
"""

import os
import sys
import json
import time
import socket
import platform
import datetime
import hashlib
import psutil

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from database import DatabaseManager


class SIEMCorrelationEngine:
    """
    Centralized event correlation, posture analysis, and MITRE ATT&CK taxonomy mapper.
    Integrates all 9 protection modules into a real-time SOC dashboard.
    """
    MITRE_TACTICS = [
        "Initial Access",
        "Execution",
        "Persistence",
        "Privilege Escalation",
        "Defense Evasion",
        "Credential Access",
        "Lateral Movement",
        "Exfiltration"
    ]

    def __init__(self, session_manager=None):
        self.session = session_manager
        db_path = "nexashield.db"
        if self.session and hasattr(self.session, "get_db_path"):
            user_db = self.session.get_db_path()
            if user_db and os.path.exists(user_db):
                db_path = user_db
        self.db = DatabaseManager(db_name=db_path)
        self.root_db = None
        root_path = os.path.join(os.getcwd(), "nexashield.db")
        if os.path.exists(root_path) and os.path.abspath(root_path) != os.path.abspath(db_path):
            self.root_db = DatabaseManager(db_name=root_path)

    def _map_mitre_tactic(self, source: str, description: str, severity: str) -> str:
        """Heuristically tags security events with their corresponding MITRE ATT&CK tactic."""
        desc_lower = description.lower()
        src_lower = source.lower()

        if "phishing" in src_lower or "url" in desc_lower or "lure" in desc_lower or "link" in desc_lower:
            return "Initial Access"
        elif "vbs" in desc_lower or "script" in desc_lower or "dropper" in desc_lower or "trojan" in desc_lower or "malware" in desc_lower:
            return "Execution"
        elif "service" in desc_lower or "startup" in desc_lower or "registry" in desc_lower:
            return "Persistence"
        elif "sudo" in desc_lower or "root" in desc_lower or "admin" in desc_lower or "privilege" in desc_lower:
            return "Privilege Escalation"
        elif "evasion" in desc_lower or "tamper" in desc_lower or "disable" in desc_lower:
            return "Defense Evasion"
        elif "key" in desc_lower or "token" in desc_lower or "secret" in desc_lower or "password" in desc_lower or "ssn" in desc_lower or "card" in desc_lower:
            return "Credential Access"
        elif "syn flood" in desc_lower or "port scan" in desc_lower or "lateral" in desc_lower or "smb" in desc_lower:
            return "Lateral Movement"
        elif "exfiltration" in desc_lower or "c2" in desc_lower or "upload" in desc_lower or "public internet" in desc_lower:
            return "Exfiltration"
        
        if severity in ("Critical", "High", "High Risk"):
            return "Execution"
        return "Initial Access"

    def get_correlated_events(self, limit: int = 150, severity: str = None, search: str = "") -> list[dict]:
        """
        Gathers and normalizes events across:
        1. siem_events table
        2. nids_events table
        3. phishing_scans table
        4. cloud_assets table
        5. scan_history table
        """
        all_events = []

        # 1. SIEM Events
        try:
            raw_siem = self.db.get_siem_events(limit=limit)
            for r in raw_siem:
                sev = r.get("severity", "Safe")
                desc = r.get("description", "")
                src = r.get("source", "SIEM Core")
                all_events.append({
                    "id": f"siem_{r.get('id')}",
                    "timestamp": r.get("timestamp", datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
                    "severity": self._normalize_severity(sev),
                    "source": src,
                    "title": src,
                    "description": desc,
                    "mitre_tactic": self._map_mitre_tactic(src, desc, sev),
                    "raw_data": r
                })
        except Exception:
            pass

        # 2. NIDS Events
        try:
            nids_evts = self.db.get_nids_events(limit=min(100, limit))
            for ne in nids_evts:
                risk = ne.get("risk_level", "Safe")
                sig = ne.get("threat_signature", "")
                src_ip = ne.get("source_ip", "Unknown")
                dst_ip = ne.get("destination_ip", "Unknown")
                proto = ne.get("protocol", "TCP")
                desc = f"[{proto}] {src_ip} -> {dst_ip} | {sig}"
                all_events.append({
                    "id": f"nids_{ne.get('id')}",
                    "timestamp": ne.get("timestamp", datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
                    "severity": self._normalize_severity(risk),
                    "source": "NIDS Sniffer",
                    "title": f"Network {proto} Anomaly",
                    "description": desc,
                    "mitre_tactic": self._map_mitre_tactic("NIDS", sig, risk),
                    "raw_data": ne
                })
        except Exception:
            pass

        # 3. Phishing Scans
        try:
            phish_scans = self.db.get_phishing_history(limit=min(80, limit))
            for ps in phish_scans:
                tl = ps.get("threat_level", "Safe")
                url = ps.get("url", "")
                score = ps.get("score", 0)
                desc = f"Scanned: {url} (Threat Score: {score}/100)"
                all_events.append({
                    "id": f"phish_{ps.get('id')}",
                    "timestamp": ps.get("timestamp", datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
                    "severity": self._normalize_severity(tl),
                    "source": "Phishing Heuristics",
                    "title": "URL Threat Inspection",
                    "description": desc,
                    "mitre_tactic": "Initial Access",
                    "raw_data": ps
                })
        except Exception:
            pass

        # 4. Cloud CASB Assets with Violations
        try:
            cloud_assets = self.db.get_cloud_assets(limit=min(80, limit))
            for ca in cloud_assets:
                score = ca.get("score", 0)
                findings = ca.get("findings", [])
                if findings or score > 0:
                    name = ca.get("name", "Asset")
                    sharing = ca.get("sharing", "Private")
                    find_str = ", ".join(findings) if isinstance(findings, list) else str(findings)
                    desc = f"Asset '{name}' [{sharing}] Security Findings: {find_str}"
                    sev = "Critical" if score >= 75 else ("High" if score >= 50 else ("Medium" if score >= 25 else "Safe"))
                    all_events.append({
                        "id": f"cloud_{ca.get('id')}",
                        "timestamp": ca.get("timestamp") or datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        "severity": sev,
                        "source": "Cloud CASB & DLP",
                        "title": f"Cloud Exposure: {name}",
                        "description": desc,
                        "mitre_tactic": self._map_mitre_tactic("Cloud CASB", find_str, sev),
                        "raw_data": ca
                    })
        except Exception:
            pass

        # 5. Antivirus Scans
        try:
            scans = self.db.get_scan_history()
            for s in scans[:40]:
                scan_type = s[1] if len(s) > 1 else "Quick"
                threats = s[3] if len(s) > 3 else 0
                ts = s[4] if len(s) > 4 else datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                sev = "Critical" if threats > 0 else "Safe"
                desc = f"AV {scan_type} Scan - {threats} threat(s) neutralized"
                all_events.append({
                    "id": f"av_{s[0] if len(s) > 0 else 0}",
                    "timestamp": ts,
                    "severity": sev,
                    "source": "Antivirus Engine",
                    "title": f"Antivirus {scan_type} Audit",
                    "description": desc,
                    "mitre_tactic": "Execution" if threats > 0 else "Defense Evasion",
                    "raw_data": {"scan_type": scan_type, "threats": threats}
                })
        except Exception:
            pass

        # Sort chronologically descending
        all_events.sort(key=lambda x: str(x.get("timestamp", "")), reverse=True)

        # Apply in-memory filtering if requested
        filtered = []
        for ev in all_events:
            if severity and severity != "All Severities":
                if ev["severity"].lower() != severity.lower():
                    continue
            if search:
                s_lower = search.lower()
                match = (
                    s_lower in ev["description"].lower() or
                    s_lower in ev["source"].lower() or
                    s_lower in ev["title"].lower() or
                    s_lower in ev["mitre_tactic"].lower()
                )
                if not match:
                    continue
            filtered.append(ev)

        return filtered[:limit]

    def _normalize_severity(self, sev_str: str) -> str:
        s = str(sev_str).lower().strip()
        if "crit" in s or "severe" in s:
            return "Critical"
        elif "high" in s:
            return "High"
        elif "med" in s or "warn" in s:
            return "Medium"
        elif "low" in s:
            return "Low"
        return "Safe"

    def get_threat_analytics(self) -> dict:
        """
        Calculates dynamic posture scores, DEFCON threat levels, MITRE counts,
        and multi-dimensional radar metrics across all system sensors.
        """
        events = self.get_correlated_events(limit=300)

        sev_dist = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Safe": 0}
        mitre_counts = {t: 0 for t in self.MITRE_TACTICS}

        for ev in events:
            sev = ev.get("severity", "Safe")
            if sev in sev_dist:
                sev_dist[sev] += 1
            else:
                sev_dist["Medium"] += 1

            tactic = ev.get("mitre_tactic", "Initial Access")
            if tactic in mitre_counts:
                mitre_counts[tactic] += 1

        # Posture Score: Start at 100, deduct based on active critical/high alerts
        crit_count = sev_dist["Critical"]
        high_count = sev_dist["High"]
        med_count = sev_dist["Medium"]

        deduction = (crit_count * 15) + (high_count * 8) + (med_count * 2)
        global_score = max(10, min(100, 100 - deduction))

        # DEFCON level: 1 (War/Critical) to 5 (Peace/Optimal)
        if global_score < 40:
            defcon = 1
        elif global_score < 60:
            defcon = 2
        elif global_score < 75:
            defcon = 3
        elif global_score < 90:
            defcon = 4
        else:
            defcon = 5

        # Query blocked IPs count
        blocked_ips_count = 0
        try:
            blocked_ips = self.db.get_nids_blocked_ips()
            blocked_ips_count = len(blocked_ips)
        except Exception:
            pass

        # Query cloud DLP leaks count
        cloud_leaks_count = 0
        try:
            c_assets = self.db.get_cloud_assets(limit=100)
            cloud_leaks_count = sum(1 for a in c_assets if a.get("score", 0) > 0)
        except Exception:
            pass

        # Multi-axis Radar Posture: (Endpoint, Network, Memory, Cloud, Phishing, Antivirus)
        # Score out of 100 for each dimension
        radar_posture = {
            "Host Endpoint": max(20, 100 - (psutil.cpu_percent() if hasattr(psutil, 'cpu_percent') else 10)),
            "Network (NIDS)": max(15, 100 - (crit_count * 8)),
            "Memory Health": max(25, 100 - (psutil.virtual_memory().percent if hasattr(psutil, 'virtual_memory') else 20)),
            "Cloud CASB": max(15, 100 - (cloud_leaks_count * 12)),
            "Phishing Defense": max(30, 100 - (sev_dist["High"] * 6)),
            "Antivirus": 100 if crit_count == 0 else max(30, 100 - (crit_count * 10))
        }

        return {
            "global_score": int(global_score),
            "defcon": defcon,
            "active_critical": crit_count,
            "active_high": high_count,
            "total_incidents": len(events),
            "blocked_hosts": blocked_ips_count,
            "cloud_dlp_leaks": cloud_leaks_count,
            "ai_anomaly_index": min(98.5, max(1.2, float(crit_count * 12.5 + high_count * 4.2))),
            "severity_distribution": sev_dist,
            "mitre_counts": mitre_counts,
            "radar_posture": radar_posture
        }


def gather_deep_super_report_data(session=None) -> dict:
    """
    Exhaustive Forensic Collector for the 'SUPER REPORT' Engine.
    Aggregates deep structural data across ALL 9 TABS:
    - Host & OS Telemetry
    - Running Processes & Forensics
    - Network Sockets & Port Activity
    - Memory Health & Anomaly Status
    - Phishing URL Intelligence
    - NIDS Intrusion Alerts & Attacker IPs
    - Firewall Configuration & Rules
    - Antivirus Threat Scans & Quarantine
    - Cloud CASB Posture, Assets & DLP Leaks
    - SIEM Correlation Audit Matrix
    """
    data = {}
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Resolve primary and fallback databases
    db_path = "nexashield.db"
    if session and hasattr(session, "get_db_path"):
        user_db = session.get_db_path()
        if user_db and os.path.exists(user_db):
            db_path = user_db
    db = DatabaseManager(db_name=db_path)
    
    root_path = os.path.join(os.getcwd(), "nexashield.db")
    root_db = None
    if os.path.exists(root_path) and os.path.abspath(root_path) != os.path.abspath(db_path):
        root_db = DatabaseManager(db_name=root_path)

    engine = SIEMCorrelationEngine(session_manager=session)

    # 1. Executive Metadata & Audit Fingerprint
    analytics = engine.get_threat_analytics()
    data["meta"] = {
        "report_id": f"SR-{int(time.time())}",
        "timestamp": timestamp,
        "operator": session.username if session and hasattr(session, 'username') else os.getlogin(),
        "hostname": socket.gethostname(),
        "os_info": f"{platform.system()} {platform.release()} ({platform.architecture()[0]})",
        "global_score": analytics["global_score"],
        "defcon": analytics["defcon"],
        "active_critical": analytics["active_critical"],
        "active_high": analytics["active_high"],
        "total_incidents": analytics["total_incidents"],
        "blocked_hosts": analytics["blocked_hosts"],
        "cloud_dlp_leaks": analytics["cloud_dlp_leaks"],
        "ai_anomaly_index": analytics["ai_anomaly_index"],
        "mitre_counts": analytics["mitre_counts"],
        "radar_posture": analytics["radar_posture"],
        "severity_distribution": analytics["severity_distribution"]
    }

    # 2. Host System & Environmental Hardware (fault-tolerant against PDH / sandbox errors)
    try:
        try:
            boot_time = datetime.datetime.fromtimestamp(psutil.boot_time()).strftime("%Y-%m-%d %H:%M:%S")
        except Exception:
            boot_time = "Active Session"

        try:
            vmem = psutil.virtual_memory()
            ram_total_gb = round(vmem.total / (1024**3), 2)
            ram_used_gb = round(vmem.used / (1024**3), 2)
            ram_percent = vmem.percent
        except Exception:
            ram_total_gb, ram_used_gb, ram_percent = 8.0, 4.0, 50.0

        swap_total_gb = 0.0
        swap_percent = 0.0
        try:
            swap = psutil.swap_memory()
            swap_total_gb = round(swap.total / (1024**3), 2)
            swap_percent = swap.percent
        except Exception:
            pass

        disks = []
        try:
            for part in psutil.disk_partitions(all=False):
                try:
                    usage = psutil.disk_usage(part.mountpoint)
                    disks.append({
                        "device": part.device,
                        "mountpoint": part.mountpoint,
                        "fstype": part.fstype,
                        "total_gb": round(usage.total / (1024**3), 1),
                        "used_gb": round(usage.used / (1024**3), 1),
                        "percent": usage.percent
                    })
                except Exception:
                    pass
        except Exception:
            pass

        net_sent_mb = 0.0
        net_recv_mb = 0.0
        try:
            net_io = psutil.net_io_counters()
            if net_io:
                net_sent_mb = round(net_io.bytes_sent / (1024**2), 1)
                net_recv_mb = round(net_io.bytes_recv / (1024**2), 1)
        except Exception:
            pass

        cpu_p = 0.0
        try:
            cpu_p = psutil.cpu_percent(interval=None) or 0.0
        except Exception:
            pass

        data["host_system"] = {
            "hostname": socket.gethostname(),
            "boot_time": boot_time,
            "cpu_physical_cores": psutil.cpu_count(logical=False) or os.cpu_count() or 1,
            "cpu_logical_cores": psutil.cpu_count(logical=True) or os.cpu_count() or 1,
            "cpu_percent": cpu_p,
            "ram_total_gb": ram_total_gb,
            "ram_used_gb": ram_used_gb,
            "ram_percent": ram_percent,
            "swap_total_gb": swap_total_gb,
            "swap_percent": swap_percent,
            "disks": disks,
            "net_bytes_sent_mb": net_sent_mb,
            "net_bytes_recv_mb": net_recv_mb
        }
    except Exception as e:
        data["host_system"] = {
            "hostname": socket.gethostname(),
            "boot_time": "Nominal",
            "cpu_physical_cores": os.cpu_count() or 1,
            "cpu_logical_cores": os.cpu_count() or 1,
            "cpu_percent": 0.0,
            "ram_total_gb": 8.0,
            "ram_used_gb": 4.0,
            "ram_percent": 50.0,
            "swap_total_gb": 0.0,
            "swap_percent": 0.0,
            "disks": [],
            "net_bytes_sent_mb": 0.0,
            "net_bytes_recv_mb": 0.0
        }

    # 3. Process Forensics (Top active and anomalous processes)
    processes = []
    try:
        for p in psutil.process_iter(['pid', 'name', 'username', 'cpu_percent', 'memory_percent', 'status']):
            try:
                info = p.info
                if info.get('name'):
                    processes.append(info)
            except Exception:
                pass
        processes.sort(key=lambda x: (x.get('cpu_percent') or 0) + (x.get('memory_percent') or 0), reverse=True)
        data["processes"] = processes[:25]
    except Exception:
        data["processes"] = []

    # 4. Network Sockets & Port Activity
    connections = []
    try:
        for c in psutil.net_connections(kind='inet'):
            if c.status == 'LISTEN' or c.raddr:
                connections.append({
                    "fd": c.fd,
                    "family": "IPv4" if c.family == socket.AF_INET else "IPv6",
                    "type": "TCP" if c.type == socket.SOCK_STREAM else "UDP",
                    "laddr": f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "-",
                    "raddr": f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else "-",
                    "status": c.status,
                    "pid": c.pid or 0
                })
        data["network_sockets"] = connections[:30]
    except Exception:
        data["network_sockets"] = []

    # 5. Phishing Threat Intelligence
    try:
        phish_items = db.get_phishing_history(limit=50)
        if not phish_items and root_db:
            phish_items = root_db.get_phishing_history(limit=50)
        data["phishing"] = phish_items or []
    except Exception:
        data["phishing"] = []

    # 6. NIDS Network Intrusion System
    try:
        nids_items = db.get_nids_events(limit=50)
        blocked_ips = db.get_nids_blocked_ips()
        if not nids_items and root_db:
            nids_items = root_db.get_nids_events(limit=50)
            blocked_ips = root_db.get_nids_blocked_ips()
        data["nids"] = {
            "events": nids_items or [],
            "blocked_ips": blocked_ips or []
        }
    except Exception:
        data["nids"] = {"events": [], "blocked_ips": []}

    # 7. Cloud CASB Posture & Quarantined Assets
    try:
        cloud_assets = db.get_cloud_assets(limit=50)
        vaulted_assets = db.get_cloud_vaulted_assets()
        if not cloud_assets and root_db:
            cloud_assets = root_db.get_cloud_assets(limit=50)
            vaulted_assets = root_db.get_cloud_vaulted_assets()
        data["cloud"] = {
            "assets": cloud_assets or [],
            "vaulted": vaulted_assets or []
        }
    except Exception:
        data["cloud"] = {"assets": [], "vaulted": []}

    # 8. Antivirus Scan Logs
    try:
        scans = db.get_scan_history()
        if not scans and root_db:
            scans = root_db.get_scan_history()
        data["antivirus"] = [
            {
                "id": s[0],
                "scan_type": s[1],
                "files_scanned": s[2],
                "threats_found": s[3],
                "timestamp": s[4]
            } for s in (scans or [])[:30]
        ]
    except Exception:
        data["antivirus"] = []

    # 9. Firewall Rules & Status
    try:
        from firewall_logic import FirewallManager
        fw = FirewallManager()
        rules_out, _ = fw._run_ps_command("Get-NetFirewallRule -Enabled True | Select-Object -First 25 DisplayName, Direction, Action | ConvertTo-Json -Compress")
        if rules_out:
            parsed_rules = json.loads(rules_out)
            if isinstance(parsed_rules, dict):
                parsed_rules = [parsed_rules]
            data["firewall"] = parsed_rules
        else:
            data["firewall"] = []
    except Exception:
        data["firewall"] = []

    # 10. Correlated SIEM Audit Feed
    data["siem_events"] = engine.get_correlated_events(limit=50)

    # Cryptographic Hash of gathered payload
    summary_str = json.dumps(data.get("meta", {}), sort_keys=True)
    data["meta"]["forensic_audit_hash"] = hashlib.sha256(summary_str.encode('utf-8')).hexdigest()

    return data

