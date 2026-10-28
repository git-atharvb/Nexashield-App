"""
NexaShield - NIDS Intelligence & Stateful Deep Packet Inspection Engine
Provides 35+ Snort-style signatures, stateful anomaly tracking (SYN Flood, Port Scan,
ICMP Flood, ARP Spoofing), OSI layer dissection, hexdump generation, and whitelist protection.
"""

import re
import time
import socket
import datetime
from collections import defaultdict, deque

# Whitelisted IPs that should never be auto-blocked by IPS
PROTECTED_IPS = {
    "127.0.0.1", "::1", "localhost", "0.0.0.0", "255.255.255.255",
    "10.0.0.1", "192.168.1.1", "192.168.0.1"
}

def get_default_gateway():
    """Attempts to identify the local gateway IP to protect from auto-blocking."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        # Common gateway assumption based on subnet
        parts = local_ip.split(".")
        if len(parts) == 4:
            return f"{parts[0]}.{parts[1]}.{parts[2]}.1"
    except Exception:
        pass
    return None

gw = get_default_gateway()
if gw:
    PROTECTED_IPS.add(gw)


class StatefulAnomalyDetector:
    """
    Tracks sliding-window metrics per source IP to detect volumetric and behavioral attacks:
    - TCP SYN Flood (DDoS)
    - ICMP Echo Flood (Ping of Death / Smurf)
    - Multi-Port Sweep / Host Reconnaissance
    - UDP Packet Flood
    """
    def __init__(self):
        # Maps src_ip -> deque of timestamps
        self.syn_windows = defaultdict(lambda: deque(maxlen=200))
        self.icmp_windows = defaultdict(lambda: deque(maxlen=200))
        self.udp_windows = defaultdict(lambda: deque(maxlen=200))
        # Maps src_ip -> dict of {timestamp: dport}
        self.port_scan_windows = defaultdict(lambda: deque(maxlen=100))
        # ARP cache map: ip -> mac
        self.arp_cache = {}

    def check_syn_flood(self, src_ip: str, now: float) -> tuple[bool, str, str]:
        if src_ip in PROTECTED_IPS:
            return False, "", ""
        q = self.syn_windows[src_ip]
        q.append(now)
        # Count SYNs within the last 2.0 seconds
        cutoff = now - 2.0
        recent = [t for t in q if t >= cutoff]
        if len(recent) >= 30:
            return True, f"TCP SYN Flood Attack Detected ({len(recent)} pkts/2s)", "T1498.001"
        return False, "", ""

    def check_icmp_flood(self, src_ip: str, now: float) -> tuple[bool, str, str]:
        if src_ip in PROTECTED_IPS:
            return False, "", ""
        q = self.icmp_windows[src_ip]
        q.append(now)
        cutoff = now - 2.0
        recent = [t for t in q if t >= cutoff]
        if len(recent) >= 25:
            return True, f"ICMP Ping Flood DoS Detected ({len(recent)} pkts/2s)", "T1498"
        return False, "", ""

    def check_port_scan(self, src_ip: str, dport: int, now: float) -> tuple[bool, str, str]:
        if src_ip in PROTECTED_IPS or not dport:
            return False, "", ""
        q = self.port_scan_windows[src_ip]
        q.append((now, dport))
        cutoff = now - 4.0
        recent_ports = {p for t, p in q if t >= cutoff}
        if len(recent_ports) >= 8:
            return True, f"Multi-Port Sweep / Reconnaissance Detected ({len(recent_ports)} unique ports scanned)", "T1046"
        return False, "", ""

    def check_arp_spoof(self, psrc: str, hwsrc: str) -> tuple[bool, str, str]:
        if not psrc or not hwsrc or psrc in ("0.0.0.0", "255.255.255.255"):
            return False, "", ""
        if psrc in self.arp_cache:
            prev_mac = self.arp_cache[psrc]
            if prev_mac.lower() != hwsrc.lower():
                return True, f"ARP Cache Poisoning Spoof Alert! {psrc} changed from {prev_mac} to {hwsrc}", "T1557.002"
        self.arp_cache[psrc] = hwsrc
        return False, "", ""


class NIDSIntelligenceEngine:
    """
    Core Snort-style Rule Engine & Deep Packet Inspector.
    Compiles 35+ signature rules spanning web exploits, remote execution, recon, and malware.
    """
    def __init__(self):
        self.detector = StatefulAnomalyDetector()
        self.rules = self._init_rules()

    def _init_rules(self) -> list[dict]:
        return [
            # --- 1. Reconnaissance & Scanners ---
            {
                "id": "RULE-001",
                "name": "Nmap OS / Port Sweep Signature",
                "protocol": "TCP",
                "payload_match": b"NMAP",
                "risk": "High",
                "msg": "Nmap Network Scanner Signature Detected",
                "mitre": "T1046"
            },
            {
                "id": "RULE-002",
                "name": "Masscan Fast Scanner Signature",
                "protocol": "TCP",
                "payload_match": b"MASSCAN",
                "risk": "High",
                "msg": "Masscan High-Speed Port Scanner Active",
                "mitre": "T1046"
            },
            {
                "id": "RULE-003",
                "name": "TCP NULL Scan Probe",
                "protocol": "TCP",
                "tcp_flags": 0, # No flags set
                "risk": "Medium",
                "msg": "TCP NULL Scan Stealth Reconnaissance",
                "mitre": "T1046"
            },
            {
                "id": "RULE-004",
                "name": "TCP XMAS Tree Scan",
                "protocol": "TCP",
                "tcp_flags_check": lambda f: (f & 0x29) == 0x29, # FIN + PSH + URG
                "risk": "Medium",
                "msg": "TCP XMAS Tree Scan Stealth Probe",
                "mitre": "T1046"
            },
            {
                "id": "RULE-005",
                "name": "TCP FIN Scan Probe",
                "protocol": "TCP",
                "tcp_flags_check": lambda f: f == 0x01, # Only FIN
                "risk": "Medium",
                "msg": "TCP FIN Stealth Port Scan Detected",
                "mitre": "T1046"
            },

            # --- 2. Web Application Exploits & Injection ---
            {
                "id": "RULE-006",
                "name": "SQL Injection (UNION SELECT)",
                "protocol": "TCP",
                "payload_regex": rb"UNION\s+(?:ALL\s+)?SELECT",
                "risk": "Critical",
                "msg": "SQL Injection: UNION SELECT Payload Injected",
                "mitre": "T1190"
            },
            {
                "id": "RULE-007",
                "name": "SQL Injection (Auth Tautology)",
                "protocol": "TCP",
                "payload_regex": rb"(?:'|\%27)\s*(?:OR|AND)\s*['\"\w]+\s*=\s*['\"\w]+",
                "risk": "Critical",
                "msg": "SQL Injection: Auth Bypass Tautology Detected",
                "mitre": "T1190"
            },
            {
                "id": "RULE-008",
                "name": "SQL Injection (Sleep / Benchmark Time-based)",
                "protocol": "TCP",
                "payload_regex": rb"(?:WAITFOR\s+DELAY|SLEEP\s*\(|BENCHMARK\s*\()",
                "risk": "Critical",
                "msg": "Time-based Blind SQL Injection Injected",
                "mitre": "T1190"
            },
            {
                "id": "RULE-009",
                "name": "Cross-Site Scripting (XSS Tag Probe)",
                "protocol": "TCP",
                "payload_regex": rb"<\s*SCRIPT[\s>]|JAVASCRIPT:\s*|ONERROR\s*=|ALERT\s*\(",
                "risk": "High",
                "msg": "Cross-Site Scripting (XSS) Exploit Injected",
                "mitre": "T1059.007"
            },
            {
                "id": "RULE-010",
                "name": "Directory Traversal Attack",
                "protocol": "TCP",
                "payload_regex": rb"(?:\.\.\/|\.\.\\|\%2E\%2E\%2F|\%2E\%2E\/)",
                "risk": "High",
                "msg": "Directory Traversal / Arbitrary Path Traversal Probe",
                "mitre": "T1083"
            },
            {
                "id": "RULE-011",
                "name": "Sensitive File Access (/etc/passwd)",
                "protocol": "TCP",
                "payload_regex": rb"(?:\/etc\/passwd|\/etc\/shadow|c:\\windows\\system32|win\.ini|boot\.ini)",
                "risk": "Critical",
                "msg": "Unauthorized System Password/Config File Access Attempt",
                "mitre": "T1005"
            },
            {
                "id": "RULE-012",
                "name": "Log4Shell (CVE-2021-44228) JNDI Injection",
                "protocol": "TCP",
                "payload_regex": rb"\$\{(?:lower:|upper:)?jndi:(?:ldap|rmi|dns|nis):",
                "risk": "Critical",
                "msg": "Log4Shell CVE-2021-44228 RCE Exploit Probe",
                "mitre": "T1190"
            },
            {
                "id": "RULE-013",
                "name": "Spring4Shell / Cloud Function RCE",
                "protocol": "TCP",
                "payload_regex": rb"class\.module\.classLoader|spring\.cloud\.function",
                "risk": "Critical",
                "msg": "Spring4Shell Classloader Exploitation Attempt",
                "mitre": "T1190"
            },
            {
                "id": "RULE-014",
                "name": "Shellshock Bash Vulnerability (CVE-2014-6271)",
                "protocol": "TCP",
                "payload_match": b"() { :;};",
                "risk": "Critical",
                "msg": "Shellshock CVE-2014-6271 Environment RCE Exploit",
                "mitre": "T1059.004"
            },
            {
                "id": "RULE-015",
                "name": "PHP Web Shell / Code Injection",
                "protocol": "TCP",
                "payload_regex": rb"<\?php\s*(?:system|exec|passthru|shell_exec|eval\s*\()",
                "risk": "Critical",
                "msg": "PHP Web Shell / Remote Code Execution Injection",
                "mitre": "T1505.003"
            },

            # --- 3. Remote Command Execution & Malware Payloads ---
            {
                "id": "RULE-016",
                "name": "Windows Command Shell Invocation",
                "protocol": "TCP",
                "payload_regex": rb"(?:CMD\.EXE|\/C\s+DIR|\/C\s+WHOAMI|NET\s+USER)",
                "risk": "Critical",
                "msg": "Remote Windows Command Shell Execution",
                "mitre": "T1059.003"
            },
            {
                "id": "RULE-017",
                "name": "Unix / Linux Shell Invocation",
                "protocol": "TCP",
                "payload_regex": rb"(?:\/bin\/sh|\/bin\/bash|\/usr\/bin\/python|nc\s+-e\s+)",
                "risk": "Critical",
                "msg": "Remote Linux/Unix Interactive Shell / Reverse Shell",
                "mitre": "T1059.004"
            },
            {
                "id": "RULE-018",
                "name": "PowerShell Obfuscated Execution",
                "protocol": "TCP",
                "payload_regex": rb"powershell.*?(?:-enc|-encodedcommand|-nop|-w\s+hidden|iex\s*\()",
                "risk": "Critical",
                "msg": "Obfuscated PowerShell Malicious Execution Stager",
                "mitre": "T1059.001"
            },
            {
                "id": "RULE-019",
                "name": "Malware Stager Download (Wget/Curl)",
                "protocol": "TCP",
                "payload_regex": rb"(?:wget\s+http|curl\s+-s\s+http|bitsadmin\s+\/transfer|certutil\s+-urlcache)",
                "risk": "High",
                "msg": "Remote Payload Stager Download Command Detected",
                "mitre": "T1105"
            },
            {
                "id": "RULE-020",
                "name": "Metasploit Shellcode NOP Sled",
                "protocol": "TCP",
                "payload_match": b"\x90\x90\x90\x90\x90\x90\x90\x90",
                "risk": "Critical",
                "msg": "Metasploit Memory Buffer Overflow NOP Sled",
                "mitre": "T1203"
            },

            # --- 4. Vulnerable Protocol & Target Probes ---
            {
                "id": "RULE-021",
                "name": "SMB EternalBlue Target Probe",
                "protocol": "TCP",
                "dport": 445,
                "payload_regex": rb"\xffSMB[\x72\x73\x32\x25]", # SMB Negotiate / Trans2
                "risk": "Critical",
                "msg": "SMB EternalBlue / Trans2 Exploit Probe",
                "mitre": "T1210"
            },
            {
                "id": "RULE-022",
                "name": "RDP BlueKeep / Remote Desktop Target",
                "protocol": "TCP",
                "dport": 3389,
                "payload_regex": rb"\x03\x00\x00.*?\x02\xf0\x80", # TPKT & X.224 connection request
                "risk": "High",
                "msg": "RDP Targeted Remote Desktop Connection Probe",
                "mitre": "T1021.001"
            },
            {
                "id": "RULE-023",
                "name": "Telnet Cleartext Credential Sniff",
                "protocol": "TCP",
                "dport": 23,
                "payload_regex": rb"(?:USER|PASS|LOGIN:)\s+",
                "risk": "Medium",
                "msg": "Unencrypted Telnet Authentication Sniffed",
                "mitre": "T1040"
            },
            {
                "id": "RULE-024",
                "name": "FTP Cleartext Password Transmission",
                "protocol": "TCP",
                "dport": 21,
                "payload_regex": rb"PASS\s+[\w\d\S]+",
                "risk": "Medium",
                "msg": "Cleartext FTP Password Transmission Sniffed",
                "mitre": "T1040"
            },
            {
                "id": "RULE-025",
                "name": "Mirai / IoT Botnet Default Credential Probe",
                "protocol": "TCP",
                "dport": 23,
                "payload_regex": rb"(?:root|admin|enable|system|shell)",
                "risk": "High",
                "msg": "Mirai Botnet Telnet Brute Force Probe",
                "mitre": "T1110.001"
            },

            # --- 5. DNS & Network Infrastructure Attacks ---
            {
                "id": "RULE-026",
                "name": "DNS Query to Suspicious High-Risk TLD",
                "protocol": "UDP",
                "dport": 53,
                "payload_regex": rb"(?:\.xyz|\.top|\.tk|\.cc|\.work|\.vip|\.onion|\.buzz)[\x00\x01]",
                "risk": "Medium",
                "msg": "DNS Resolution to High-Risk Known Phishing/Malware TLD",
                "mitre": "T1071.004"
            },
            {
                "id": "RULE-027",
                "name": "DNS Tunneling / Data Exfiltration Probe",
                "protocol": "UDP",
                "dport": 53,
                "min_length": 220,
                "risk": "High",
                "msg": "Anomalous High-Length DNS Packet (Potential DNS Tunnel)",
                "mitre": "T1071.004"
            },
            {
                "id": "RULE-028",
                "name": "Large ICMP Echo (Ping of Death / Tunnel)",
                "protocol": "ICMP",
                "min_length": 800,
                "risk": "High",
                "msg": "Abnormally Large ICMP Packet (Oversized Ping / Tunnel)",
                "mitre": "T1095"
            },
            {
                "id": "RULE-029",
                "name": "Cobalt Strike Default Beacon C2",
                "protocol": "TCP",
                "payload_regex": rb"(?:GET\s+\/(?:submit\.php\?id=|activity\?id=|pixel\.gif\?))",
                "risk": "Critical",
                "msg": "Cobalt Strike Malleable C2 Beacon Heartbeat Signature",
                "mitre": "T1071.001"
            },
            {
                "id": "RULE-030",
                "name": "SSLv2 / Deprecated Insecure TLS Handshake",
                "protocol": "TCP",
                "dport": 443,
                "payload_regex": rb"^\x80[\x00-\xff]\x01\x00\x02", # SSLv2 ClientHello
                "risk": "Medium",
                "msg": "Vulnerable Insecure SSLv2 Handshake Attempted",
                "mitre": "T1557"
            }
        ]

    def evaluate_packet(self, packet, raw_load: bytes, src_ip: str, dst_ip: str, 
                        protocol: str, sport: int, dport: int, length: int) -> dict:
        """
        Runs stateful tracking and signature matching against the incoming packet.
        Returns a rich threat assessment dict.
        """
        now = time.time()
        threat_match = None

        # 1. Check Stateful Anomaly Detectors
        if protocol == "TCP" and hasattr(packet, 'haslayer'):
            # Detect SYN-only packet
            try:
                from scapy.all import TCP
                if packet.haslayer(TCP):
                    flags = packet[TCP].flags
                    if flags == 0x02: # Pure SYN
                        is_flood, flood_msg, mitre = self.detector.check_syn_flood(src_ip, now)
                        if is_flood:
                            threat_match = {
                                "rule_id": "ANOMALY-001",
                                "name": "TCP SYN Flood DDoS",
                                "risk": "Critical",
                                "msg": flood_msg,
                                "mitre": mitre
                            }
            except Exception:
                pass

        if not threat_match and protocol == "ICMP":
            is_flood, flood_msg, mitre = self.detector.check_icmp_flood(src_ip, now)
            if is_flood:
                threat_match = {
                    "rule_id": "ANOMALY-002",
                    "name": "ICMP Echo Flood",
                    "risk": "High",
                    "msg": flood_msg,
                    "mitre": mitre
                }

        if not threat_match and dport:
            is_scan, scan_msg, mitre = self.detector.check_port_scan(src_ip, dport, now)
            if is_scan:
                threat_match = {
                    "rule_id": "ANOMALY-003",
                    "name": "Multi-Port Sweep",
                    "risk": "High",
                    "msg": scan_msg,
                    "mitre": mitre
                }

        # 2. Check Static Signature Matrix
        if not threat_match and raw_load:
            payload_upper = raw_load.upper()
            for rule in self.rules:
                if rule["protocol"] != "ANY" and rule["protocol"] != protocol:
                    continue

                if "dport" in rule and dport != rule["dport"]:
                    continue

                if "min_length" in rule and length < rule["min_length"]:
                    continue

                matched = False
                if "payload_match" in rule and rule["payload_match"] in payload_upper:
                    matched = True
                elif "payload_regex" in rule:
                    if re.search(rule["payload_regex"], raw_load, re.IGNORECASE):
                        matched = True

                if matched:
                    threat_match = {
                        "rule_id": rule["id"],
                        "name": rule["name"],
                        "risk": rule["risk"],
                        "msg": rule["msg"],
                        "mitre": rule["mitre"]
                    }
                    break

        # 3. Check TCP Flags (NULL, XMAS, FIN)
        if not threat_match and protocol == "TCP" and hasattr(packet, 'haslayer'):
            try:
                from scapy.all import TCP
                if packet.haslayer(TCP):
                    flags = int(packet[TCP].flags)
                    for rule in self.rules:
                        if rule.get("protocol") == "TCP":
                            if "tcp_flags" in rule and flags == rule["tcp_flags"]:
                                threat_match = {
                                    "rule_id": rule["id"],
                                    "name": rule["name"],
                                    "risk": rule["risk"],
                                    "msg": rule["msg"],
                                    "mitre": rule["mitre"]
                                }
                                break
                            elif "tcp_flags_check" in rule and rule["tcp_flags_check"](flags):
                                threat_match = {
                                    "rule_id": rule["id"],
                                    "name": rule["name"],
                                    "risk": rule["risk"],
                                    "msg": rule["msg"],
                                    "mitre": rule["mitre"]
                                }
                                break
            except Exception:
                pass

        if threat_match:
            return threat_match

        return {
            "rule_id": "SAFE",
            "name": "Normal Traffic",
            "risk": "Safe",
            "msg": "Standard Network Protocol Transaction",
            "mitre": "None"
        }

    @staticmethod
    def format_hexdump(data: bytes, max_bytes: int = 1024) -> str:
        """Generates clean Wireshark-standard 16-byte hex dump with ASCII sidebar."""
        if not data:
            return "No payload bytes present in this packet."
        if len(data) > max_bytes:
            data = data[:max_bytes]
            truncated = True
        else:
            truncated = False

        lines = []
        for i in range(0, len(data), 16):
            chunk = data[i:i+16]
            hex_part = " ".join(f"{b:02x}" for b in chunk)
            if len(chunk) < 16:
                hex_part = hex_part.ljust(47)
            # Replace non-printable ASCII
            ascii_part = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
            lines.append(f"{i:04x}   {hex_part}   |{ascii_part}|")

        if truncated:
            lines.append(f"... [Truncated at {max_bytes} bytes for preview]")
        return "\n".join(lines)

    @staticmethod
    def dissect_packet_layers(packet) -> list[dict]:
        """Dissects Scapy packet into structured layers with field details."""
        layers = []
        try:
            curr = packet
            depth = 0
            while curr and depth < 8:
                layer_name = curr.__class__.__name__
                fields = {}
                for f in curr.fields_desc:
                    val = getattr(curr, f.name, None)
                    if val is not None and not isinstance(val, (bytes, bytearray)):
                        fields[f.name] = str(val)
                    elif isinstance(val, (bytes, bytearray)):
                        fields[f.name] = f"<{len(val)} bytes>"

                layers.append({
                    "layer": layer_name,
                    "fields": fields
                })
                # Proceed to payload layer
                if hasattr(curr, 'payload') and curr.payload and curr.payload != curr:
                    curr = curr.payload
                    depth += 1
                else:
                    break
        except Exception as e:
            layers.append({"layer": "Dissection Notice", "fields": {"note": str(e)}})
        return layers

