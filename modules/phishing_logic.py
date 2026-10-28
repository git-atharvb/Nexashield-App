import os
import re
import ssl
import json
import math
import time
import socket
import pickle
import urllib.parse
from datetime import datetime

# Optional requests for network deep scan
try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

MODEL_PATH = "phishing_model.pkl"
VECTORIZER_PATH = "vectorizer.pkl"

class PhishingIntelligenceEngine:
    """
    Enterprise-grade Deep Phishing & Malicious URL Intelligence Engine.
    Executes a 22+ rule heuristic matrix, deep live SSL/TLS analysis,
    redirect chain tracing, security header auditing, DOM inspection,
    and hybrid Machine Learning threat scoring with MITRE ATT&CK mapping.
    """

    KNOWN_BRANDS = [
        "paypal", "apple", "microsoft", "google", "amazon", "netflix",
        "facebook", "instagram", "whatsapp", "twitter", "chase", "wellsfargo",
        "bankofamerica", "citibank", "coinbase", "binance", "metamask",
        "steam", "dropbox", "linkedin", "yahoo", "outlook", "adobe"
    ]

    SUSPICIOUS_TLDS = [
        '.xyz', '.top', '.gq', '.tk', '.ml', '.ga', '.cf', '.cn', '.vip',
        '.cc', '.work', '.icu', '.buzz', '.fit', '.surf', '.monster',
        '.rest', '.bar', '.live', '.casa', '.fun', '.kim', '.uno'
    ]

    SHORTENERS = [
        'bit.ly', 'tinyurl.com', 'goo.gl', 'ow.ly', 't.co', 'is.gd',
        'buff.ly', 'rebrand.ly', 'cutt.ly', 'shorturl.at', 'bl.ink'
    ]

    def __init__(self, model_path=MODEL_PATH, vectorizer_path=VECTORIZER_PATH):
        self.model_path = model_path
        self.vectorizer_path = vectorizer_path
        self.model = None
        self.vectorizer = None
        self.ml_enabled = False
        self._load_models()

    def _load_models(self):
        """Attempts to load serialized ML models, falling back cleanly if absent."""
        try:
            if os.path.exists(self.model_path) and os.path.exists(self.vectorizer_path):
                with open(self.model_path, 'rb') as f:
                    self.model = pickle.load(f)
                with open(self.vectorizer_path, 'rb') as f:
                    self.vectorizer = pickle.load(f)
                self.ml_enabled = True
        except Exception as e:
            self.ml_enabled = False

    @staticmethod
    def calculate_entropy(text: str) -> float:
        """Calculates Shannon entropy of a string."""
        if not text:
            return 0.0
        entropy = 0.0
        length = len(text)
        occ = {}
        for c in text:
            occ[c] = occ.get(c, 0) + 1
        for count in occ.values():
            p = count / length
            entropy -= p * math.log2(p)
        return round(entropy, 3)

    def parse_url_anatomy(self, url: str) -> dict:
        """Parses and dissects full URL components, domain levels, and IP resolution."""
        parsed = urllib.parse.urlparse(url)
        hostname = parsed.hostname or ""
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        path = parsed.path or "/"
        query = parsed.query or ""

        # Extract domain parts
        domain_parts = hostname.split('.') if hostname else []
        tld = f".{domain_parts[-1]}" if len(domain_parts) > 1 else ""
        registered_domain = ".".join(domain_parts[-2:]) if len(domain_parts) >= 2 else hostname
        subdomains = ".".join(domain_parts[:-2]) if len(domain_parts) > 2 else ""

        # Resolve IP
        resolved_ips = []
        reverse_dns = "-"
        if hostname:
            try:
                addr_info = socket.getaddrinfo(hostname, None)
                for item in addr_info:
                    ip = item[4][0]
                    if ip not in resolved_ips:
                        resolved_ips.append(ip)
                if resolved_ips:
                    try:
                        reverse_dns = socket.gethostbyaddr(resolved_ips[0])[0]
                    except Exception:
                        reverse_dns = "No PTR Record"
            except Exception:
                resolved_ips = ["Resolution Failed"]

        return {
            "original_url": url,
            "scheme": parsed.scheme or "http",
            "netloc": parsed.netloc,
            "hostname": hostname,
            "registered_domain": registered_domain,
            "subdomains": subdomains,
            "tld": tld,
            "port": port,
            "path": path,
            "query": query,
            "fragment": parsed.fragment,
            "url_length": len(url),
            "entropy": self.calculate_entropy(url),
            "resolved_ips": resolved_ips,
            "primary_ip": resolved_ips[0] if resolved_ips else "-",
            "reverse_dns": reverse_dns
        }

    def evaluate_heuristics(self, url: str, anatomy: dict) -> tuple[float, list[dict], list[str]]:
        """
        Executes a 22-rule behavioral heuristic security matrix.
        Returns: (score, structured_rules_list, reason_strings)
        """
        score = 0.0
        rules_triggered = []
        reasons = []

        def add_rule(rule_id: str, name: str, points: float, evidence: str, mitre: str):
            nonlocal score
            score += points
            entry = {
                "id": rule_id,
                "name": name,
                "points": points,
                "evidence": evidence,
                "mitre": mitre
            }
            rules_triggered.append(entry)
            reasons.append(f"[{rule_id}] {name}: {evidence}")

        hostname = anatomy.get("hostname", "").lower()
        path = anatomy.get("path", "")
        query = anatomy.get("query", "")
        scheme = anatomy.get("scheme", "").lower()
        subdomains = anatomy.get("subdomains", "").lower()
        tld = anatomy.get("tld", "").lower()
        url_lower = url.lower()

        # Rule 1: IP address in hostname
        ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
        if re.match(ip_pattern, hostname):
            add_rule("RULE-01", "Dotted Quad IP Hostname", 45.0, f"Host is raw IP: {hostname}", "T1566.002")

        # Rule 2: Suspicious URL Length
        if len(url) > 120:
            add_rule("RULE-02A", "Extreme URL Length", 25.0, f"Length {len(url)} > 120 chars", "T1566.002")
        elif len(url) > 75:
            add_rule("RULE-02B", "High URL Length", 15.0, f"Length {len(url)} > 75 chars", "T1566.002")

        # Rule 3: '@' symbol in authority (RFC 3986 Obfuscation)
        if "@" in url:
            add_rule("RULE-03", "Embedded Credential / Userinfo '@'", 30.0, "Contains '@' authority delimiter", "T1566.002")

        # Rule 4: Sensitive / Phishing Lure Keywords
        keywords = ["login", "verify", "update", "secure", "account", "banking", "confirm",
                     "signin", "wallet", "paypal", "crypto", "recover", "authenticate", "billing"]
        found_kw = [k for k in keywords if k in url_lower]
        if found_kw:
            pts = min(len(found_kw) * 12.0, 30.0)
            add_rule("RULE-04", "Sensitive Lure Keywords", pts, f"Matches: {', '.join(found_kw)}", "T1566.002")

        # Rule 5: Excessive Subdomain Depth
        dot_count = hostname.count('.')
        if dot_count > 4:
            add_rule("RULE-05A", "Extreme Subdomain Nesting", 30.0, f"{dot_count} dots in hostname", "T1583.001")
        elif dot_count > 2:
            add_rule("RULE-05B", "Deep Subdomain Nesting", 15.0, f"{dot_count} dots in hostname", "T1583.001")

        # Rule 6: High-Abuse / Suspicious TLD
        if any(hostname.endswith(t) for t in self.SUSPICIOUS_TLDS):
            add_rule("RULE-06", "Suspicious or High-Abuse TLD", 25.0, f"TLD is {tld}", "T1583.001")

        # Rule 7: Known URL Shortening Service
        if any(shortener in hostname for shortener in self.SHORTENERS):
            add_rule("RULE-07", "URL Shortener Cloaking", 20.0, f"Shortener detected: {hostname}", "T1036.007")

        # Rule 8: Hyphen Typosquatting in Hostname
        hyphen_count = hostname.count('-')
        if hyphen_count > 2:
            add_rule("RULE-08A", "Heavy Hyphenated Typosquatting", 25.0, f"{hyphen_count} hyphens in hostname", "T1036.007")
        elif hyphen_count > 0:
            add_rule("RULE-08B", "Hyphenated Hostname", 10.0, f"{hyphen_count} hyphens in hostname", "T1036.007")

        # Rule 9: Double Slash in Path (Open Redirect / Obfuscation)
        if "//" in path:
            add_rule("RULE-09", "Double Slash Path Obfuscation", 20.0, "Path contains '//' redirection pattern", "T1566.002")

        # Rule 10: Punycode / Internationalized Domain Name (Homograph Attack)
        if "xn--" in hostname:
            add_rule("RULE-10", "IDN Punycode Homograph Signature", 40.0, f"Hostname contains punycode: {hostname}", "T1036.007")

        # Rule 11: Non-Standard Web Port
        port = anatomy.get("port", 80)
        if port not in (80, 443):
            add_rule("RULE-11", "Non-Standard Port Listener", 20.0, f"Port is {port}", "T1071.001")

        # Rule 12: Hex/Percent-Encoded Characters in Authority/Path
        if re.search(r'%[0-9a-fA-F]{2}', url):
            add_rule("RULE-12", "Percent-Encoded Evasion", 15.0, "URL contains URL-encoded bytes (%XX)", "T1036.007")

        # Rule 13: Brand Impersonation in Subdomain / Path
        reg_domain = anatomy.get("registered_domain", "").lower()
        for brand in self.KNOWN_BRANDS:
            if brand in url_lower and not reg_domain.startswith(brand):
                add_rule("RULE-13", f"Brand Impersonation ({brand.capitalize()})", 35.0,
                         f"'{brand}' targeted outside root domain '{reg_domain}'", "T1036.007")
                break

        # Rule 14: Dangerous / Non-HTTP Schemes
        if scheme not in ("http", "https"):
            add_rule("RULE-14", "Insecure or Dangerous Scheme", 50.0, f"Scheme is '{scheme}'", "T1566.002")

        # Rule 15: Deep Path Traversal
        path_segments = [p for p in path.split('/') if p]
        if len(path_segments) >= 5:
            add_rule("RULE-15", "Excessive Path Depth", 15.0, f"{len(path_segments)} path segments", "T1566.002")

        # Rule 16: Mixed/Uppercase Casing in Domain
        if re.search(r'[A-Z]', anatomy.get("netloc", "")):
            add_rule("RULE-16", "Mixed-Case Authority Camouflage", 10.0, "Authority netloc contains uppercase casing", "T1036.007")

        # Rule 17: Phishing Lure Prefix/Suffix in Hostname
        lure_patterns = ["secure-", "login-", "verify-", "account-", "auth-", "update-", "-security", "-login", "-verify"]
        if any(pat in hostname for pat in lure_patterns):
            add_rule("RULE-17", "Adversarial Hostname Prefix/Suffix Lure", 25.0, "Matched structural phishing prefix/suffix", "T1583.001")

        # Rule 18: Entirely Numeric or High Entropy Hostname
        if hostname.replace('.', '').isdigit():
            add_rule("RULE-18A", "Numeric Hostname Impersonation", 30.0, "Hostname is all-numeric characters", "T1583.001")
        elif anatomy.get("entropy", 0) > 4.6:
            add_rule("RULE-18B", "High-Entropy Obfuscated String", 15.0, f"Entropy {anatomy.get('entropy')} > 4.6", "T1036.007")

        # Rule 19: Base64 / Encoded Query Payload
        if query:
            if re.search(r'(?:[A-Za-z0-9+/]{20,}={0,2})', query):
                add_rule("RULE-19", "Base64-Encoded Query Payload", 25.0, "Query string contains Base64 payload block", "T1027")

        # Rule 20: Missing Security Protocol (Plaintext HTTP)
        if scheme == "http":
            add_rule("RULE-20", "Unencrypted HTTP Protocol", 15.0, "Cleartext HTTP transmission vulnerable to MITM", "T1566.002")

        # Rule 21: Homoglyph Character Mix (Latin + Cyrillic / Greek)
        cyrillic_match = bool(re.search(r'[\u0400-\u04FF]', url))
        if cyrillic_match:
            add_rule("RULE-21", "Cyrillic Script Homoglyph Spoof", 45.0, "Contains deceptive Cyrillic Unicode characters", "T1036.007")

        # Rule 22: Suspicious File Extension in URL Path
        suspicious_exts = ['.exe', '.scr', '.vbs', '.apk', '.bat', '.ps1', '.zip', '.iso']
        if any(path.lower().endswith(ext) for ext in suspicious_exts):
            add_rule("RULE-22", "Direct Executable/Malware Drop Payload", 40.0, f"Path ends with payload extension: {path[-4:]}", "T1204.002")

        final_heuristic_score = min(score, 100.0)
        return final_heuristic_score, rules_triggered, reasons

    def analyze_ssl_tls(self, hostname: str, port: int = 443) -> dict:
        """Connects directly via SSL socket to audit certificate parameters and trust chains."""
        if not hostname or hostname in ("-", "Resolution Failed"):
            return {"status": "Skipped", "details": "No valid hostname"}

        result = {
            "has_ssl": False,
            "issuer": "-",
            "subject": "-",
            "valid_from": "-",
            "valid_to": "-",
            "days_until_expiry": 0,
            "is_expired": False,
            "is_self_signed": False,
            "is_wildcard": False,
            "sans": [],
            "risk_flags": []
        }

        try:
            context = ssl.create_default_context()
            context.timeout = 4.0
            with socket.create_connection((hostname, port), timeout=4.0) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    result["has_ssl"] = True

                    # Subject
                    subject_dict = dict(x[0] for x in cert.get('subject', ()))
                    result["subject"] = subject_dict.get('commonName', '-')

                    # Issuer
                    issuer_dict = dict(x[0] for x in cert.get('issuer', ()))
                    result["issuer"] = issuer_dict.get('organizationName', issuer_dict.get('commonName', '-'))

                    # Dates
                    not_before = cert.get('notBefore')
                    not_after = cert.get('notAfter')
                    result["valid_from"] = not_before
                    result["valid_to"] = not_after

                    if not_after:
                        # Format: 'May 10 12:00:00 2025 GMT'
                        try:
                            exp_date = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                            days_left = (exp_date - datetime.utcnow()).days
                            result["days_until_expiry"] = days_left
                            if days_left < 0:
                                result["is_expired"] = True
                                result["risk_flags"].append("Certificate is Expired")
                            elif days_left < 14:
                                result["risk_flags"].append(f"Certificate Expiring Soon ({days_left} days)")
                        except Exception:
                            pass

                    # Self-signed check
                    if result["subject"] == result["issuer"]:
                        result["is_self_signed"] = True
                        result["risk_flags"].append("Self-Signed Certificate Detected")

                    # SANs and Wildcard
                    sans = [item[1] for item in cert.get('subjectAltName', ()) if item[0] == 'DNS']
                    result["sans"] = sans[:10]  # First 10
                    if result["subject"].startswith("*") or any(s.startswith("*") for s in sans):
                        result["is_wildcard"] = True

        except ssl.SSLCertVerificationError as e:
            result["has_ssl"] = True
            result["is_self_signed"] = True
            result["risk_flags"].append(f"SSL Verification Failure: {str(e)}")
        except Exception as e:
            result["status"] = "Connection Failed"
            result["risk_flags"].append(f"SSL Handshake Inaccessible: {str(e)[:60]}")

        return result

    def trace_http_and_content(self, url: str) -> tuple[dict, dict, list[dict]]:
        """
        Traces live HTTP redirect chain, security response headers, and performs
        DOM/content security inspection for credential harvesters and hidden iframes.
        """
        http_data = {
            "status_code": 0,
            "latency_ms": 0,
            "server": "-",
            "final_url": url,
            "security_headers": {},
            "headers_score": 0.0,
            "missing_headers": []
        }
        content_data = {
            "page_title": "-",
            "has_login_form": False,
            "password_inputs": 0,
            "forms_count": 0,
            "external_scripts": 0,
            "hidden_iframes": 0,
            "suspicious_js": [],
            "risk_flags": []
        }
        redirect_chain = []

        if not REQUESTS_AVAILABLE:
            http_data["server"] = "requests library unavailable"
            return http_data, content_data, redirect_chain

        try:
            session = requests.Session()
            session.headers.update({
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 NexaShield/2.0'
            })

            start_t = time.time()
            resp = session.get(url, timeout=5.0, allow_redirects=True, verify=False)
            latency = int((time.time() - start_t) * 1000)

            http_data["status_code"] = resp.status_code
            http_data["latency_ms"] = latency
            http_data["server"] = resp.headers.get("Server", "Undisclosed")
            http_data["final_url"] = resp.url

            # Redirect chain capture
            if resp.history:
                for idx, r in enumerate(resp.history):
                    redirect_chain.append({
                        "hop": idx + 1,
                        "url": r.url,
                        "status": r.status_code,
                        "location": r.headers.get("Location", "-")
                    })
                redirect_chain.append({
                    "hop": len(resp.history) + 1,
                    "url": resp.url,
                    "status": resp.status_code,
                    "location": "Destination"
                })

            # Security Headers Audit
            headers = resp.headers
            sec_headers_spec = {
                "Strict-Transport-Security": 25,
                "Content-Security-Policy": 25,
                "X-Frame-Options": 20,
                "X-Content-Type-Options": 15,
                "X-XSS-Protection": 15
            }
            hdr_score = 0.0
            for h_name, weight in sec_headers_spec.items():
                val = headers.get(h_name)
                if val:
                    http_data["security_headers"][h_name] = val
                    hdr_score += weight
                else:
                    http_data["missing_headers"].append(h_name)
            http_data["headers_score"] = hdr_score

            # DOM Content Inspection
            html = resp.text[:200000] if resp.text else ""
            if html:
                # Title
                m_title = re.search(r'<title[^>]*>(.*?)</title>', html, re.IGNORECASE | re.DOTALL)
                if m_title:
                    content_data["page_title"] = m_title.group(1).strip()[:80]

                # Forms and Password Inputs
                pwd_inputs = len(re.findall(r'<input[^>]+type=["\']password["\']', html, re.IGNORECASE))
                content_data["password_inputs"] = pwd_inputs
                content_data["forms_count"] = len(re.findall(r'<form', html, re.IGNORECASE))

                if pwd_inputs > 0:
                    content_data["has_login_form"] = True
                    content_data["risk_flags"].append(f"Contains {pwd_inputs} Password Field(s) [Credential Harvester Indicator]")

                # External Scripts
                ext_scripts = len(re.findall(r'<script[^>]+src=["\']http', html, re.IGNORECASE))
                content_data["external_scripts"] = ext_scripts

                # Hidden Iframes
                hidden_iframes = len(re.findall(r'<iframe[^>]+(display:\s*none|visibility:\s*hidden|width=["\']0["\'])', html, re.IGNORECASE))
                content_data["hidden_iframes"] = hidden_iframes
                if hidden_iframes > 0:
                    content_data["risk_flags"].append(f"Found {hidden_iframes} Hidden Iframe(s)")

                # Suspicious JS
                sus_js = []
                if "eval(" in html: sus_js.append("eval() execution")
                if "unescape(" in html: sus_js.append("unescape() string unpack")
                if "document.write(unescape" in html: sus_js.append("Obfuscated payload injection")
                if sus_js:
                    content_data["suspicious_js"] = sus_js
                    content_data["risk_flags"].append(f"Suspicious JS Patterns: {', '.join(sus_js)}")

        except Exception as e:
            http_data["server"] = f"Network Connection Skipped/Failed: {str(e)[:50]}"

        return http_data, content_data, redirect_chain

    def scan(self, url: str) -> dict:
        """
        Main execution pipeline: conducts full deep forensic scan of a URL.
        Synthesizes Heuristics + Live SSL/HTTP/Content + ML Model.
        """
        start_time = time.time()
        url = url.strip()
        if not (url.startswith("http://") or url.startswith("https://")):
            url = "http://" + url

        # 1. URL Anatomy
        anatomy = self.parse_url_anatomy(url)

        # 2. Behavioral Heuristic Analysis
        heuristic_score, rules_triggered, reasons = self.evaluate_heuristics(url, anatomy)

        # 3. Live SSL/TLS Analysis
        ssl_data = {}
        if anatomy.get("hostname"):
            ssl_data = self.analyze_ssl_tls(anatomy["hostname"], anatomy.get("port", 443))

        # 4. Live HTTP and Content Analysis
        http_data, content_data, redirect_chain = self.trace_http_and_content(url)

        # Adjust heuristic score based on live indicators
        if ssl_data.get("is_self_signed"):
            heuristic_score = min(heuristic_score + 25.0, 100.0)
            reasons.append("[LIVE-SSL] Certificate is Self-Signed or Untrusted (+25)")
        if ssl_data.get("is_expired"):
            heuristic_score = min(heuristic_score + 20.0, 100.0)
            reasons.append("[LIVE-SSL] Certificate is Expired (+20)")
        if content_data.get("has_login_form") and (heuristic_score > 35.0 or ssl_data.get("is_self_signed")):
            heuristic_score = min(heuristic_score + 20.0, 100.0)
            reasons.append("[LIVE-DOM] Unsecured Credential Harvesting Form Detected (+20)")
        if content_data.get("hidden_iframes", 0) > 0:
            heuristic_score = min(heuristic_score + 20.0, 100.0)
            reasons.append("[LIVE-DOM] Concealed Malicious Iframe Detected (+20)")

        # 5. ML Model Inference
        ml_score = 0.0
        ml_confidence = 0.0
        ml_decision = "N/A"
        if self.ml_enabled and self.vectorizer and self.model:
            try:
                features = self.vectorizer.transform([url])
                prob = self.model.predict_proba(features)[0][1]
                ml_score = round(prob * 100.0, 1)
                ml_confidence = round(prob * 100.0 if prob > 0.5 else (1 - prob) * 100.0, 1)
                ml_decision = "Phishing Threat" if prob > 0.5 else "Benign URL"
            except Exception as e:
                reasons.append(f"ML Inference Fallback: {str(e)[:40]}")

        # 6. Hybrid Synthesis
        if self.ml_enabled:
            if heuristic_score > 70.0:
                final_score = max(ml_score, heuristic_score)
                method = "Hybrid (Heuristics Dominant)"
            elif ml_score > 80.0:
                final_score = (ml_score * 0.7) + (heuristic_score * 0.3)
                method = "Hybrid (ML Dominant)"
            else:
                final_score = (ml_score * 0.5) + (heuristic_score * 0.5)
                method = "Hybrid (Balanced Ensemble)"
        else:
            final_score = heuristic_score
            method = "Multi-Vector Deep Heuristics"

        final_score = round(min(max(final_score, 0.0), 100.0), 1)

        # Threat Level Classification
        if final_score < 30.0:
            threat_level = "Safe"
            threat_tag = "L1 ◆ SAFE"
            threat_color = "#10b981"
        elif final_score < 60.0:
            threat_level = "Low Risk"
            threat_tag = "L2 ◆ LOW RISK"
            threat_color = "#0ea5e9"
        elif final_score < 80.0:
            threat_level = "Medium Risk"
            threat_tag = "L3 ◆ SUSPICIOUS"
            threat_color = "#f59e0b"
        elif final_score < 90.0:
            threat_level = "High Risk"
            threat_tag = "L4 ◆ HIGH RISK"
            threat_color = "#ea580c"
        else:
            threat_level = "High Risk"
            threat_tag = "L5 ◆ CRITICAL"
            threat_color = "#ef4444"

        duration = round(time.time() - start_time, 2)
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Compile Full Dossier
        return {
            "url": url,
            "normalized_url": anatomy.get("original_url"),
            "final_url": http_data.get("final_url", url),
            "threat_level": threat_level,
            "threat_tag": threat_tag,
            "threat_color": threat_color,
            "score": final_score,
            "heuristic_score": round(heuristic_score, 1),
            "ml_score": ml_score,
            "ml_decision": ml_decision,
            "ml_confidence": ml_confidence,
            "method": method,
            "timestamp": timestamp,
            "scan_duration": duration,
            "domain": anatomy.get("hostname", "-"),
            "resolved_ip": anatomy.get("primary_ip", "-"),
            "reasons": reasons,
            # Structured deep details for permanent DB storage & rich dossier
            "details": {
                "anatomy": anatomy,
                "rules_triggered": rules_triggered,
                "ml_results": {
                    "ml_enabled": self.ml_enabled,
                    "ml_score": ml_score,
                    "ml_decision": ml_decision,
                    "ml_confidence": ml_confidence
                },
                "ssl_analysis": ssl_data,
                "http_analysis": http_data,
                "content_analysis": content_data,
                "redirect_chain": redirect_chain,
                "domain_intel": {
                    "registered_domain": anatomy.get("registered_domain"),
                    "subdomains": anatomy.get("subdomains"),
                    "tld": anatomy.get("tld"),
                    "reverse_dns": anatomy.get("reverse_dns"),
                    "resolved_ips": anatomy.get("resolved_ips")
                }
            }
        }

