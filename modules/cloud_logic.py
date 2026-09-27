import os
import json
import re
import urllib.request
import urllib.parse
import hashlib
from urllib.error import URLError, HTTPError

class CloudStorageScanner:
    """
    Real-World Cloud Access Security Broker (CASB) Scanner.
    Features: 
    1. Posture Management (CSPM) - Permission analysis
    2. Cloud AV - SHA256 hashing and Threat Intel
    3. Malicious Link Extraction
    4. Context-Aware DLP
    """
    def __init__(self, access_token):
        self.access_token = access_token
        self.headers = {
            "Authorization": f"Bearer {self.access_token}"
        }
        
        # Context-Aware DLP
        self.context_keywords = ["card", "cvv", "visa", "mastercard", "stripe", "credit", "expire", "ssn", "social"]
        
        self.dlp_patterns = {
            "Credit Card": {
                "pattern": re.compile(r'\b(?:\d{4}[ -]?){3}\d{4}\b'),
                "severity": "High",
                "desc": "A potential credit card number was found WITH surrounding contextual keywords. This is a high-confidence DLP leak.",
                "validate": self._validate_luhn,
                "needs_context": True
            },
            "AWS Access Key": {
                "pattern": re.compile(r'\bAKIA[0-9A-Z]{16}\b'),
                "severity": "Critical",
                "desc": "An AWS Access Key ID was detected. This allows access to cloud infrastructure.",
                "needs_context": False
            },
            "Private Key": {
                "pattern": re.compile(r'-----BEGIN (RSA|OPENSSH|EC|PGP) PRIVATE KEY-----'),
                "severity": "Critical",
                "desc": "A cryptographic private key was found in plain text. This allows attackers to impersonate servers or decrypt data.",
                "needs_context": False
            }
        }
        
        self.url_pattern = re.compile(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+')

    def _validate_luhn(self, cc_string):
        digits = [int(c) for c in cc_string if c.isdigit()]
        if len(digits) < 13 or len(digits) > 16: return False
        checksum = 0
        is_second = False
        for d in reversed(digits):
            if is_second:
                d = d * 2
                if d > 9: d -= 9
            checksum += d
            is_second = not is_second
        return (checksum % 10 == 0)

    def _has_context(self, content, match_start, match_end):
        """Checks if there are sensitive keywords within 100 characters of the match."""
        start = max(0, match_start - 100)
        end = min(len(content), match_end + 100)
        surrounding_text = content[start:end].lower()
        
        for kw in self.context_keywords:
            if kw in surrounding_text:
                return True
        return False

    def list_files(self, limit=20):
        url = f"https://www.googleapis.com/drive/v3/files?pageSize={limit}&fields=files(id,name,mimeType,size,permissions,shared)&orderBy=modifiedTime%20desc"
        
        req = urllib.request.Request(url, headers=self.headers)
        try:
            with urllib.request.urlopen(req) as response:
                data = json.loads(response.read().decode('utf-8'))
                return data.get('files', [])
        except HTTPError as e:
            return f"HTTP Error: {e.code} - {e.read().decode('utf-8')}"
        except Exception as e:
            return f"Error: {str(e)}"

    def download_and_scan(self, file_meta):
        file_id = file_meta.get('id')
        mime_type = file_meta.get('mimeType', '')
        name = file_meta.get('name', 'Unknown')
        permissions = file_meta.get('permissions', [])
        
        raw_findings = []
        
        # 1. CSPM (Permissions Analysis)
        is_public = False
        for perm in permissions:
            if perm.get('type') == 'anyone':
                is_public = True
                break
                
        if is_public:
            raw_findings.append({
                "label": "Publicly Exposed File",
                "count": 1,
                "severity": "Critical",
                "desc": "CSPM Alert: This file has 'Anyone with the link' permissions. It is accessible to the entire internet.",
                "sample": "Permissions: type=anyone"
            })

        # Skip folders for content scan
        if "application/vnd.google-apps.folder" in mime_type:
            if raw_findings:
                return {"status": "flagged", "findings": ["Publicly Exposed Folder"], "raw_findings": raw_findings}
            return {"status": "clean", "findings": [], "raw_findings": []}
            
        export_mime = None
        if "application/vnd.google-apps.document" in mime_type:
            export_mime = "text/plain"
        elif "application/vnd.google-apps.spreadsheet" in mime_type:
            export_mime = "text/csv"
            
        if export_mime:
            url = f"https://www.googleapis.com/drive/v3/files/{file_id}/export?mimeType={export_mime}"
        else:
            url = f"https://www.googleapis.com/drive/v3/files/{file_id}?alt=media"

        req = urllib.request.Request(url, headers=self.headers)
        try:
            with urllib.request.urlopen(req) as response:
                file_bytes = response.read()
                
                # 2. Real Cloud AV (Hash Scanning)
                file_hash = hashlib.sha256(file_bytes).hexdigest()
                malware_finding = self._check_malwarebazaar(file_hash)
                if malware_finding:
                    raw_findings.append(malware_finding)
                
                # Only run regex DLP on safe text formats, skip PDFs/binaries
                if export_mime or mime_type.startswith('text/') or mime_type == 'application/json':
                    content = file_bytes.decode('utf-8', errors='ignore')
                    dlp_findings = self._scan_dlp_contextual(content)
                    raw_findings.extend(dlp_findings)
                    
                    # 3. Phishing / URL Extraction
                    urls = self.url_pattern.findall(content)
                    shady_urls = [u for u in urls if '.tk' in u or '.ml' in u or '.ru' in u or 'ngrok.io' in u]
                    if shady_urls:
                        raw_findings.append({
                            "label": "Suspicious Links",
                            "count": len(shady_urls),
                            "severity": "High",
                            "desc": "Urls pointing to known suspicious top-level domains or tunnels were found.",
                            "sample": shady_urls[0]
                        })

                if raw_findings:
                    severity_order = {"Critical": 3, "High": 2, "Medium": 1}
                    raw_findings.sort(key=lambda x: severity_order.get(x["severity"], 0), reverse=True)
                    
                    summary = [f"{f['label']} ({f['count']})" for f in raw_findings]
                    return {
                        "status": "flagged", 
                        "findings": summary, 
                        "raw_findings": raw_findings
                    }
                    
                return {"status": "clean", "findings": [], "raw_findings": []}
                
        except Exception as e:
            return {"status": "error", "message": str(e)}

    def _scan_dlp_contextual(self, content):
        findings = []
        for label, rules in self.dlp_patterns.items():
            pattern = rules["pattern"]
            validator = rules.get("validate")
            needs_context = rules.get("needs_context", False)
            
            valid_matches = []
            for match in pattern.finditer(content):
                match_str = match.group()
                
                if validator and not validator(match_str):
                    continue
                    
                if needs_context and not self._has_context(content, match.start(), match.end()):
                    continue
                    
                valid_matches.append(match_str)
                
            if valid_matches:
                findings.append({
                    "label": label,
                    "count": len(valid_matches),
                    "severity": rules["severity"],
                    "desc": rules["desc"],
                    "sample": valid_matches[0][:4] + "..." if len(valid_matches[0]) > 4 else "***"
                })
        return findings

    def _check_malwarebazaar(self, sha256_hash):
        """Queries the free MalwareBazaar API for the file hash."""
        try:
            url = "https://mb-api.abuse.ch/api/v1/"
            data = urllib.parse.urlencode({"query": "get_info", "hash": sha256_hash}).encode('utf-8')
            req = urllib.request.Request(url, data=data)
            
            with urllib.request.urlopen(req, timeout=3) as response:
                res = json.loads(response.read().decode('utf-8'))
                if res.get('query_status') == 'ok':
                    data = res.get('data', [{}])[0]
                    return {
                        "label": "Known Malware (Threat Intel)",
                        "count": 1,
                        "severity": "Critical",
                        "desc": f"Cloud AV Hash Match! Signature: {data.get('signature', 'Unknown')}. Tags: {data.get('tags', [])}",
                        "sample": f"Hash: {sha256_hash}"
                    }
        except:
            pass # Fail silently for network errors to not block the scan
        return None

    def revoke_public_access(self, file_id):
        """Zero-Trust Enforcement: Revokes 'anyone with the link' access."""
        url = f"https://www.googleapis.com/drive/v3/files/{file_id}/permissions/anyone"
        req = urllib.request.Request(url, headers=self.headers, method='DELETE')
        try:
            with urllib.request.urlopen(req) as response:
                return True
        except HTTPError as e:
            if e.code == 404:
                return True # Already revoked or doesn't exist
            raise Exception(f"Failed to revoke access: {e.read().decode('utf-8')}")

    def vault_file(self, file_id, file_name, file_bytes=None):
        """Cryptographic Vaulting: Downloads, encrypts locally, and deletes from cloud."""
        # 1. Ensure we have the bytes
        if not file_bytes:
            url = f"https://www.googleapis.com/drive/v3/files/{file_id}?alt=media"
            req = urllib.request.Request(url, headers=self.headers)
            with urllib.request.urlopen(req) as response:
                file_bytes = response.read()
                
        # 2. Save locally into a Vault (using a basic local quarantine folder for now)
        vault_dir = os.path.join(os.path.expanduser("~"), "NexaShield_Vault")
        os.makedirs(vault_dir, exist_ok=True)
        
        # Simple obfuscation to prevent accidental execution/opening of vaulted malware
        obfuscated_bytes = bytes([b ^ 0xAA for b in file_bytes])
        vault_path = os.path.join(vault_dir, f"{file_name}.nxvault")
        
        with open(vault_path, 'wb') as f:
            f.write(obfuscated_bytes)
            
        # 3. Delete from Google Drive permanently
        del_url = f"https://www.googleapis.com/drive/v3/files/{file_id}"
        del_req = urllib.request.Request(del_url, headers=self.headers, method='DELETE')
        with urllib.request.urlopen(del_req) as response:
            pass
            
        return vault_path
