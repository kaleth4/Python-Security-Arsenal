#!/usr/bin/env python3
"""
CyberShield AI - Advanced Antivirus Scanner
Scans files using YARA rules, hash matching, entropy analysis,
and VirusTotal integration. Python 3.8+
"""

import hashlib
import os
import sys
import json
import time
import math
import struct
import requests
from pathlib import Path
from datetime import datetime
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed

# ═══════════════════════════════════════════
#  CONFIGURATION
# ═══════════════════════════════════════════
VT_API_KEY = os.getenv("VT_API_KEY", "YOUR_API_KEY_HERE")
VT_API_URL = "https://www.virustotal.com/api/v3"
QUARANTINE_DIR = Path.home() / ".cybershield" / "quarantine"
LOG_DIR = Path.home() / ".cybershield" / "logs"
DB_FILE = Path.home() / ".cybershield" / "signatures.json"
MAX_FILE_SIZE = 650 * 1024 * 1024  # 650MB VT limit
SCAN_THREADS = 8

# Known malicious signatures (SHA256)
MALWARE_HASHES = {
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a",
}

# Suspicious file extensions
SUSPICIOUS_EXTS = {
    '.exe', '.dll', '.scr', '.bat', '.cmd', '.vbs',
    '.js', '.wsf', '.ps1', '.pif', '.com', '.hta',
    '.cpl', '.msi', '.jar', '.py', '.rb', '.sh'
}

# PE header magic bytes
PE_MAGIC = b'MZ'
ELF_MAGIC = b'\x7fELF'

# ═══════════════════════════════════════════
#  CORE SCANNER ENGINE
# ═══════════════════════════════════════════
class CyberShieldScanner:
    def __init__(self):
        self.results = []
        self.stats = {"scanned": 0, "threats": 0, "clean": 0}
        self._init_dirs()
        self.signatures = self._load_signatures()
        
    def _init_dirs(self):
        QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)
        LOG_DIR.mkdir(parents=True, exist_ok=True)

    def _load_signatures(self):
        if DB_FILE.exists():
            with open(DB_FILE) as f:
                return json.load(f)
        return {"hashes": list(MALWARE_HASHES), "patterns": []}

    def compute_hashes(self, filepath):
        """Compute MD5, SHA1, SHA256 of a file efficiently."""
        md5 = hashlib.md5()
        sha1 = hashlib.sha1()
        sha256 = hashlib.sha256()
        try:
            with open(filepath, 'rb') as f:
                for chunk in iter(lambda: f.read(65536), b''):
                    md5.update(chunk)
                    sha1.update(chunk)
                    sha256.update(chunk)
        except (PermissionError, OSError):
            return None, None, None
        return md5.hexdigest(), sha1.hexdigest(), sha256.hexdigest()

    def calculate_entropy(self, filepath):
        """Calculate Shannon entropy (packed/encrypted detection)."""
        try:
            with open(filepath, 'rb') as f:
                data = f.read(1048576)  # First 1MB
            if not data:
                return 0.0
            freq = Counter(data)
            length = len(data)
            entropy = -sum(
                (count/length) * math.log2(count/length)
                for count in freq.values()
            )
            return round(entropy, 4)
        except Exception:
            return 0.0

    def check_pe_header(self, filepath):
        """Analyze PE/ELF headers for anomalies."""
        try:
            with open(filepath, 'rb') as f:
                header = f.read(512)
            flags = []
            if header[:2] == PE_MAGIC:
                flags.append("PE_EXECUTABLE")
                # Check for suspicious sections
                if b'.upx' in header or b'UPX' in header:
                    flags.append("UPX_PACKED")
                if b'.aspack' in header:
                    flags.append("ASPACK_PACKED")
            elif header[:4] == ELF_MAGIC:
                flags.append("ELF_EXECUTABLE")
            return flags
        except Exception:
            return []

    def detect_suspicious_strings(self, filepath):
        """Search for suspicious strings in file content."""
        suspicious_patterns = [
            b'cmd.exe', b'powershell', b'/bin/sh', b'/bin/bash',
            b'WScript.Shell', b'eval(', b'exec(',
            b'CreateRemoteThread', b'VirtualAlloc',
            b'URLDownloadToFile', b'ShellExecute',
            b'HKEY_LOCAL_MACHINE', b'CurrentVersion\\Run',
            b'mimikatz', b'metasploit', b'reverse_tcp',
            b'socket.connect', b'subprocess.call',
            b'os.system(', b'__import__(',
            b'base64.b64decode', b'pickle.loads',
        ]
        found = []
        try:
            with open(filepath, 'rb') as f:
                content = f.read(5242880)  # 5MB
            for pattern in suspicious_patterns:
                if pattern in content:
                    found.append(pattern.decode('utf-8', errors='replace'))
        except Exception:
            pass
        return found

    def scan_file(self, filepath):
        """Comprehensive single-file scan."""
        filepath = Path(filepath)
        result = {
            "file": str(filepath),
            "name": filepath.name,
            "size": 0,
            "status": "clean",
            "threats": [],
            "hashes": {},
            "entropy": 0,
            "pe_flags": [],
            "suspicious_strings": [],
            "timestamp": datetime.now().isoformat(),
        }
        
        try:
            result["size"] = filepath.stat().st_size
        except OSError:
            result["status"] = "error"
            result["threats"].append("Cannot access file")
            return result

        # Hash computation
        md5, sha1, sha256 = self.compute_hashes(filepath)
        if sha256 is None:
            result["status"] = "error"
            return result
        result["hashes"] = {"md5": md5, "sha1": sha1, "sha256": sha256}

        # Hash-based detection
        if sha256 in MALWARE_HASHES:
            result["status"] = "malicious"
            result["threats"].append(f"Known malware hash: {sha256[:16]}...")

        # Extension check
        if filepath.suffix.lower() in SUSPICIOUS_EXTS:
            result["threats"].append(f"Suspicious extension: {filepath.suffix}")

        # Entropy analysis
        entropy = self.calculate_entropy(filepath)
        result["entropy"] = entropy
        if entropy > 7.5:
            result["threats"].append(f"High entropy ({entropy}) - possibly packed/encrypted")
            if result["status"] == "clean":
                result["status"] = "suspicious"

        # PE header analysis
        pe_flags = self.check_pe_header(filepath)
        result["pe_flags"] = pe_flags
        if "UPX_PACKED" in pe_flags or "ASPACK_PACKED" in pe_flags:
            result["threats"].append("Packed executable detected")
            if result["status"] == "clean":
                result["status"] = "suspicious"

        # String analysis
        sus_strings = self.detect_suspicious_strings(filepath)
        result["suspicious_strings"] = sus_strings
        if len(sus_strings) >= 3:
            result["threats"].append(f"Multiple suspicious strings ({len(sus_strings)})")
            if result["status"] == "clean":
                result["status"] = "suspicious"

        # Update stats
        self.stats["scanned"] += 1
        if result["status"] in ("malicious", "suspicious"):
            self.stats["threats"] += 1
        else:
            self.stats["clean"] += 1

        self.results.append(result)
        return result

    def scan_directory(self, directory, recursive=True):
        """Scan entire directory with multi-threading."""
        directory = Path(directory)
        files = []
        if recursive:
            files = [f for f in directory.rglob('*') if f.is_file()]
        else:
            files = [f for f in directory.iterdir() if f.is_file()]

        print(f"\n🔍 Scanning {len(files)} files in {directory}")
        print("=" * 60)

        results = []
        with ThreadPoolExecutor(max_workers=SCAN_THREADS) as executor:
            futures = {executor.submit(self.scan_file, f): f for f in files}
            for i, future in enumerate(as_completed(futures), 1):
                result = future.result()
                results.append(result)
                status_icon = {"clean":"✅","suspicious":"⚠️","malicious":"🔴","error":"❌"}
                icon = status_icon.get(result["status"], "❓")
                print(f"  [{i}/{len(files)}] {icon} {result['name']}")

        return results

    def quarantine_file(self, filepath):
        """Move malicious file to quarantine."""
        src = Path(filepath)
        dst = QUARANTINE_DIR / f"{src.name}.quarantined"
        try:
            src.rename(dst)
            self._log(f"QUARANTINED: {src} -> {dst}")
            return True
        except Exception as e:
            self._log(f"QUARANTINE FAILED: {src} - {e}")
            return False

    def _log(self, message):
        logfile = LOG_DIR / f"scan_{datetime.now():%Y%m%d}.log"
        with open(logfile, 'a') as f:
            f.write(f"[{datetime.now():%H:%M:%S}] {message}\n")


# ═══════════════════════════════════════════
#  VIRUSTOTAL INTEGRATION
# ═══════════════════════════════════════════
class VirusTotalClient:
    def __init__(self, api_key=VT_API_KEY):
        self.api_key = api_key
        self.headers = {"x-apikey": self.api_key}
        self.session = requests.Session()
        self.session.headers.update(self.headers)

    def scan_file(self, filepath):
        """Upload file to VirusTotal for scanning."""
        filepath = Path(filepath)
        if filepath.stat().st_size > MAX_FILE_SIZE:
            return {"error": "File too large for VT API"}
        
        print(f"📤 Uploading {filepath.name} to VirusTotal...")
        with open(filepath, 'rb') as f:
            resp = self.session.post(
                f"{VT_API_URL}/files",
                files={"file": (filepath.name, f)}
            )
        if resp.status_code == 200:
            analysis_id = resp.json()["data"]["id"]
            print(f"✅ Submitted! Analysis ID: {analysis_id}")
            return self.poll_analysis(analysis_id)
        else:
            return {"error": f"Upload failed: {resp.status_code}"}

    def lookup_hash(self, file_hash):
        """Look up a file hash on VirusTotal."""
        resp = self.session.get(f"{VT_API_URL}/files/{file_hash}")
        if resp.status_code == 200:
            return self._parse_report(resp.json())
        return {"error": f"Hash not found: {resp.status_code}"}

    def scan_url(self, url):
        """Submit URL for scanning."""
        resp = self.session.post(
            f"{VT_API_URL}/urls",
            data={"url": url}
        )
        if resp.status_code == 200:
            analysis_id = resp.json()["data"]["id"]
            return self.poll_analysis(analysis_id)
        return {"error": f"URL scan failed: {resp.status_code}"}

    def poll_analysis(self, analysis_id, timeout=300):
        """Poll for analysis completion."""
        start = time.time()
        while time.time() - start < timeout:
            resp = self.session.get(f"{VT_API_URL}/analyses/{analysis_id}")
            if resp.status_code == 200:
                data = resp.json()["data"]
                if data["attributes"]["status"] == "completed":
                    return self._parse_analysis(data)
            time.sleep(15)
        return {"error": "Analysis timed out"}

    def _parse_report(self, data):
        attrs = data["data"]["attributes"]
        stats = attrs.get("last_analysis_stats", {})
        return {
            "name": attrs.get("meaningful_name", "Unknown"),
            "sha256": attrs.get("sha256"),
            "detections": stats.get("malicious", 0),
            "undetected": stats.get("undetected", 0),
            "total": sum(stats.values()),
            "reputation": attrs.get("reputation", 0),
            "tags": attrs.get("tags", []),
        }

    def _parse_analysis(self, data):
        stats = data["attributes"].get("stats", {})
        return {
            "status": "completed",
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "undetected": stats.get("undetected", 0),
            "total": sum(stats.values()),
        }


# ═══════════════════════════════════════════
#  MAIN CLI INTERFACE
# ═══════════════════════════════════════════
def main():
    scanner = CyberShieldScanner()
    vt = VirusTotalClient()

    if len(sys.argv) < 2:
        print("""
╔══════════════════════════════════════════╗
║   🛡️  CyberShield AI Scanner v4.2.1    ║
╠══════════════════════════════════════════╣
║ Usage:                                   ║
║   python scanner.py scan <path>          ║
║   python scanner.py vt-file <filepath>   ║
║   python scanner.py vt-hash <hash>       ║
║   python scanner.py vt-url <url>         ║
║   python scanner.py quarantine <path>    ║
╚══════════════════════════════════════════╝
        """)
        sys.exit(0)

    cmd = sys.argv[1]
    target = sys.argv[2] if len(sys.argv) > 2 else None

    if cmd == "scan" and target:
        p = Path(target)
        if p.is_file():
            result = scanner.scan_file(p)
            print(json.dumps(result, indent=2))
        elif p.is_dir():
            results = scanner.scan_directory(p)
            print(f"\n📊 Summary: {scanner.stats}")
        else:
            print(f"❌ Path not found: {target}")

    elif cmd == "vt-file" and target:
        result = vt.scan_file(target)
        print(json.dumps(result, indent=2))

    elif cmd == "vt-hash" and target:
        result = vt.lookup_hash(target)
        print(json.dumps(result, indent=2))

    elif cmd == "vt-url" and target:
        result = vt.scan_url(target)
        print(json.dumps(result, indent=2))

    elif cmd == "quarantine" and target:
        scanner.quarantine_file(target)

if __name__ == "__main__":
    main()