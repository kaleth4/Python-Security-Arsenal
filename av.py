#!/usr/bin/env python3
"""
CyberShield AI - Advanced Antivirus Scanner v5.0
Multi-engine file analysis with VirusTotal integration.
Pure Python 3.8+ — No React, No Node.js
"""
import hashlib, os, sys, json, time, math, struct, re
import requests
from pathlib import Path
from datetime import datetime
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed

# ═══════════════ CONFIG ═══════════════
VT_API_KEY = os.getenv("VT_API_KEY", "")
VT_API_URL = "https://www.virustotal.com/api/v3"
QUARANTINE = Path.home() / ".cybershield" / "quarantine"
LOGS = Path.home() / ".cybershield" / "logs"
MAX_VT_SIZE = 650 * 1024 * 1024
THREADS = 8

MALWARE_SIGS = {
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a",
}
DANGER_EXTS = {'.exe','.dll','.scr','.bat','.cmd','.vbs','.js','.ps1','.hta','.msi','.jar','.pif','.com','.wsf'}
SUSPICIOUS_STRINGS = [
    b'cmd.exe', b'powershell', b'/bin/sh', b'WScript.Shell',
    b'eval(', b'exec(', b'CreateRemoteThread', b'VirtualAlloc',
    b'URLDownloadToFile', b'ShellExecute', b'CurrentVersion\\Run',
    b'mimikatz', b'metasploit', b'reverse_tcp', b'socket.connect',
    b'subprocess.call', b'os.system(', b'__import__(',
    b'base64.b64decode', b'pickle.loads', b'torch.load',
    b'tensorflow', b'model.predict', b'gradient', b'adversarial',
]

class CyberShieldScanner:
    def __init__(self):
        self.stats = {"scanned": 0, "threats": 0, "clean": 0}
        QUARANTINE.mkdir(parents=True, exist_ok=True)
        LOGS.mkdir(parents=True, exist_ok=True)

    def hash_file(self, path):
        md5, sha1, sha256 = hashlib.md5(), hashlib.sha1(), hashlib.sha256()
        try:
            with open(path, 'rb') as f:
                for chunk in iter(lambda: f.read(65536), b''):
                    md5.update(chunk); sha1.update(chunk); sha256.update(chunk)
            return md5.hexdigest(), sha1.hexdigest(), sha256.hexdigest()
        except: return None, None, None

    def entropy(self, path):
        try:
            with open(path, 'rb') as f: data = f.read(1048576)
            if not data: return 0.0
            freq = Counter(data); n = len(data)
            return -sum((c/n)*math.log2(c/n) for c in freq.values())
        except: return 0.0

    def check_pe(self, path):
        try:
            with open(path, 'rb') as f: hdr = f.read(512)
            flags = []
            if hdr[:2] == b'MZ':
                flags.append("PE_EXECUTABLE")
                if b'UPX' in hdr: flags.append("UPX_PACKED")
                if b'.aspack' in hdr: flags.append("ASPACK_PACKED")
            elif hdr[:4] == b'\x7fELF': flags.append("ELF_BINARY")
            return flags
        except: return []

    def find_strings(self, path):
        found = []
        try:
            with open(path, 'rb') as f: data = f.read(5242880)
            for pat in SUSPICIOUS_STRINGS:
                if pat in data: found.append(pat.decode('utf-8', errors='replace'))
        except: pass
        return found

    def scan(self, path):
        path = Path(path)
        r = {"file": str(path), "name": path.name, "size": 0,
             "status": "clean", "threats": [], "hashes": {},
             "entropy": 0, "timestamp": datetime.now().isoformat()}
        try: r["size"] = path.stat().st_size
        except: r["status"] = "error"; return r

        md5, sha1, sha256 = self.hash_file(path)
        if not sha256: r["status"] = "error"; return r
        r["hashes"] = {"md5": md5, "sha1": sha1, "sha256": sha256}

        if sha256 in MALWARE_SIGS:
            r["status"] = "malicious"
            r["threats"].append(f"Known malware: {sha256[:16]}...")

        ent = self.entropy(path); r["entropy"] = round(ent, 4)
        if ent > 7.5:
            r["threats"].append(f"High entropy: {ent:.2f}")
            if r["status"] == "clean": r["status"] = "suspicious"

        pe = self.check_pe(path)
        if any(x in pe for x in ["UPX_PACKED", "ASPACK_PACKED"]):
            r["threats"].append("Packed executable")
            if r["status"] == "clean": r["status"] = "suspicious"

        sus = self.find_strings(path)
        if len(sus) >= 3:
            r["threats"].append(f"{len(sus)} suspicious strings")
            if r["status"] == "clean": r["status"] = "suspicious"

        if path.suffix.lower() in DANGER_EXTS:
            r["threats"].append(f"Dangerous ext: {path.suffix}")

        self.stats["scanned"] += 1
        self.stats["threats" if r["status"] != "clean" else "clean"] += 1
        return r

    def scan_dir(self, directory, recursive=True):
        d = Path(directory)
        files = list(d.rglob('*') if recursive else d.iterdir())
        files = [f for f in files if f.is_file()]
        print(f"\n🔍 Scanning {len(files)} files...")
        results = []
        with ThreadPoolExecutor(max_workers=THREADS) as ex:
            futs = {ex.submit(self.scan, f): f for f in files}
            for i, fut in enumerate(as_completed(futs), 1):
                r = fut.result(); results.append(r)
                ic = {"clean":"✅","suspicious":"⚠️","malicious":"🔴","error":"❌"}
                print(f"  [{i}/{len(files)}] {ic.get(r['status'],'?')} {r['name']}")
        return results

    def quarantine(self, path):
        src = Path(path); dst = QUARANTINE / f"{src.name}.quarantined"
        try: src.rename(dst); print(f"🔒 Quarantined: {src.name}"); return True
        except Exception as e: print(f"❌ Failed: {e}"); return False

    def vt_scan(self, path):
        if not VT_API_KEY: print("❌ Set VT_API_KEY"); return None
        path = Path(path)
        if path.stat().st_size > MAX_VT_SIZE:
            print("❌ File too large for VT"); return None
        print(f"📤 Uploading {path.name} to VirusTotal...")
        with open(path, 'rb') as f:
            r = requests.post(f"{VT_API_URL}/files",
                headers={"x-apikey": VT_API_KEY},
                files={"file": (path.name, f)})
        if r.status_code == 200:
            aid = r.json()["data"]["id"]
            print(f"✅ Submitted: {aid}")
            return self._poll_vt(aid)
        print(f"❌ Upload failed: {r.status_code}")
        return None

    def vt_hash(self, h):
        if not VT_API_KEY: return None
        r = requests.get(f"{VT_API_URL}/files/{h}",
            headers={"x-apikey": VT_API_KEY})
        if r.status_code == 200:
            s = r.json()["data"]["attributes"]["last_analysis_stats"]
            return {"malicious": s.get("malicious",0), "total": sum(s.values())}
        return None

    def _poll_vt(self, aid, timeout=300):
        start = time.time()
        while time.time() - start < timeout:
            r = requests.get(f"{VT_API_URL}/analyses/{aid}",
                headers={"x-apikey": VT_API_KEY})
            if r.status_code == 200:
                d = r.json()["data"]
                if d["attributes"]["status"] == "completed":
                    s = d["attributes"]["stats"]
                    return {"malicious": s.get("malicious",0),
                            "total": sum(s.values())}
            time.sleep(15)
        return {"error": "timeout"}

if __name__ == "__main__":
    sc = CyberShieldScanner()
    if len(sys.argv) < 2:
        print("Usage: python cybershield.py scan <path>")
        print("       python cybershield.py vt-file <file>")
        print("       python cybershield.py vt-hash <hash>")
        sys.exit(0)
    cmd, tgt = sys.argv[1], sys.argv[2] if len(sys.argv)>2 else None
    if cmd == "scan" and tgt:
        p = Path(tgt)
        if p.is_file(): print(json.dumps(sc.scan(p), indent=2))
        elif p.is_dir(): sc.scan_dir(p); print(f"\n📊 {sc.stats}")
    elif cmd == "vt-file" and tgt: print(json.dumps(sc.vt_scan(tgt), indent=2))
    elif cmd == "vt-hash" and tgt: print(json.dumps(sc.vt_hash(tgt), indent=2))
    elif cmd == "quarantine" and tgt: sc.quarantine(tgt)