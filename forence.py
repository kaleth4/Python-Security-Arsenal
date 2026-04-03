#!/usr/bin/env python3
"""
CyberShield AI - Digital Forensics Toolkit v5.0
File forensics, metadata extraction, timeline analysis,
artifact recovery, and IOC extraction.
Pure Python 3.8+
"""
import os, sys, json, hashlib, struct, time, re
from pathlib import Path
from datetime import datetime
from collections import defaultdict

class ForensicAnalyzer:
    def __init__(self):
        self.artifacts = []
        self.timeline = []
        self.iocs = {"ips": set(), "domains": set(),
                     "hashes": set(), "emails": set(), "urls": set()}

    def analyze_file(self, path):
        """Deep forensic analysis of a single file."""
        path = Path(path)
        result = {"file": str(path), "name": path.name,
                  "analysis": {}, "artifacts": [], "iocs": []}

        stat = path.stat()
        result["analysis"]["size"] = stat.st_size
        result["analysis"]["created"] = datetime.fromtimestamp(stat.st_ctime).isoformat()
        result["analysis"]["modified"] = datetime.fromtimestamp(stat.st_mtime).isoformat()
        result["analysis"]["accessed"] = datetime.fromtimestamp(stat.st_atime).isoformat()

        # Hashes
        md5, sha1, sha256 = self._hash(path)
        result["analysis"]["hashes"] = {"md5": md5, "sha1": sha1, "sha256": sha256}

        # File type detection
        result["analysis"]["magic"] = self._file_magic(path)

        # String extraction & IOC mining
        strings = self._extract_strings(path)
        result["analysis"]["string_count"] = len(strings)

        # Extract IOCs from strings
        for s in strings:
            ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', s)
            for ip in ips: self.iocs["ips"].add(ip); result["iocs"].append({"type":"ip","value":ip})

            domains = re.findall(r'\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b', s)
            for d in domains:
                if len(d) > 5: self.iocs["domains"].add(d); result["iocs"].append({"type":"domain","value":d})

            urls = re.findall(r'https?://[^\s<>"{}|\\^\[\]]+', s)
            for u in urls: self.iocs["urls"].add(u); result["iocs"].append({"type":"url","value":u})

            emails = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', s)
            for e in emails: self.iocs["emails"].add(e); result["iocs"].append({"type":"email","value":e})

        # Timeline entry
        self.timeline.append({
            "time": result["analysis"]["modified"],
            "file": path.name, "action": "analyzed"})

        self.artifacts.append(result)
        return result

    def _hash(self, path):
        md5, sha1, sha256 = hashlib.md5(), hashlib.sha1(), hashlib.sha256()
        try:
            with open(path, 'rb') as f:
                for chunk in iter(lambda: f.read(65536), b''):
                    md5.update(chunk); sha1.update(chunk); sha256.update(chunk)
            return md5.hexdigest(), sha1.hexdigest(), sha256.hexdigest()
        except: return None, None, None

    def _file_magic(self, path):
        try:
            with open(path, 'rb') as f: hdr = f.read(16)
            magic_map = {
                b'\x89PNG': 'PNG Image', b'\xff\xd8\xff': 'JPEG Image',
                b'GIF8': 'GIF Image', b'PK': 'ZIP/Office/JAR',
                b'MZ': 'PE Executable', b'\x7fELF': 'ELF Binary',
                b'%PDF': 'PDF Document', b'\xd0\xcf\x11\xe0': 'OLE/MS Office',
            }
            for sig, desc in magic_map.items():
                if hdr.startswith(sig): return desc
            return "Unknown"
        except: return "Error"

    def _extract_strings(self, path, min_len=6):
        strings = []
        try:
            with open(path, 'rb') as f: data = f.read(10485760)
            current = []
            for byte in data:
                if 32 <= byte < 127: current.append(chr(byte))
                else:
                    if len(current) >= min_len: strings.append(''.join(current))
                    current = []
        except: pass
        return strings[:5000]

    def generate_report(self):
        return {"files_analyzed": len(self.artifacts),
                "total_iocs": {k: len(v) for k, v in self.iocs.items()},
                "timeline_entries": len(self.timeline),
                "generated": datetime.now().isoformat()}

if __name__ == "__main__":
    fa = ForensicAnalyzer()
    if len(sys.argv) < 2:
        print("Usage: python forensics.py <file_or_directory>")
        sys.exit(0)
    target = Path(sys.argv[1])
    if target.is_file():
        r = fa.analyze_file(target)
        print(json.dumps(r, indent=2, default=str))
    elif target.is_dir():
        for f in target.rglob('*'):
            if f.is_file(): fa.analyze_file(f)
        print(json.dumps(fa.generate_report(), indent=2, default=str))
    print(f"\n🔬 Report: {json.dumps(fa.generate_report(), indent=2, default=str)}")