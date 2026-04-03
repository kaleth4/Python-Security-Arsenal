#!/usr/bin/env python3
"""
CyberShield AI - Network Security Monitor v5.0
Real-time connection monitoring, port scanning detection,
C2 callback detection, DNS exfiltration defense.
Pure Python 3.8+
"""
import socket, json, time, threading, hashlib, re
from datetime import datetime
from collections import defaultdict, deque
from pathlib import Path

KNOWN_C2 = {"203.0.113.42", "198.51.100.23", "192.0.2.88"}
BLOCKED_PORTS = {4444, 5555, 6666, 1337, 31337, 8888}
DNS_EXFIL_THRESHOLD = 50  # Suspicious if >50 TXT queries/min

class NetworkMonitor:
    def __init__(self):
        self.connections = deque(maxlen=50000)
        self.alerts = deque(maxlen=10000)
        self.blocked_ips = set()
        self.dns_queries = defaultdict(list)
        self.port_scan_tracker = defaultdict(set)
        self.rate_tracker = defaultdict(int)
        self.log_dir = Path.home() / ".cybershield" / "network_logs"
        self.log_dir.mkdir(parents=True, exist_ok=True)

    def analyze_connection(self, src_ip, dst_ip, dst_port, proto="TCP"):
        conn = {"time": datetime.now().isoformat(), "src": src_ip,
                "dst": dst_ip, "port": dst_port, "proto": proto,
                "status": "allowed", "threats": []}

        # C2 check
        if dst_ip in KNOWN_C2:
            conn["status"] = "blocked"
            conn["threats"].append(f"Known C2 server: {dst_ip}")
            self.blocked_ips.add(dst_ip)

        # Dangerous port
        if dst_port in BLOCKED_PORTS:
            conn["status"] = "blocked"
            conn["threats"].append(f"Blocked port: {dst_port}")

        # Port scan detection
        self.port_scan_tracker[src_ip].add(dst_port)
        if len(self.port_scan_tracker[src_ip]) > 20:
            conn["status"] = "blocked"
            conn["threats"].append(f"Port scan: {len(self.port_scan_tracker[src_ip])} ports")
            self.blocked_ips.add(src_ip)

        # Rate limiting
        self.rate_tracker[src_ip] += 1
        if self.rate_tracker[src_ip] > 1000:
            conn["status"] = "blocked"
            conn["threats"].append("Rate limit exceeded")

        self.connections.append(conn)
        if conn["threats"]:
            self.alerts.append(conn)
            self._log(f"ALERT: {conn}")
        return conn

    def analyze_dns(self, domain, query_type="A", src_ip="unknown"):
        """Detect DNS exfiltration and DGA domains."""
        result = {"domain": domain, "type": query_type, "src": src_ip,
                  "status": "clean", "threats": []}

        # DGA detection (high entropy domain)
        parts = domain.split('.')
        if len(parts) >= 2:
            label = parts[0]
            if len(label) > 20:
                entropy = self._entropy(label)
                if entropy > 3.5:
                    result["status"] = "suspicious"
                    result["threats"].append(f"Possible DGA: entropy={entropy:.2f}")

        # TXT record exfil detection
        if query_type == "TXT":
            self.dns_queries[src_ip].append(time.time())
            recent = [t for t in self.dns_queries[src_ip] if time.time()-t < 60]
            if len(recent) > DNS_EXFIL_THRESHOLD:
                result["status"] = "blocked"
                result["threats"].append(f"DNS exfiltration: {len(recent)} TXT queries/min")

        # Base64 in subdomain
        if re.match(r'^[A-Za-z0-9+/=]{20,}$', parts[0]):
            result["status"] = "suspicious"
            result["threats"].append("Base64-encoded subdomain — possible exfil")

        return result

    def _entropy(self, s):
        from collections import Counter
        import math
        freq = Counter(s); n = len(s)
        return -sum((c/n)*math.log2(c/n) for c in freq.values()) if n else 0

    def get_stats(self):
        return {"total_connections": len(self.connections),
                "alerts": len(self.alerts),
                "blocked_ips": len(self.blocked_ips),
                "port_scans_detected": sum(1 for v in self.port_scan_tracker.values() if len(v)>20)}

    def _log(self, msg):
        f = self.log_dir / f"net_{datetime.now():%Y%m%d}.log"
        with open(f, 'a') as fh:
            fh.write(f"[{datetime.now():%H:%M:%S}] {msg}\n")

if __name__ == "__main__":
    mon = NetworkMonitor()
    print("🌐 CyberShield Network Monitor v5.0")
    # Simulate traffic
    tests = [
        ("10.0.0.5", "8.8.8.8", 443),
        ("10.0.0.5", "203.0.113.42", 4444),  # C2!
        ("192.168.1.100", "10.0.0.1", 22),
    ]
    for src, dst, port in tests:
        r = mon.analyze_connection(src, dst, port)
        s = "🔴" if r["status"]=="blocked" else "🟢"
        print(f"  {s} {src} -> {dst}:{port} {r['threats']}")
    print(f"\n📊 {json.dumps(mon.get_stats(), indent=2)}")