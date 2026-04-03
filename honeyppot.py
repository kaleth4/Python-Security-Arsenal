#!/usr/bin/env python3
"""
CyberShield AI - AI Honeypot System v5.0
Deploy decoy AI services to attract and analyze attackers.
Captures: credentials, payloads, techniques, IPs.
Pure Python 3.8+
"""
import json, time, hashlib, re, socket, threading
from datetime import datetime
from collections import defaultdict, deque
from pathlib import Path
from http.server import HTTPServer, BaseHTTPRequestHandler

CAPTURE_DIR = Path.home() / ".cybershield" / "honeypot_captures"
CAPTURE_DIR.mkdir(parents=True, exist_ok=True)

class HoneypotCapture:
    def __init__(self):
        self.captures = deque(maxlen=100000)
        self.attacker_profiles = defaultdict(lambda: {
            "first_seen": None, "last_seen": None,
            "attempts": 0, "techniques": set(), "payloads": []
        })

    def record(self, ip, service, technique, payload=""):
        cap = {"time": datetime.now().isoformat(), "ip": ip,
               "service": service, "technique": technique,
               "payload_hash": hashlib.sha256(payload.encode()).hexdigest()[:16] if payload else "",
               "payload_preview": payload[:200]}
        self.captures.append(cap)

        prof = self.attacker_profiles[ip]
        if not prof["first_seen"]: prof["first_seen"] = cap["time"]
        prof["last_seen"] = cap["time"]
        prof["attempts"] += 1
        prof["techniques"].add(technique)
        if payload: prof["payloads"].append(cap["payload_hash"])

        # Save to disk
        f = CAPTURE_DIR / f"capture_{datetime.now():%Y%m%d}.jsonl"
        with open(f, 'a') as fh: fh.write(json.dumps(cap)+"\n")
        return cap

    def get_stats(self):
        return {"total_captures": len(self.captures),
                "unique_attackers": len(self.attacker_profiles),
                "techniques": list(set(t for p in self.attacker_profiles.values()
                                       for t in p["techniques"]))}

class FakeLLMHandler(BaseHTTPRequestHandler):
    """Fake LLM API that captures prompt injection attempts."""
    honeypot = HoneypotCapture()

    def do_POST(self):
        length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(length).decode('utf-8', errors='replace')
        ip = self.client_address[0]

        # Detect attack type
        technique = "unknown"
        if re.search(r'ignore.*previous|jailbreak|DAN.*mode', body, re.I):
            technique = "prompt_injection"
        elif re.search(r'system.*prompt|reveal.*instructions', body, re.I):
            technique = "prompt_extraction"
        elif len(body) > 10000:
            technique = "context_overflow"

        self.honeypot.record(ip, "fake_llm_api", technique, body)

        # Return convincing but fake response
        response = {"response": "I understand your request. Processing...",
                     "model": "cybershield-gpt-4", "usage": {"tokens": 42}}
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(response).encode())

    def log_message(self, format, *args): pass  # Silent

def run_honeypot(port=8443):
    print(f"🍯 AI Honeypot listening on port {port}")
    server = HTTPServer(('0.0.0.0', port), FakeLLMHandler)
    server.serve_forever()

if __name__ == "__main__":
    import sys
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8443
    print("🍯 CyberShield AI Honeypot v5.0")
    print(f"   Deploying fake LLM API on port {port}")
    print("   Press Ctrl+C to stop")
    try: run_honeypot(port)
    except KeyboardInterrupt:
        print(f"\n📊 {json.dumps(FakeLLMHandler.honeypot.get_stats(), indent=2)}")g