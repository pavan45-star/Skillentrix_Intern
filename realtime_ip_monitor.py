


import os
import sys
import json
import time
import threading
import ipaddress
import requests
import random
import logging
from datetime import datetime
from collections import deque
from flask import Flask, jsonify, Response, send_file
from flask_cors import CORS


VIRUSTOTAL_API_KEY = "49d70ba8d02333e1b76e56f6a982705b6950f59a0b1849598e31b6b5d520ef09"
ABUSEIPDB_API_KEY  = "ead7fa08cb0220f15ed377b656d2a4dd526b0faba4fcc8bf0e8b7c0e4a962e2d4825601897fe1ddd"


USE_DEMO_MODE = False

SCRIPT_DIR     = os.path.dirname(os.path.abspath(__file__))
DASHBOARD_FILE = os.path.join(SCRIPT_DIR, "dashboard.html")

ABUSE_MALICIOUS_THRESHOLD  = 50
ABUSE_SUSPICIOUS_THRESHOLD = 10
VT_MALICIOUS_THRESHOLD     = 3
VT_SUSPICIOUS_THRESHOLD    = 1

CAPTURE_INTERFACE  = None
MAX_LOG_ENTRIES    = 500
API_RATE_LIMIT_SEC = 1.5

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger(__name__)

app = Flask(__name__)
CORS(app)

ip_results     = {}
ip_queue       = deque()
seen_ips       = set()
event_log      = deque(maxlen=MAX_LOG_ENTRIES)
capture_active = threading.Event()
lock           = threading.Lock()
stats = {
    "total_captured": 0,
    "total_checked":  0,
    "malicious":      0,
    "suspicious":     0,
    "safe":           0,
    "start_time":     datetime.now().isoformat(),
}


_PRIVATE = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("224.0.0.0/4"),
    ipaddress.ip_network("240.0.0.0/4"),
    ipaddress.ip_network("100.64.0.0/10"),
]

def is_public_ip(ip_str: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip_str)
        return not any(addr in net for net in _PRIVATE)
    except ValueError:
        return False


def query_abuseipdb(ip: str) -> dict:
    try:
        r = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Accept": "application/json", "Key": ABUSEIPDB_API_KEY},
            params={"ipAddress": ip, "maxAgeInDays": 90},
            timeout=8,
        )
        if r.status_code == 200:
            d = r.json()["data"]
            return {
                "abuse_score":   d.get("abuseConfidenceScore", 0),
                "total_reports": d.get("totalReports", 0),
                "country":       d.get("countryCode", "??"),
                "isp":           d.get("isp", "Unknown"),
                "is_tor":        d.get("isTor", False),
                "domain":        d.get("domain", ""),
                "last_reported": d.get("lastReportedAt", ""),
                "error": None,
            }
        log.warning("AbuseIPDB HTTP %s for %s", r.status_code, ip)
        return {"error": f"HTTP {r.status_code}", "abuse_score": 0,
                "total_reports": 0, "country": "??", "isp": "Unknown", "is_tor": False}
    except Exception as exc:
        log.error("AbuseIPDB error for %s: %s", ip, exc)
        return {"error": str(exc), "abuse_score": 0,
                "total_reports": 0, "country": "??", "isp": "Unknown", "is_tor": False}


def query_virustotal(ip: str) -> dict:
    try:
        r = requests.get(
            f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
            headers={"x-apikey": VIRUSTOTAL_API_KEY},
            timeout=8,
        )
        if r.status_code == 200:
            a = r.json()["data"]["attributes"]
            s = a.get("last_analysis_stats", {})
            return {
                "malicious":  s.get("malicious", 0),
                "suspicious": s.get("suspicious", 0),
                "harmless":   s.get("harmless", 0),
                "undetected": s.get("undetected", 0),
                "reputation": a.get("reputation", 0),
                "as_owner":   a.get("as_owner", "Unknown"),
                "country":    a.get("country", "??"),
                "error": None,
            }
        log.warning("VirusTotal HTTP %s for %s", r.status_code, ip)
        return {"error": f"HTTP {r.status_code}", "malicious": 0, "suspicious": 0,
                "harmless": 0, "undetected": 0, "reputation": 0, "as_owner": "Unknown"}
    except Exception as exc:
        log.error("VirusTotal error for %s: %s", ip, exc)
        return {"error": str(exc), "malicious": 0, "suspicious": 0,
                "harmless": 0, "undetected": 0, "reputation": 0, "as_owner": "Unknown"}


def classify(abuse: dict, vt: dict) -> str:
    mal = sus = False
    score = abuse.get("abuse_score", 0)
    if   score >= ABUSE_MALICIOUS_THRESHOLD:  mal = True
    elif score >= ABUSE_SUSPICIOUS_THRESHOLD: sus = True
    vt_mal = vt.get("malicious", 0)
    vt_sus = vt.get("suspicious", 0)
    if   vt_mal >= VT_MALICIOUS_THRESHOLD:                 mal = True
    elif vt_mal >= VT_SUSPICIOUS_THRESHOLD or vt_sus > 0:  sus = True
    return "MALICIOUS" if mal else ("SUSPICIOUS" if sus else "SAFE")


_DEMO_DATA = [
    ("8.8.8.8",          "SAFE",       0,    0,   0,  0, "US", "Google LLC",              False),
    ("1.1.1.1",          "SAFE",       0,    0,   0,  0, "AU", "Cloudflare Inc",           False),
    ("8.8.4.4",          "SAFE",       0,    0,   0,  0, "US", "Google LLC",              False),
    ("208.67.222.222",   "SAFE",       0,    0,   0,  0, "US", "OpenDNS LLC",             False),
    ("151.101.1.195",    "SAFE",       2,    1,   0,  0, "SE", "Fastly CDN",              False),
    ("45.33.32.156",     "SUSPICIOUS", 16,  47,   2,  1, "US", "Akamai Technologies",     False),
    ("198.20.70.114",    "SUSPICIOUS", 22,  89,   2,  1, "US", "DigitalOcean LLC",         False),
    ("80.82.77.139",     "SUSPICIOUS", 35, 112,   1,  1, "NL", "Censys Inc",              False),
    ("192.241.203.238",  "MALICIOUS",  75, 312,  14,  3, "US", "DigitalOcean LLC",         False),
    ("89.248.167.131",   "MALICIOUS", 100,1024,  22,  5, "NL", "Shodan / Makonix SIA",    False),
    ("185.220.101.45",   "MALICIOUS", 100,2891,  18,  4, "DE", "Tor Exit Node",            True),
    ("194.165.16.11",    "MALICIOUS",  87, 445,  11,  2, "LT", "Hostinger International", False),
    ("91.240.118.168",   "MALICIOUS",  93, 678,  16,  3, "RU", "FOP Sedinkin Alexander",  False),
    ("62.204.41.97",     "MALICIOUS",  78, 234,   9,  2, "RU", "SELECTEL Ltd",            False),
]
_demo_idx = 0

def demo_check_ip(ip: str) -> dict:
    global _demo_idx
    time.sleep(random.uniform(0.3, 0.9))
    row = _DEMO_DATA[_demo_idx % len(_DEMO_DATA)]
    _demo_idx += 1
    _, cls, abuse, reports, vt_mal, vt_sus, country, isp, tor = row
    return {
        "ip":             ip,
        "classification": cls,
        "abuse_score":    abuse,
        "total_reports":  reports,
        "vt_malicious":   vt_mal,
        "vt_suspicious":  vt_sus,
        "country":        country,
        "isp":            isp,
        "is_tor":         tor,
        "domain":         "",
        "as_owner":       isp,
        "checked_at":     datetime.now().isoformat(),
        "demo":           True,
    }


def checker_worker():
    log.info("Checker worker started  [%s]", "DEMO" if USE_DEMO_MODE else "LIVE API")
    while True:
        if ip_queue:
            ip = ip_queue.popleft()
            log.info("Checking: %s", ip)

            if USE_DEMO_MODE:
                result = demo_check_ip(ip)
            else:
                abuse  = query_abuseipdb(ip)
                time.sleep(0.5)
                vt     = query_virustotal(ip)
                cls    = classify(abuse, vt)
                result = {
                    "ip":             ip,
                    "classification": cls,
                    "abuse_score":    abuse.get("abuse_score", 0),
                    "total_reports":  abuse.get("total_reports", 0),
                    "vt_malicious":   vt.get("malicious", 0),
                    "vt_suspicious":  vt.get("suspicious", 0),
                    "country":        abuse.get("country") or vt.get("country", "??"),
                    "isp":            abuse.get("isp", "Unknown"),
                    "is_tor":         abuse.get("is_tor", False),
                    "domain":         abuse.get("domain", ""),
                    "as_owner":       vt.get("as_owner", "Unknown"),
                    "checked_at":     datetime.now().isoformat(),
                    "demo":           False,
                }
                time.sleep(API_RATE_LIMIT_SEC)

            with lock:
                ip_results[ip] = result
                event_log.appendleft(result)
                stats["total_checked"] += 1
                # increment the right counter
                key = result["classification"].lower()   # "malicious", "suspicious", or "safe"
                if key in stats:
                    stats[key] += 1

            log.info("[%s] %s  abuse:%s%%  vt:%s engines",
                     result["classification"], ip,
                     result["abuse_score"], result["vt_malicious"])
        else:
            time.sleep(0.2)


def start_packet_capture():
    try:
        from scapy.all import sniff, IP as ScapyIP, conf
        import socket

        iface    = CAPTURE_INTERFACE or conf.iface
        local_ip = socket.gethostbyname(socket.gethostname())
        log.info("Packet capture on interface: %s  (local: %s)", iface, local_ip)

        def process_packet(pkt):
            if ScapyIP in pkt:
                for addr in [pkt[ScapyIP].src, pkt[ScapyIP].dst]:
                    if addr == local_ip or not is_public_ip(addr):
                        continue
                    with lock:
                        if addr not in seen_ips:
                            seen_ips.add(addr)
                            ip_queue.append(addr)
                            stats["total_captured"] += 1

        capture_active.set()
        sniff(iface=iface, prn=process_packet, store=False, filter="ip")

    except ImportError:
        log.warning("scapy not found — demo capture mode")
        simulate_capture()
    except PermissionError:
        log.error("Permission denied — run as sudo / Administrator")
        simulate_capture()
    except Exception as exc:
        log.error("Capture error (%s) — demo capture mode", exc)
        simulate_capture()


def simulate_capture():
    log.info("Demo capture simulation running")
    capture_active.set()
    demo_ips = [row[0] for row in _DEMO_DATA]
    while True:
        ip = random.choice(demo_ips)
        with lock:
            if ip not in seen_ips:
                seen_ips.add(ip)
                ip_queue.append(ip)
                stats["total_captured"] += 1
        time.sleep(random.uniform(1.5, 4.0))


@app.route("/")
def index():
    if not os.path.exists(DASHBOARD_FILE):
        return (
            f"<h2>dashboard.html not found</h2>"
            f"<p>Expected: <code>{DASHBOARD_FILE}</code></p>"
            f"<p>Put dashboard.html in the same folder as realtime_ip_monitor.py</p>",
            404,
        )
    return send_file(DASHBOARD_FILE)

@app.route("/api/stats")
def get_stats():
    with lock:
        return jsonify({**stats, "queued": len(ip_queue), "known_ips": len(ip_results)})

@app.route("/api/results")
def get_results():
    with lock:
        return jsonify(list(ip_results.values()))

@app.route("/api/malicious")
def get_malicious():
    with lock:
        return jsonify([r for r in ip_results.values() if r["classification"] == "MALICIOUS"])

@app.route("/api/recent")
def get_recent():
    with lock:
        return jsonify(list(event_log)[:50])

@app.route("/api/status")
def get_status():
    return jsonify({
        "capture_active":   capture_active.is_set(),
        "demo_mode":        USE_DEMO_MODE,
        "api_keys_set":     not USE_DEMO_MODE,
        "queued":           len(ip_queue),
        "dashboard_found":  os.path.exists(DASHBOARD_FILE),
    })

@app.route("/stream")
def stream():
    def event_generator():
        last_seen = 0
        while True:
            with lock:
                current       = list(event_log)
                new_count     = len(current) - last_seen
                new_events    = current[:new_count] if new_count > 0 else []
                last_seen     = len(current)
                current_stats = {**stats, "queued": len(ip_queue)}

            for evt in reversed(new_events):
                yield f"data: {json.dumps({'type': 'ip_result', 'data': evt})}\n\n"

            yield f"data: {json.dumps({'type': 'stats', 'data': current_stats})}\n\n"
            time.sleep(1)

    return Response(
        event_generator(),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


if __name__ == "__main__":
    mode_label = "DEMO MODE (no real API keys)" if USE_DEMO_MODE else "LIVE MODE (real API keys active)"
    dash_label = "FOUND" if os.path.exists(DASHBOARD_FILE) else "NOT FOUND - check folder!"

    print(f"""
╔══════════════════════════════════════════════════════════╗
║   REAL-TIME MALICIOUS IP INTELLIGENCE SYSTEM             ║
║   Final Year Project - Networking / Cybersecurity        ║
╠══════════════════════════════════════════════════════════╣
║   Dashboard  ->  http://localhost:5000                   ║
║   Mode       ->  {mode_label:<42}                        ║
║   HTML file  ->  {dash_label:<42}                        ║
╚══════════════════════════════════════════════════════════╝
""")

    if not os.path.exists(DASHBOARD_FILE):
        print(f"  WARNING: dashboard.html not found at:\n    {DASHBOARD_FILE}")
        print("  Make sure both files are in the SAME folder.\n")

    if USE_DEMO_MODE:
        print("  Running in DEMO MODE.")
        print("  To use real APIs: paste your keys at the top of this file.\n")
    else:
        print("  API keys detected - live threat intelligence ACTIVE.\n")
        # Cross-platform admin check (works on Windows AND Linux/Mac)
        try:
            is_admin = (os.geteuid() == 0)
        except AttributeError:
            import ctypes
            try:
                is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
            except Exception:
                is_admin = True  # assume ok if we can't check
        if not is_admin:
            print("  WARNING: Not running as Administrator/root.")
            print("  Live packet capture needs elevated privileges.\n")

    threading.Thread(target=checker_worker,       daemon=True, name="checker").start()
    threading.Thread(target=start_packet_capture, daemon=True, name="capture").start()

    app.run(host="0.0.0.0", port=5000, threaded=True, debug=False)
