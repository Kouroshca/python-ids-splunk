import scapy.all as scapy
import requests
import os
import time
import warnings
from collections import defaultdict
from dotenv import load_dotenv

warnings.filterwarnings("ignore")
load_dotenv()

SPLUNK_URL = os.getenv("SPLUNK_HEC_URL")
SPLUNK_TOKEN = os.getenv("SPLUNK_TOKEN")
HEADERS = {"Authorization": f"Splunk {SPLUNK_TOKEN}"}

# Detection thresholds
PORT_SCAN_THRESHOLD = 10   # unique ports in time window = port scan
BRUTE_FORCE_THRESHOLD = 5  # same port repeated = brute force
TIME_WINDOW = 10           # seconds

# Trackers
port_tracker = defaultdict(set)       # src_ip -> set of ports
brute_tracker = defaultdict(int)      # src_ip:dst_port -> count
timestamps = defaultdict(float)       # src_ip -> first seen time

def send_to_splunk(event_data):
    payload = {
        "event": event_data,
        "sourcetype": "ids_alert"
    }
    try:
        requests.post(SPLUNK_URL, headers=HEADERS, json=payload, verify=False)
    except Exception as e:
        print(f"[ERROR] Failed to send to Splunk: {e}")

def analyze_packet(packet):
    if not packet.haslayer(scapy.IP):
        return

    src_ip = packet[scapy.IP].src
    dst_ip = packet[scapy.IP].dst
    now = time.time()

    if packet.haslayer(scapy.TCP):
        dst_port = packet[scapy.TCP].dport
        flags = packet[scapy.TCP].flags

        # Reset tracker if time window expired
        if now - timestamps[src_ip] > TIME_WINDOW:
            port_tracker[src_ip].clear()
            brute_tracker[src_ip] = 0
            timestamps[src_ip] = now

        # Track ports hit by this IP
        port_tracker[src_ip].add(dst_port)
        brute_key = f"{src_ip}:{dst_port}"
        brute_tracker[brute_key] += 1

        # Detection: Port Scan
        if len(port_tracker[src_ip]) >= PORT_SCAN_THRESHOLD:
            alert = {
                "alert_type": "PORT_SCAN",
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "ports_scanned": len(port_tracker[src_ip]),
                "severity": "HIGH",
                "timestamp": now
            }
            print(f"[ALERT] PORT SCAN detected from {src_ip}")
            send_to_splunk(alert)
            port_tracker[src_ip].clear()

        # Detection: Brute Force
        if brute_tracker[brute_key] >= BRUTE_FORCE_THRESHOLD and dst_port == 22:
            alert = {
                "alert_type": "BRUTE_FORCE_SSH",
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "dst_port": dst_port,
                "attempt_count": brute_tracker[brute_key],
                "severity": "CRITICAL",
                "timestamp": now
            }
            print(f"[ALERT] BRUTE FORCE SSH detected from {src_ip}")
            send_to_splunk(alert)
            brute_tracker[brute_key] = 0

        # Detection: SYN Flood
        if flags == "S":
            alert = {
                "alert_type": "SYN_PACKET",
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "dst_port": dst_port,
                "severity": "LOW",
                "timestamp": now
            }
            send_to_splunk(alert)

print("[IDS] Starting packet capture... Press Ctrl+C to stop.")
scapy.sniff(filter="tcp", prn=analyze_packet, store=False)
