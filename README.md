# Python IDS with Splunk Cloud Integration

A real-time Intrusion Detection System built in Python that captures live network 
traffic, detects malicious patterns, and ships structured alerts to Splunk Cloud 
for SOC-style monitoring and visualization.

## Features
- Live packet capture using Scapy
- Detects port scans, brute force SSH attempts, and SYN packets
- Sends structured alerts to Splunk Cloud via HTTP Event Collector (HEC)
- Real-time Splunk dashboard with alert classification and top attacker IPs

## Tech Stack
- Python 3, Scapy, Requests
- Splunk Cloud (HEC ingestion)
- SPL (Splunk Search Processing Language) for dashboards

## Detection Rules
| Alert Type | Trigger |
|---|---|
| PORT_SCAN | 10+ unique ports hit within 10 seconds |
| BRUTE_FORCE_SSH | 5+ attempts on port 22 within 10 seconds |
| SYN_PACKET | Any TCP SYN packet detected |

## Setup
1. Clone the repo
2. Create a virtual environment and install dependencies
3. Add your Splunk HEC URL and token to a .env file
4. Run with sudo python3 ids.py

## Sample Alert (Splunk Event)
```json
{
  "alert_type": "PORT_SCAN",
  "src_ip": "192.168.1.10",
  "dst_ip": "10.0.0.1",
  "ports_scanned": 10,
  "severity": "HIGH"
}

