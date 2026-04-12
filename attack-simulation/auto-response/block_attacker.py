#!/usr/bin/env python3
"""
Wazuh Auto-Response Script
Monitors Rule 100003 alerts and automatically blocks
attacker IPs via UFW when post-brute-force compromise detected.

MITRE ATT&CK: T1110.001, T1078
Author: Arpan
Date: 2026-04-12
"""

import json
import subprocess
import requests
import urllib3
from datetime import datetime

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Configuration
WAZUH_API    = "https://localhost:55000"
WAZUH_USER   = "wazuh"
WAZUH_PASS   = "wazuh"
TARGET_RULE  = "100003"
LOG_FILE     = "/tmp/auto-response.log"
WHITELIST    = ["192.168.0.224", "127.0.0.1"]

def log(message):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    entry = f"[{timestamp}] {message}"
    print(entry)
    with open(LOG_FILE, "a") as f:
        f.write(entry + "\n")

def get_token():
    response = requests.post(
        f"{WAZUH_API}/security/user/authenticate",
        auth=(WAZUH_USER, WAZUH_PASS),
        verify=False
    )
    data = response.json()
    return data["data"]["token"]

def get_alerts(token):
    headers = {"Authorization": f"Bearer {token}"}
    params  = {"rule.id": TARGET_RULE, "limit": 10}
    response = requests.get(
        f"{WAZUH_API}/alerts",
        headers=headers,
        params=params,
        verify=False
    )
    return response.json().get("data", {}).get("affected_items", [])

def block_ip(ip):
    if ip in WHITELIST:
        log(f"SKIPPED: {ip} is whitelisted — not blocking")
        return

    try:
        result = subprocess.run(
            ["sudo", "ufw", "deny", "from", ip],
            capture_output=True,
            text=True
        )
        if result.returncode == 0:
            log(f"BLOCKED: {ip} added to UFW deny list")
        else:
            log(f"ERROR blocking {ip}: {result.stderr}")
    except Exception as e:
        log(f"EXCEPTION blocking {ip}: {str(e)}")

def main():
    log("=" * 50)
    log("Wazuh Auto-Response Script Started")
    log(f"Monitoring Rule {TARGET_RULE} — Post-Brute-Force Compromise")
    log(f"Whitelist: {WHITELIST}")
    log("=" * 50)

    blocked_ips = set()

    try:
        token = get_token()
        log("Successfully authenticated to Wazuh API")

        alerts = get_alerts(token)
        log(f"Found {len(alerts)} Rule {TARGET_RULE} alerts")

        for alert in alerts:
            src_ip = alert.get("data", {}).get("srcip")

            if not src_ip:
                log("Alert has no srcip field — skipping")
                continue

            if src_ip in blocked_ips:
                log(f"DUPLICATE: {src_ip} already processed")
                continue

            log(f"ALERT: Post-brute-force compromise from {src_ip}")
            block_ip(src_ip)
            blocked_ips.add(src_ip)

        if not blocked_ips:
            log("No new attacker IPs found to block")

    except Exception as e:
        log(f"FATAL ERROR: {str(e)}")

    log("=" * 50)
    log(f"Auto-response complete. Blocked: {blocked_ips}")
    log("=" * 50)

if __name__ == "__main__":
    main()
