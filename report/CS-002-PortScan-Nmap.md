# CS-002: Network Port Scan Detetion

**Date:** 2026-04-10
**Analyst:** Arpan
**Severity:** Medium
**Status:** Detected
**MITRE ATT&CK:** T1046 — Network Service Discovery
**Tactic:** Discovery

## 1. Attack Summary

Nmap 7.95 executed SYN scan against 192.168.0.133 from 192.168.0.161. Scanned 1000 ports in 23 seconds. UFW blocked all probes. Wazuh detected via rules 100005 and 100004.

---

## 2. Environment

| Role     | Machine |      IP      |        OS         |
|----------|---------|--------------|-------------------|
| Attacker | Kali    |192.168.o.161 |Kali Linux         |
| Victim   | Ubuntu  |192.168.0.133 |Ubuntu 24.04.4 LTS |
| SIEM     | Wazuh   |192.168.0.224 |Wazuh v4.14.3	|

---

## 3. Attack Tool

**Tool:** Nmap 7.95
**Command:**
```bash
nmap -sS 192.168.0.133
```
**Scan Type:** SYN Stealth Scan (-sS)
**Ports Scanned:** 1000 (default)
**Duration:** 23.45 seconds
**Result:** All 1000 ports filtered — SSH (22/tcp) only open port

---

## 4. Attack Timeline

| Timestamp (UTC) | Event |
|-----------------|-------|
| 2026-04-10 02:56:00.080 | Nmap SYN scan initiated — first UFW BLOCK logged |
| 2026-04-10 02:56:00.580 | Rule 100004 triggered — port scan threshold reached |
| 2026-04-10 02:56:01.251 | 30 UFW BLOCK events recorded — scan still active |
| 2026-04-10 02:56:01.272 | Scan complete — 1000 ports probed in 23 seconds |

---

## 5. Detection Evidence

### UFW Log (Victim Machine — ubuntu-lab-01)

2026-04-09T21:13:46.839225+00:00 Ubuntu kernel: [UFW BLOCK] IN=enp0s3 OUT= MAC=08:00:27:14:ff:06:08:00:27:9f:a1:e5:08:00 SRC=192.168.0.161 DST=192.168.0.133 LEN=44 TOS=0x00 PREC=0x00 TTL=40 ID=51021 PROTO=TCP SPT=45518 DPT=3389 WINDOW=1024 RES=0x00 SYN URGP=0
2026-04-09T21:13:46.839227+00:00 Ubuntu kernel: [UFW BLOCK] IN=enp0s3 OUT= MAC=08:00:27:14:ff:06:08:00:27:9f:a1:e5:08:00 SRC=192.168.0.161 DST=192.168.0.133 LEN=44 TOS=0x00 PREC=0x00 TTL=56 ID=24979 PROTO=TCP SPT=45518 DPT=993 WINDOW=1024 RES=0x00 SYN URGP=0
2026-04-09T21:13:46.839228+00:00 Ubuntu kernel: [UFW BLOCK] IN=enp0s3 OUT= MAC=08:00:27:14:ff:06:08:00:27:9f:a1:e5:08:00 SRC=192.168.0.161 DST=192.168.0.133 LEN=44 TOS=0x00 PREC=0x00 TTL=41 ID=58567 PROTO=TCP SPT=45518 DPT=995 WINDOW=1024 RES=0x00 SYN URGP=0
2026-04-09T21:13:46.839229+00:00 Ubuntu kernel: [UFW BLOCK] IN=enp0s3 OUT= MAC=08:00:27:14:ff:06:08:00:27:9f:a1:e5:08:00 SRC=192.168.0.161 DST=192.168.0.133 LEN=44 TOS=0x00 PREC=0x00 TTL=57 ID=43783 PROTO=TCP SPT=45518 DPT=23 WINDOW=1024 RES=0x00 SYN URGP=0

### Wazuh Alert — Rule 100005 (Base Detection)

Rule ID:     100005
Level:       4
Description: UFW blocked incoming connection from
MITRE ID:    T1046
Tactic:      Discovery
Technique:   Network Service Discovery
Agent:       ubuntu-lab-01

### Wazuh Alert — Rule 100004 (Port Scan Correlated)

Rule ID:     100004
Level:       10
Description: Port Scan Detected: High volume of blocked connections
MITRE ID:    T1046
Tactic:      Discovery
Technique:   Network Service Discovery
Agent:       ubuntu-lab-01
Timestamp:   Apr 10, 2026 @ 02:56:00.580

---

## 6. Rules Triggered

| Rule ID | Description | Level | Type |
|---------|-------------|-------|------|
| 100005 | UFW Blocked Incoming Connection | 4 | Custom |
| 100004 | Port Scan Detected: High Volume of Blocked Connections | 10 | Custom |

---

## 7. Root Cause

The scan reached the target because:
- No network-level scan prevention or IDS deployed
- UFW enabled but default configuration does not alert on scans
- SSH (port 22) exposed on default port — visible to scanners
- No rate limiting on incoming connection attempts at network level

---

## 8. Analyst Notes

- Source port 45518 remained constant across all 1000 port probes —
  Nmap SYN scan fingerprint, normal clients use different source
  ports per connection
- 1000 ports scanned in 23 seconds — speed eliminates human
  interaction, confirms automated tooling
- All probes sent as SYN packets with no ACK — confirms stealth
  scan technique, designed to avoid application-layer logging
- UFW blocked every probe — attacker received no useful banner
  information, only port 22 confirmed open via earlier -sV scan
- 30 UFW BLOCK events generated in under 2 seconds at peak —
  consistent with Nmap's parallel probe technique

---

## 9. Recommendations

1. **Deploy an IDS/IPS** — tools like Snort or Suricata provide
   network-level scan detection independent of host firewall,
   catching scans before they reach the target
2. **Implement port knocking or single packet authorization** —
   hides SSH from scanners entirely, making port 22 invisible
   until authenticated knock sequence received
3. **Alert on UFW spike volume** — current rule fires at 20 blocks
   in 10 seconds; tune threshold down to 10 blocks in 5 seconds
   for faster detection of slower stealth scans
