# CS-001: SSH Brute Force Attack Detection

**Date:** 2026-04-09  
**Analyst:** Arpan  
**Severity:** High  
**Status:** Detected  
**MITRE ATT&CK:** T1110.001 - Brute Force: Password Guessing  
**Tactic:** Credential Access  

---

## 1. Attack Summary

Hydra v9.6 executed 20 SSH authentication attempts against
root@192.168.0.133 (ubuntu-lab-01) from 192.168.0.161 (Kali Linux)
over approximately 18 seconds using 8 parallel threads. All 20
attempts failed to authenticate. The attack triggered custom Wazuh
detection rules 100002 and 100003, generating High (level 10) and
Critical (level 14) severity alerts mapped to MITRE ATT&CK T1110.001
(Brute Force: Password Guessing) and T1078 (Valid Accounts).

---

## 2. Environment

| Role | Machine | IP | OS |
|------|---------|----|----|
| Attacker | Kali Linux | 192.168.0.161 | Kali Linux 2023 |
| Victim | ubuntu-lab-01 | 192.168.0.133 | Ubuntu 24.04.4 LTS |
| SIEM | Wazuh (Dockerized) | 192.168.0.224 | Wazuh v4.14.3 |

---

## 3. Attack Tool

**Tool:** Hydra v9.6  
**Command:**
```bash
hydra -l root -P /tmp/passwords2.txt ssh://192.168.0.133 -t 8 -V
```
**Wordlist:** 20 common passwords  
**Threads:** 8 parallel connections  
**Target account:** root  
**Duration:** 2026-04-09 15:53:24 → 15:53:42 (18 seconds)  

---

## 4. Attack Timeline

| Timestamp (UTC) | Event |
|-----------------|-------|
| 2026-04-09T19:53:37 | First SSH connection attempt from 192.168.0.161 |
| 2026-04-09T19:53:39 | Multiple parallel sessions — ports 59486, 59506, 59524, 59544 |
| 2026-04-09T19:53:39 | Failed password confirmed for root from 192.168.0.161 |
| 2026-04-10T01:23:37 | Rule 100003 triggered — CRITICAL alert generated |
| 2026-04-10T01:23:39 | Rule 100003 fired repeatedly — sustained activity detected |
| 2026-04-10T01:23:41 | Final Rule 100003 alert — 192.168.0.161 flagged |

---

## 5. Detection Evidence

### Auth.log (Victim Machine — ubuntu-lab-01)

2026-04-09T19:53:39.529120+00:00 Ubuntu sshd[6936]: Failed password for root from 192.168.0.161 port 59486 ssh2
2026-04-09T19:53:39.549820+00:00 Ubuntu sshd[6941]: Failed password for root from 192.168.0.161 port 59524 ssh2
2026-04-09T19:53:39.551077+00:00 Ubuntu sshd[6943]: Failed password for root from 192.168.0.161 port 59544 ssh2
2026-04-09T19:53:39.561471+00:00 Ubuntu sshd[6939]: Failed password for root from 192.168.0.161 port 59506 ssh2

### Wazuh Alert — Rule 100003 (Critical)

Rule ID:     100003
Level:       14
Description: CRITICAL: Successful login after Brute Force
from 192.168.0.161 - Possible Account Compromise
MITRE ID:    T1078
Tactic:      Defense Evasion, Persistence
Agent:       ubuntu-lab-01
Timestamp:   Apr 10, 2026 @ 01:23:37

---

## 6. Rules Triggered

| Rule ID | Description | Level | Type |
|---------|-------------|-------|------|
| 5760 | sshd: authentication failed | 5 | Default (Wazuh) |
| 2502 | syslog: User missed password more than once | 10 | Default (Wazuh) |
| 100002 | SSH Brute Force Against Valid User | 10 | Custom |
| 100003 | CRITICAL: Post-Brute-Force Activity Detected | 14 | Custom |

---

## 7. Root Cause

The attack reached the target because:
- SSH exposed on default port 22 with no rate limiting
- Root login over SSH permitted (PermitRootLogin not disabled)
- No account lockout policy configured on victim system
- No IP-based blocking or fail2ban deployed
- Password authentication enabled with weak password candidates

---

## 8. Analyst Notes

- Attacker IP 192.168.0.161 opened 4 parallel SSH sessions
  simultaneously (ports 59486, 59506, 59524, 59544) — confirms
  automated tooling, not manual attempts
- All 20 attempts exclusively targeted root — highest privilege
  account — indicating deliberate high-value target selection
- Full attack completed in 18 seconds — eliminates any possibility
  of human interaction
- Rule 100003 (level 14) fired multiple times indicating Wazuh
  correlated brute force pattern with subsequent activity
  from same source IP
- 4 simultaneous ports is consistent with Hydra's -t 8 thread flag

---

## 9. Recommendations

1. **Disable root SSH login** — set `PermitRootLogin no` in
   `/etc/ssh/sshd_config` — eliminates highest-value target
   from remote access entirely
2. **Deploy fail2ban** — block source IPs automatically after
   3 failed attempts within 60 seconds — makes brute force
   computationally expensive
3. **Enforce SSH key-based authentication** — set
   `PasswordAuthentication no` in sshd_config — renders
   password brute force impossible regardless of tool used
4. **Relocate SSH to non-standard port** — reduces automated
   scanner noise and eliminates opportunistic attacks
