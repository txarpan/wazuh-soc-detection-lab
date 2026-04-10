# CS-003: Privilege Escalation & Credential Access Detection

**Date:** 2026-04-10
**Analyst:** Arpan
**Severity:** High
**Status:** Detected
**MITRE ATT&CK:** T1548.003 — Sudo and Sudo Caching
**MITRE ATT&CK:** T1003.008 — /etc/passwd and /etc/shadow
**Tactic:** Privilege Escalation, Credential Access

---

## 1. Attack Summary

A local user (vboxuser) on ubuntu-lab-01 abused unrestricted sudo
privileges to escalate to root and access sensitive credential files.
Commands executed included `sudo whoami` (privilege confirmation),
`sudo cat /etc/passwd` (user enumeration), and `sudo cat /etc/shadow`
(password hash extraction). No external exploit was used — attack
relied entirely on misconfigured sudo permissions (living-off-the-land).
Wazuh detected all three actions via custom rules 100006, 100007, and
100008, mapped to MITRE T1548.003 and T1003.008.

---

## 2. Environment

|   Role   |        Machine     |   User   |      IP       |         OS         |
|----------|--------------------|----------|---------------|--------------------|
| Attacker | Ubuntu VM          | vboxuser | 192.168.0.133 | Ubuntu 24.04.4 LTS |
| Target   | Same Host          | root     | 192.168.0.133 | Ubuntu 24.04.4 LTS |
| SIEM     | Wazuh (Dockerized) |    —     | 192.168.0.224 | Wazuh v4.14.3      |

---

## 3. Attack Tool

**Tool:** Native Linux commands (no external tool required)
**Technique:** Sudo abuse + direct sensitive file access

**Commands Executed:**
```bash
sudo whoami          # Confirm root privilege
sudo cat /etc/passwd # Enumerate all system users
sudo cat /etc/shadow # Extract password hashes
```

---

## 4. Attack Timeline

| Timestamp (UTC) | Event |
|-----------------|-------|
| 2026-04-10T04:46:09 | `sudo cat /etc/shadow` executed — password hash extraction |
| 2026-04-10T04:46:09 | `sudo whoami` executed — root privilege confirmed |
| 2026-04-10T04:46:09 | `sudo cat /etc/passwd` executed — user enumeration |
| 2026-04-10T10:30:00 | Rules 100006, 100007, 100008 triggered in Wazuh |
| 2026-04-10T10:31:01 | All three alerts visible in Threat Hunting dashboard |

---

## 5. Detection Evidence

### Auth.log (Victim Machine — ubuntu-lab-01)

2026-04-10T04:46:09.476922+00:00 Ubuntu sudo: vboxuser : TTY=pts/1 ; PWD=/home/vboxuser ; USER=root ; COMMAND=/usr/bin/cat /etc/shadow
2026-04-10T04:46:09.489198+00:00 Ubuntu sudo: vboxuser : TTY=pts/1 ; PWD=/home/vboxuser ; USER=root ; COMMAND=/usr/bin/whoami
2026-04-10T04:46:09.500011+00:00 Ubuntu sudo: vboxuser : TTY=pts/1 ; PWD=/home/vboxuser ; USER=root ; COMMAND=/usr/bin/grep -a sudo /var/log/auth.log

### Wazuh Alert — Rule 100006 (Critical)

Rule ID:     100006
Level:       12
Description: CRITICAL: Sudo used to read /etc/shadow —
Possible credential harvesting by root
MITRE ID:    T1548.003, T1003.008
Tactic:      Privilege Escalation, Credential Access
Agent:       ubuntu-lab-01
Timestamp:   Apr 10, 2026 @ 10:30:01

### Wazuh Alert — Rule 100007

Rule ID:     100007
Level:       10
Description: Sudo used to confirm root privilege —
Possible post-exploitation activity by root
MITRE ID:    T1548.003
Tactic:      Privilege Escalation
Agent:       ubuntu-lab-01

### Wazuh Alert — Rule 100008
Rule ID:     100008
Level:       10
Description: Sudo used to read /etc/passwd —
Possible user enumeration by root
MITRE ID:    T1548.003
Tactic:      Privilege Escalation
Agent:       ubuntu-lab-01

---

## 6. Rules Triggered

| Rule ID | Description | Level | Type |
|---------|-------------|-------|------|
| 5402 | Successful sudo to ROOT executed | 3 | Default (Wazuh) |
| 100006 | CRITICAL: Sudo read /etc/shadow — Credential harvesting | 12 | Custom |
| 100007 | Sudo used to confirm root privilege | 10 | Custom |
| 100008 | Sudo used to read /etc/passwd — User enumeration | 10 | Custom |

---

## 7. Root Cause

The attack succeeded because:
- User `vboxuser` had unrestricted sudo access `(ALL:ALL) ALL`
- No command-level restrictions enforced in `/etc/sudoers`
- No OS-level alerting on sensitive file access before Wazuh rules
- Principle of least privilege not enforced on the system
- Password authentication enabled with no MFA for privileged operations

---

## 8. Analyst Notes

- `sudo whoami` as first command confirms intentional privilege
  validation before further actions — structured attacker behavior
- Immediate pivot to `/etc/shadow` indicates attacker awareness of
  Linux credential storage locations
- No external exploit used — purely abusing legitimate sudo privileges,
  a classic living-off-the-land (LOTL) technique
- All three commands executed within same second (04:46:09) —
  consistent with scripted or copy-paste execution, not manual typing
- Sequence (whoami → passwd → shadow) mirrors standard
  post-exploitation credential harvesting playbook
- Rule 100006 at level 12 triggered email alert flag (`mail: True`) —
  in production this would page the on-call analyst immediately

---

## 9. Recommendations

1. **Restrict sudo access** — remove `vboxuser` from unrestricted
   sudo and allow only specific required commands via `/etc/sudoers`
2. **Implement least privilege** — replace `(ALL:ALL) ALL` with
   explicit command allowlist per user
3. **Deploy auditd** — configure audit rules specifically monitoring
   read access to `/etc/shadow` and `/etc/passwd` for all users
4. **Enable AppArmor profiles** — restrict which processes can read
   sensitive credential files regardless of user privilege level
5. **Alert on sudo command content** — current Wazuh rules catch
   specific commands; expand to alert on any sudo access to `/etc/`
6. **Enforce MFA for privileged operations** — require second factor
   before any sudo command executes

