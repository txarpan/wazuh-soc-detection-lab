# CS-004: Windows Failed Logon Brute Force Detection

**Date:** 2026-04-12
**Analyst:** Arpan
**Severity:** High
**Status:** Detected
**MITRE ATT&CK:** T1110.001 — Brute Force: Password Guessing
**Tactic:** Credential Access

---

## 1. Attack Summary

A local user (vboxuser) on a Windows 10 VM performed repeated failed
logon attempts using the native `runas` command targeting non-existent
account `fakeuser`. Each attempt generated Windows Security Event ID
4625. Wazuh detected individual failures via default rule 60122 and
correlated the pattern into a brute force alert via custom rule 100009
(5+ failures within 60 seconds), mapped to MITRE ATT&CK T1110.001
(Brute Force: Password Guessing).

---

## 2. Environment

| Role | Machine | User | IP | OS |
|------|---------|------|-----|-----|
| Attacker | Windows VM | vboxuser | 192.168.0.144 | Windows 10 Home |
| Target | Local System | fakeuser | 192.168.0.144 | Windows 10 Home |
| SIEM | Wazuh (Dockerized) | — | 192.168.0.224 | Wazuh v4.14.3 |

---

## 3. Attack Tool

**Tool:** Native Windows command — no external tool required
**Command:**
```cmd
runas /user:fakeuser cmd
```
**Technique:** Manual password guessing via Windows runas command
**Target Account:** fakeuser (non-existent account)
**Logon Type:** 2 (Interactive)

---

## 4. Attack Timeline

| Timestamp (UTC) | Event |
|-----------------|-------|
| 2026-04-12 09:24:56 | First failed logon attempt — Event ID 4625 generated |
| 2026-04-12 09:25:01 | Second failed attempt — fakeuser targeted |
| 2026-04-12 09:25:08 | Third consecutive failure recorded |
| 2026-04-12 09:25:11 | Fourth failure — pattern accumulating |
| 2026-04-12 09:30:44 | Rule 60122 firing repeatedly in Wazuh |
| 2026-04-12 09:31:00 | Rule 100009 triggered — brute force threshold reached |

---

## 5. Detection Evidence

### Windows Security Log (Event ID 4625)

Log Name:    Security
Source:      Microsoft-Windows-Security-Auditing
Date:        2026-04-12T09:25:01.105Z
Event ID:    4625
Keyword:     Audit Failure
Account For Which Logon Failed:
Account Name:   fakeuser
Account Domain: WINDOWS
Failure Information:
Failure Reason: Unknown user name or bad password
Status:         0xC000006D
Sub Status:     0xC0000064
Process Information:
Caller Process: C:\Windows\System32\svchost.exe
Logon Type: 2 (Interactive)

### Wazuh Alert — Rule 60122 (Default)
Rule ID:     60122
Level:       5
Description: Logon Failure - Unknown user or bad password
Agent:       Windows
Event ID:    4625

### Wazuh Alert — Rule 100009 (Custom)
Rule ID:     100009
Level:       10
Description: Windows Brute Force Detected:
Multiple failed logons for fakeuser
MITRE ID:    T1110.001
Tactic:      Credential Access
Technique:   Password Guessing
Agent:       Windows
Timestamp:   Apr 12, 2026 @ 09:31:00


---

## 6. Rules Triggered

| Rule ID | Description | Level | Type |
|---------|-------------|-------|------|
| 60122 | Windows Logon Failure — Event ID 4625 | 5 | Default (Wazuh) |
| 100009 | Windows Brute Force Detected | 10 | Custom |

---

## 7. Root Cause

The attack was possible because:
- No account lockout policy enforced on the Windows system
- No restriction on repeated `runas` authentication attempts
- Local system permitted unlimited failed logon attempts
- No OS-level alerting threshold — only SIEM correlation detected pattern

---

## 8. Analyst Notes

- Target account `fakeuser` does not exist on the system —
  SubStatus `0xC0000064` specifically indicates invalid username,
  distinguishing this from a valid account with wrong password
- Use of `runas` confirms manual attack, not automated tooling —
  lower speed, spaced attempts over several minutes
- SubStatus `0xC000006D` = general authentication failure;
  `0xC0000064` = username does not exist — critical field for
  triage and attacker intent analysis
- Attack persisted for approximately 6 minutes indicating
  deliberate repeated attempts despite consistent failures
- Rule 100009 correctly correlated 5+ individual 60122 events
  into single actionable high-severity alert — reducing analyst
  workload vs reviewing individual failure events

---

## 9. Recommendations

1. **Enforce account lockout policy** — configure Group Policy to
   lock accounts after 5 failed attempts within 30 minutes,
   making brute force computationally expensive
2. **Restrict runas usage** — audit and limit which users can
   execute `runas` for non-administrative purposes via AppLocker
3. **Monitor Event ID 4625 volume** — alert on 10+ failures
   per user within 5 minutes at OS level via Windows Defender
4. **Deploy Windows Defender Credential Guard** — protects
   credential material from extraction even after account compromise
5. **Enable audit policy** — ensure Security audit logging is
   enabled for all logon/logoff events via Group Policy

