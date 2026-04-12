# Detection Engineering & SOC Lab — Wazuh SIEM (Dockerized)

A hands-on Detection Engineering and SOC Analysis lab built to 
simulate real-world attack scenarios, develop custom detection rules, 
and practice alert triage — all mapped to the MITRE ATT&CK framework.

---

## Lab Architecture

| Component | Details |
|-----------|---------|
| SIEM | Wazuh 4.14.3 (Dockerized, single-node) |
| Attacker | Kali Linux 2023 — 192.168.0.161 |
| Victim (Linux) | Ubuntu 24.04.4 LTS — 192.168.0.133 |
| Victim (Windows) | Windows 10 Home — 192.168.0.144 |
| Host | Fedora Linux — 192.168.0.224 |
| Tools | Hydra, Nmap, Wazuh Agent |

---

## What This Lab Demonstrates

- Deploying a production-style SIEM using Docker
- Writing custom Wazuh detection rules from scratch
- Simulating attacks mapped to MITRE ATT&CK techniques
- Triaging and investigating alerts as a SOC analyst
- Documenting findings in professional case study format

---

## Attack Scenarios Completed

| # | Attack | MITRE Technique | Detection Rule | Severity |
|---|--------|----------------|----------------|----------|
| 1 | SSH Brute Force (Hydra) | T1110.001 — Password Guessing | Custom Rule 100002 | High |
| 2 | Post-Brute-Force Activity | T1078 — Valid Accounts | Custom Rule 100003 | Critical |
| 3 | Nmap SYN Port Scan | T1046 — Network Service Discovery | Custom Rules 100004/100005 | Medium |
| 4 | Privilege Escalation via Sudo | T1548.003 — Sudo Abuse | Custom Rules 100006/100007/100008 | High |
| 5 | Credential Access — /etc/shadow | T1003.008 — /etc/passwd and /etc/shadow | Custom Rule 100006 | Critical |
| 6 | Windows Brute Force (runas) | T1110.001 — Password Guessing | Custom Rule 100009 | High |

---

## Custom Detection Rules

Located in `/rules/`

| Rule ID | Description | Trigger | MITRE |
|---------|-------------|---------|-------|
| 100001 | SSH Brute Force — Invalid Users | 4+ failures/60s on rule 5710 | T1110.001 |
| 100002 | SSH Brute Force — Valid Users | 4+ failures/60s on rule 5760 | T1110.001 |
| 100003 | Post-Brute-Force Account Compromise | Login after brute force from same IP | T1078 |
| 100005 | UFW Blocked Connection | UFW BLOCK kernel log match | T1046 |
| 100004 | Port Scan Detected | 20+ UFW blocks in 10 seconds | T1046 |
| 100006 | Sudo read /etc/shadow — Credential Harvesting | sudo cat /etc/shadow detected | T1548.003, T1003.008 |
| 100007 | Sudo privilege confirmation | sudo whoami detected | T1548.003 |
| 100008 | Sudo read /etc/passwd — User Enumeration | sudo cat /etc/passwd detected | T1548.003 |
| 100009 | Windows Brute Force Detection | 5+ failed logons/60s on rule 60122 | T1110.001 |
| 100010 | Windows Post-Brute-Force Compromise | Login after brute force | T1078 |

---

## Case Studies

| ID | Title | Status |
|----|-------|--------|
| [CS-001](report/CS-001-SSH-BruteForce.md) | SSH Brute Force Attack Detection | ✅ Complete |
| [CS-002](report/CS-002-PortScan-Nmap.md) | Network Port Scan Detection | ✅ Complete |
| [CS-003](report/CS-003-PrivilegeEscalation.md) | Privilege Escalation & Credential Access | ✅ Complete |
| [CS-004](report/CS-004-Windows-BruteForce.md) | Windows Brute Force Detection | ✅ Complete |

---

## Repository Structure

```
wazuh-soc-detection-lab/
├── README.md
├── rules/
│   └── local_rules.xml                    # 10 custom detection rules, MITRE mapped
├── report/
│   ├── CS-001-SSH-BruteForce.md           # Hydra SSH brute force detection
│   ├── CS-002-PortScan-Nmap.md            # Nmap SYN port scan detection
│   ├── CS-003-PrivilegeEscalation.md      # Sudo abuse & credential access
│   ├── CS-004-Windows-BruteForce.md       # Windows failed logon detection
│   └── FP-Tuning-Report.md               # False positive analysis & tuning
├── attack-simulation/
│   └── auto-response/
│       ├── block_attacker.py              # SOAR auto-response script
│       └── README.md                     # Script documentation & proof
├── logs/                                  # Sample log evidence
└── screenshots/                           # Wazuh dashboard evidence
```

---

## Tools & Technologies

`Wazuh SIEM` `Docker` `Kali Linux` `Ubuntu` `Windows 10`
`Hydra` `Nmap` `Python` `MITRE ATT&CK` `Bash` `PowerShell`
`UFW` `SSH` `Linux` `VirtualBox`

---

## SOAR Automation

Basic auto-response script (`attack-simulation/auto-response/block_attacker.py`)
monitors Wazuh API for Rule 100003 alerts and automatically blocks
attacker IPs via UFW. Successfully authenticated to Wazuh API during
lab testing. See script README for execution proof and usage.

## Author

**Arpan Mukherjee** 
Cybersecurity Engineer | Detection Engineering | SOC Analyst |
RHCSA Certified | Penetration Tester | Security Researcher | BugBounty Hunter
[GitHub](https://github.com/txarpan)
