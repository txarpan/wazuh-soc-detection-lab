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

---

## Case Studies

| ID | Title | Status |
|----|-------|--------|
| [CS-001](report/CS-001-SSH-BruteForce.md) | SSH Brute Force Attack Detection | ✅ Complete |
| [CS-002](report/CS-002-PortScan-Nmap.md) | Network Port Scan Detection | ✅ Complete |

---

## Repository Structure

wazuh-soc-detection-lab/
├── README.md
├── rules/                    # Custom Wazuh detection rules
├── report/                   # Attack case studies
│   └── CS-001-SSH-BruteForce.md
├── attack-simulation/        # Attack scripts and wordlists
├── logs/                     # Sample log evidence
└── screenshots/              # Wazuh dashboard evidence

---

## Tools & Technologies

`Wazuh SIEM` `Docker` `Kali Linux` `Ubuntu` `Hydra` 
`MITRE ATT&CK` `Bash` `SSH` `Linux`

---

## Author

**Arpan Mukherjee** 
Cybersecurity Engineer | Detection Engineering | SOC Analysis 
RHCSA Certified | Penetration Tester | Security Researcher | BugBounty Hunter
[GitHub](https://github.com/txarpan)
