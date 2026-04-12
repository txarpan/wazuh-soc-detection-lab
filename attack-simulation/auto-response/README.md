# Auto-Response Script — block_attacker.py

## Purpose
Automatically blocks attacker IPs via UFW when Wazuh Rule 100003
(Post-Brute-Force Account Compromise) fires.

## How It Works
1. Authenticates to Wazuh API
2. Queries alerts for Rule 100003
3. Extracts source IP from each alert
4. Runs `ufw deny from <ip>` to block attacker
5. Logs all actions to `/tmp/auto-response.log`
6. Skips whitelisted IPs (admin machines)

## Proof of Execution

Script successfully authenticated to Wazuh API and queried
Rule 100003 alerts during lab testing:
[2026-04-12 10:37:01] Wazuh Auto-Response Script Started
[2026-04-12 10:37:01] Monitoring Rule 100003 — Post-Brute-Force Compromise
[2026-04-12 10:37:01] Whitelist: ['192.168.0.224', '127.0.0.1']
[2026-04-12 10:37:01] Successfully authenticated to Wazuh API
[2026-04-12 10:37:01] Found 0 Rule 100003 alerts
[2026-04-12 10:37:01] No new attacker IPs found to block
[2026-04-12 10:37:01] Auto-response complete. Blocked: set()

## Resource Constraint Note

Full end-to-end blocking demo (Hydra attack → Rule 100003 →
auto-block) requires simultaneous operation of:
- Kali Linux VM (attacker)
- Ubuntu VM (victim + Wazuh agent)
- Fedora host (Wazuh SIEM)

Lab environment supports maximum 2 VMs simultaneously due to
RAM constraints (16GB). Script logic is complete and verified
to authenticate and query Wazuh API correctly. Live blocking
demo deferred to production environment testing.

## Usage
```bash
pip install requests
python3 block_attacker.py
```

## MITRE ATT&CK
- T1110.001 — Brute Force: Password Guessing
- T1078 — Valid Accounts

## Requirements
- Python 3.x
- requests library
- Wazuh API access (wazuh-wui credentials)
- UFW installed on host
