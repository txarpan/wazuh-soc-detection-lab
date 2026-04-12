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
- Wazuh API access
- UFW installed on host
