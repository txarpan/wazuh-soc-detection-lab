# False Positive Tuning Report

**Date:** 2026-04-12
**Analyst:** Arpan
**Lab:** Wazuh SOC Detection Lab (Dockerized)
**Scope:** Custom rules 100001–100009 and default Wazuh rules

---

## Overview

During lab operation across multiple attack simulation sessions,
several detection rules generated alerts on legitimate activity.
This document identifies observed false positive patterns, explains
tuning decisions made, and documents whitelist logic applied to
reduce noise without compromising detection coverage.

Note: Alert volumes are based on lab observation periods, not
production baselines. In a real SOC environment, a minimum 48-hour
baseline measurement period would precede any tuning decisions.

---

## False Positive Analysis

### Rule 100003 — Post-Brute-Force Account Compromise

**Rule Logic:**
```xml
<rule id="100003" level="14" timeframe="300">
    <if_matched_sid>100002</if_matched_sid>
    <same_source_ip />
    <description>CRITICAL: Successful login after Brute Force</description>
</rule>
```

**Observed Issue:**
Rule fires when ANY successful login follows brute force detection
from same IP — including legitimate users who mistype password
multiple times then authenticate correctly.

**False Positive Scenario:**
09:25:01 — Admin mistyped SSH password (rule 5760 fired x4)
09:25:03 — Rule 100002 triggered — brute force declared
09:25:10 — Admin logged in successfully (same IP)
→ Rule 100003 fired CRITICAL — FALSE POSITIVE

**Root Cause:**
No distinction between automated tooling (Hydra) and human
mistyping. Frequency threshold of 4 is too low for environments
where users occasionally mistype credentials.

**Tuning Decision:**
- Raise frequency threshold from 4 to 8 failures within 60 seconds
- Require failures within tighter 30-second window
- Whitelist known administrative source IPs

**Recommended Rule Update:**
```xml
<rule id="100003" level="14" timeframe="300">
    <if_matched_sid>100002</if_matched_sid>
    <same_source_ip />
    <white_list>192.168.0.224</white_list>
    <description>CRITICAL: Successful login after Brute Force
    from $(srcip) - Possible Account Compromise</description>
</rule>
```

**Impact:** Eliminates FP from legitimate admin logins while
maintaining detection of automated brute force tools.

---

### Rule 100004 — Port Scan Detected

**Rule Logic:**
```xml
<rule id="100004" level="10" frequency="20" timeframe="10">
    <if_matched_sid>100005</if_matched_sid>
    <description>Port Scan Detected: High volume of blocked
    connections</description>
</rule>
```

**Observed Issue:**
Internal network monitoring tools, vulnerability scanners run
by security team, and legitimate IT asset discovery tools would
trigger this rule — identical traffic pattern to Nmap scans.

**False Positive Scenario:**
Security team runs weekly Nmap asset inventory scan
→ 20+ UFW blocks in 10 seconds from known internal IP
→ Rule 100004 fires — FALSE POSITIVE

**Root Cause:**
Rule has no awareness of trusted source IPs. Any host generating
20+ blocked connections in 10 seconds triggers the alert regardless
of whether it is a known scanner or external attacker.

**Tuning Decision:**
- Whitelist known security team and monitoring IPs
- Raise threshold to 50 blocks in 10 seconds for internal ranges
- Document all authorized scanning IPs in whitelist registry

**Recommended Rule Update:**
```xml
<rule id="100004" level="10" frequency="50" timeframe="10">
    <if_matched_sid>100005</if_matched_sid>
    <white_list>192.168.0.224</white_list>
    <description>Port Scan Detected: High volume of blocked
    connections from $(srcip)</description>
</rule>
```

**Impact:** Reduces authorized internal scan alerts while
maintaining detection of external reconnaissance activity.

---

### Rule 100005 — UFW Blocked Connection

**Rule Logic:**
```xml
<rule id="100005" level="4">
    <program_name>kernel</program_name>
    <match>UFW BLOCK</match>
    <description>UFW blocked incoming connection</description>
</rule>
```

**Observed Issue:**
Fires on every single blocked connection including routine
internet background noise — random scanners, misconfigured
devices, broadcast traffic. Not actionable individually.

**Observation:**
During a 15-minute lab session, Rule 100005 generated 30+
alerts from a single Nmap scan. In a production environment
exposed to the internet, this would generate thousands of
alerts per hour from background noise alone.

**Tuning Decision:**
- Rule 100005 kept at level 4 — informational only
- Not promoted to email alerting (mail: False)
- Only Rule 100004 correlated pattern treated as actionable
- Individual UFW blocks reviewed only during active investigation,
  not as standalone alerts

**Impact:** Eliminates noise from background internet traffic
while preserving the audit trail for forensic investigation.

---

### Rules 60642 / 61104 — Windows System Noise

**Observed Issue:**
Default Wazuh Windows rules fire constantly on normal OS
operations — software protection service scheduling, service
configuration changes triggered by Windows Update and system
maintenance.

**Observed Events:**
Rule 60642 — Software protection service scheduled — Level 3
Rule 61104 — Service startup type was changed — Level 3

Both fire multiple times per hour on a standard Windows 10
system with no attacker activity.

**Tuning Decision:**
- Both rules kept at level 3 — below actionable threshold
- Not promoted to custom rules
- Filtered from Threat Hunting view using `rule.level > 5` filter
- Treated as baseline Windows operational noise

**Impact:** Removes persistent low-level noise from analyst
view while preserving complete audit log for compliance purposes.

---

### Rules 100006/100007/100008 — Sudo Command Detection

**Observed Issue:**
Rules fire on legitimate administrative activity — system
administrators routinely use sudo for maintenance tasks.
Rule 100006 (level 12) fires on any `sudo cat /etc/shadow`
regardless of whether it is an authorized admin or attacker.

**False Positive Scenario:**
Admin runs sudo cat /etc/shadow during routine account audit
→ Rule 100006 fires CRITICAL level 12 — FALSE POSITIVE

**Tuning Decision:**
- Whitelist known admin accounts from sudo rules
- Add time-based suppression for scheduled maintenance windows
- Require correlation with prior suspicious activity before
  escalating to Critical severity

**Impact:** Reduces admin workflow interruption while maintaining
detection of unexpected credential access by non-admin users.

---

## Tuning Summary

| Rule | Issue Observed | Action Taken | Result |
|------|---------------|--------------|--------|
| 100003 | FP on legitimate login after mistype | Raise threshold, whitelist admin IP | Reduced noise |
| 100004 | FP on authorized internal scans | Raise threshold, whitelist scanner IP | Reduced noise |
| 100005 | High volume background noise | Keep informational, suppress email | Eliminated noise |
| 60642/61104 | Windows OS operational noise | Keep level 3, filter from view | Eliminated noise |
| 100006-100008 | FP on legitimate admin sudo | Whitelist admin accounts | Reduced noise |

---

## Key Takeaways

- Detection without tuning creates alert fatigue — analysts
  begin ignoring alerts including real threats
- Whitelisting known-good IPs and accounts is the fastest
  noise reduction technique available
- Correlation rules must have higher frequency thresholds
  than single-event rules to avoid false positive cascade
- Level thresholds are the primary noise filter in Wazuh —
  treat anything below level 7 as informational background
- In production, establish 48-hour baseline before tuning —
  never tune based on assumptions alone
- Document every tuning decision with justification —
  tuning without documentation creates blind spots

---

## Production Recommendations

1. Run 48-hour baseline with zero tuning to establish true
   FP rate before making any threshold adjustments
2. Implement scheduled maintenance windows with automatic
   alert suppression for known administrative activity
3. Build IP whitelist registry — document every whitelisted
   IP with owner, purpose, and review date
4. Review all tuning decisions quarterly — network changes
   make yesterday's whitelist tomorrow's blind spot
5. Never suppress alerts permanently — use time-limited
   suppressions with mandatory review dates


