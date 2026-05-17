# Behavioural Baselining – Privilege Escalation Activity (Microsoft Sentinel)

## Objective

This lab introduces behavioural baselining concepts using Microsoft Sentinel and Syslog telemetry.

The focus is on understanding how privilege escalation activity behaves over time rather than simply detecting individual events.

---

## Background

Previous detection evaluations showed that timing-based detections could fail when attacker behaviour became delayed or stealthy.

This exercise begins exploring behavioural analysis and baselining approaches.

---

## Initial Query Attempt

```kql
Syslog
| where TimeGenerated > ago(7d)
| where SyslogMessage has "sudo"
| extend Account = extract(@"sudo:\s+(\w+)", 1, SyslogMessage)
| where isnotempty(Account)
| summarize SudoCount = count() by Account
| order by SudoCount desc
```

---

## Problem Identified

No results were returned.

Investigation revealed that the Syslog format in the environment did not match the extraction logic assumptions.

Observed log format:

```text
pam_unix(sudo:session): session closed for user root
```

---

## Updated Query

```kql
Syslog
| where TimeGenerated > ago(7d)
| where SyslogMessage has "sudo"
    or SyslogMessage has "session opened for user root"
| summarize PrivEscalationCount = count() by Computer
| order by PrivEscalationCount desc
```

---

## Results

| Computer | PrivEscalationCount |
|------|------|
| soc-lab-vm-01 | 2 |

---

## Key Insight

> Detection engineering requires validating telemetry formats before implementing parsing and correlation logic.

---

## Conclusion

This exercise demonstrated the importance of:
- validating raw telemetry
- adapting detection logic to environment-specific log formats
- beginning behavioural baselining methodologies

Future work will focus on:
- account-level baselining
- anomaly detection
- behavioural deviation analysis
