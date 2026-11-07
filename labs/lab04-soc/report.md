# Incident Report: SSH Brute Force & Account Compromise (SOC Detection)

| | |
|---|---|
| **Incident ID** | INC-2026-1106 |
| **Affected host** | `victim` (10.10.40.20) |
| **Source** | `10.10.40.5` (attacker) |
| **Analyst** | Mahmod Aldahol |
| **Date** | 2026-11-06 |
| **Severity** | High |
| **Status** | Detected, detections authored |

> Lab exercise. The monitored environment is a purpose-built mini-SIEM (log pipeline → detection engine → dashboard).

---

## 1. Executive summary
An external host brute-forced SSH on the monitored server, successfully compromised the `webadmin` account, and
escalated to root via `sudo`. The brute force was detected by an existing rule. During response, three additional
detections were authored so the **compromise** and **escalation** stages (not just the noisy brute force) are now
alerted on.

---

## 2. Timeline (UTC)
| Time | Stage | Evidence | ATT&CK |
|------|-------|----------|--------|
| T+0 | Brute force begins | ~14 `Failed password for webadmin from 10.10.40.5` in <60s | T1110 |
| T+~15s | **Compromise** | `Accepted password for webadmin from 10.10.40.5` | T1078 |
| T+~16s | Privilege escalation | `sudo: webadmin : ... COMMAND=/usr/bin/id` | T1548 |

## 3. Investigation
Performed from the SIEM (`soc` CLI, dashboard, raw `/logs/auth.log`):
```bash
soc alerts                       # existing SOC-001 "SSH Brute Force" alert, src=10.10.40.5
soc events --type failed_login   # ~14 failures from one IP in a tight window
soc events --type accepted_login # the successful login -> account = webadmin
```
- **Source IP:** `10.10.40.5`
- **Compromised account:** `webadmin`
- **Technique (initial):** T1110 Brute Force

## 4. Detections authored (detection-as-code)
The SIEM initially alerted only on the brute force (the noise). Three rules were added so the actual compromise is
caught. Rules are YAML, evaluated live by the engine.

| Rule | Detects | ATT&CK |
|------|---------|--------|
| MY-100 | Successful SSH login (`accepted_login`) | T1078 Valid Accounts |
| MY-101 | `sudo` privilege escalation | T1548 |
| MY-102 | ≥10 failed logins from one source in 60s (threshold) | T1110 |

Example (MY-102, threshold rule):
```yaml
id: MY-102
title: SSH brute-force detector
level: high
mitre: [T1110]
match:
  event_type: failed_login
threshold:
  count: 10
  by: source_ip
  window: 60
```
All three were verified by replaying the attack and confirming the alerts fired.

## 5. Findings & recommendations
| ID | Finding | Risk | Recommendation |
|----|---------|------|----------------|
| S1 | SSH password authentication enabled; weak password on `webadmin` | High | Key-only SSH, MFA, strong password policy (see Lab 02 hardening) |
| S2 | Compromise stage was not alerted before this incident | Medium | MY-100/101/102 now deployed; alert on success-after-failures |
| S3 | `webadmin` has broad `sudo` rights | Medium | Apply least privilege |

**Detection-engineering note:** a single successful login is normal, so MY-100 alone is noisy. The higher-fidelity
signal is **a success from an IP that just failed many times** (correlating MY-102 + MY-100). Recommended as a tuning
follow-up to cut false positives.

## 6. Lessons learned
- The brute force is loud; the **compromise** (valid-account login) is quiet and is what matters. Detections must
  cover the whole kill chain, not just the noisy first step.
- **False negative vs false positive:** missing the compromise (false negative) is far more dangerous than an extra
  brute-force alert. Rules were tuned with that priority in mind.
- Mapping each stage to ATT&CK exposes coverage gaps and gives the team a shared language.
