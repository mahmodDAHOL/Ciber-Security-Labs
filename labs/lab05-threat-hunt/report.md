# Incident Report: Web Server Compromise & Data Exfiltration

| | |
|---|---|
| **Incident ID** | INC-2026-1107 |
| **Affected host** | Northwind web server (10.0.0.10) |
| **Attacker** | `35.71.35.201` |
| **Analyst** | Mahmod Aldahol |
| **Date** | 2026-11-07 |
| **Severity** | Critical (confirmed data exfiltration) |
| **Status** | Reconstructed from logs |

> Lab exercise (threat hunt). Findings reconstructed from access.log, auth.log, and conn.log. Values are from this run.

---

## 1. Executive summary
Northwind's web server was compromised through a web application vulnerability. The attacker performed
reconnaissance, uploaded a **web shell**, read the application's database credentials, pivoted to **SSH** and created
a **rogue account** for persistence, then **exfiltrated ~50 MB** of data to an external host. This is a full
end-to-end breach with confirmed data loss. **Immediate containment is required** (see §5).

---

## 2. Timeline & kill chain (2026-11-07, UTC)
| Time | Tactic | Action | Evidence | ATT&CK |
|------|--------|--------|----------|--------|
| 08:00 | Reconnaissance | Directory brute force (dozens of 404s) from one IP | `access.log` — 54× 404 from `35.71.35.201`, UA `python-requests` | T1595 |
| 08:07 | Initial Access / Execution | Web shell uploaded | `POST /admin/upload.php 200` | T1190 |
| 08:08–08:11 | Execution | Commands run via web shell (`id`, `whoami`, `uname -a`) | `GET /uploads/thumb61.php?cmd=...` | T1505.003 |
| 08:11 | Impact / Collection | Read DB credentials | `cmd=cat /var/www/html/config.php` | T1552 |
| 08:20 | Lateral / Initial Access | SSH login after failures | `auth.log` — `Accepted password for deploy from 35.71.35.201` | T1078 |
| 08:21 | Persistence | Rogue account created, added to sudo | `useradd ... name=ops54`; `usermod ... group 'sudo'` | T1136 |
| 08:30 | Exfiltration | ~50 MB outbound to external host | `conn.log` — `10.0.0.10 -> 55.125.189.159:443, 50,094,908 bytes` | T1041 |

## 3. Indicators of Compromise (IOCs)
| Type | Value |
|------|-------|
| Attacker source IP | `35.71.35.201` |
| Web shell | `/uploads/thumb61.php` |
| Sensitive file accessed | `/var/www/html/config.php` |
| Persistence account | `ops54` |
| Exfiltration destination | `55.125.189.159` |
| Attacker user agent | `python-requests/2.31.0` |

## 4. How it was found (method)
```bash
# Attacker IP: rank sources by 404 count, confirm it also used the web shell
awk '$9==404 {print $1}' access.log | sort | uniq -c | sort -rn | head
grep -E 'cmd=|/uploads/.*\.php' access.log        # same IP running commands

# Commands executed through the shell (URL-decoded)
grep -oE 'cmd=[^ "]+' access.log | sed 's/%20/ /g' | sort -u

# Persistence
grep -E 'useradd|Accepted password' auth.log

# Exfiltration: the outlier transfer
tail -n +2 conn.log | sort -t, -k5 -nr | head
```

## 5. Containment & remediation
**Immediate:**
1. Isolate the web server from the network.
2. Delete the web shell `/uploads/thumb61.php` **and** disable/remove the rogue account `ops54`.
3. Rotate all credentials in `config.php` (database and any API keys) — assume compromised.
4. Block/monitor traffic to `55.125.189.159`; assess what the 50 MB contained (breach-notification trigger).

**Root cause / longer term:**
5. Fix the file-upload vulnerability (`/admin/upload.php`): validate file type, store uploads outside the web root,
   disable PHP execution in `/uploads/`.
6. Enforce key-only SSH + MFA; alert on new account creation and on sudo-group changes.
7. Add egress monitoring / DLP to detect large outbound transfers.

## 6. Lessons learned
- **Deleting the web shell is not remediation.** The attacker established independent persistence (SSH account); miss
  it and they still have access. Containment means finding *every* foothold.
- **Correlation beats single indicators.** Internet scanning noise is constant; what made `35.71.35.201` the attacker
  was recon *followed by* a successful action.
- **Exfiltration is a volume anomaly:** one connection moved 50 MB when normal traffic moved kilobytes. Baselining
  outbound data per host would have alerted in near-real-time.
