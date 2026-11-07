# Lab 05: Threat Hunt — Reconstruct a Web Intrusion from Logs

**Roadmap:** Phase 2 (log investigation, incident response & triage) · **Time:** 3–5 hours · **Points:** 12

## Scenario
Northwind's online shop may be breached: the product database leaked. You're handed a day of logs from the
web server (`10.0.0.10`) and asked to find out exactly what happened. No live attack to watch this time — just
evidence to work through, the way most real investigations actually go. Your job is to **reconstruct the full
attack chain** and produce the facts an incident report needs.

Every run of this lab randomizes the attacker's IP, the web shell name, the account they created, and the
exfil destination, so you can't guess. You have to hunt.

> The evidence is generated; don't read `evidence/gen.py` — that's the answer key. Work only from the logs in `/cases`.

## The evidence
Shell into the analyst box; the logs are mounted read-only at `/cases`:
```powershell
docker exec -it lab05-analyst bash
cat /cases/CASE.txt
ls -l /cases
```
| File | What it is |
|------|------------|
| `access.log` | Web server access log, Apache combined format |
| `auth.log` | Linux authentication log from the web server |
| `conn.log` | Outbound network connections, CSV: `timestamp,src_ip,dst_ip,dst_port,bytes_out` |

You have `rg` (ripgrep), `grep`, `awk`, `jq`, `sort`, `uniq`, `less`.

## Read first (about 1.5 h)
1. Apache/Nginx access log format: https://www.sumologic.com/blog/apache-access-log/
2. Threat hunting basics (hypothesis → evidence): https://www.crowdstrike.com/cybersecurity-101/threat-hunting/
3. Web shells explained: https://www.microsoft.com/en-us/security/blog/2021/02/11/web-shell-attacks-continue-to-rise/
4. The ATT&CK tactics in order (recon → initial access → execution → persistence → exfiltration): https://attack.mitre.org/tactics/enterprise/
5. Getting started with `awk` (short beginner blog): https://opensource.com/article/19/10/intro-awk — then the copy-paste "Hunting recipes" below give the exact `awk`/`sort`/`uniq` patterns for this lab

---

## Your findings (12 pts)
Work top to bottom — each answer leads toward the next stage of the attack.

| # | Question | Pts |
|---|----------|-----|
| 1 | **Initial access.** One IP probed dozens of non-existent paths (a flood of 404s) before breaking in. What is the **attacker's IP**? | 2 |
| 2 | **Execution/persistence.** After the recon, the attacker uploaded a **web shell**. What is its **URL path**? (Look for a `.php` under `/uploads/` being requested with a `?cmd=` parameter.) | 2 |
| 3 | **Impact.** Through that web shell, the attacker read a sensitive file. **Which file?** (Decode the `cmd=` parameter values.) | 2 |
| 4 | **Persistence.** The attacker also pivoted to SSH and created a new account to keep access. What is that **username**? (`auth.log`.) | 2 |
| 5 | **Exfiltration.** A large outbound transfer left the server. What is the **destination IP**? (`conn.log` — find the outlier by `bytes_out`.) | 2 |
| 6 | **ATT&CK.** Which technique ID covers planting a **web shell** for persistence? | 1 |
| 7 | **ATT&CK.** Which technique ID covers **data exfiltration** over the network/C2 channel? | 1 |

### Hunting recipes (learn these — they're daily SOC skills)
```bash
# Who generated the most 404s? (directory brute force stands out)
awk '$9==404 {print $1}' /cases/access.log | sort | uniq -c | sort -rn | head

# Everything one IP did, in order:
grep '<attacker_ip>' /cases/access.log

# Find web shell usage (requests carrying a command parameter):
grep -E 'cmd=' /cases/access.log

# Decode what commands were run through the shell:
grep -oE 'cmd=[^ "]+' /cases/access.log | sort -u     # %20 = space, %2F = /

# auth.log: account creation & SSH success:
grep -E 'useradd|Accepted password' /cases/auth.log

# conn.log: biggest outbound transfer (skip header, sort by bytes):
sort -t, -k5 -nr /cases/conn.log | head
```

### Hints
<details><summary>Task 1</summary>Normal visitors hit real pages (mostly 200/304). An attacker doing recon hits many paths that don't exist. Rank source IPs by their 404 count; one is far above the rest and uses a <code>python-requests</code> user agent.</details>
<details><summary>Task 3</summary><code>cat%20/var/www/...</code> — <code>%20</code> is a URL-encoded space. The file path follows it.</details>
<details><summary>Task 5</summary>Every row is an outbound connection; the exfil is the one with a <b>huge</b> byte count (tens of millions), far larger than any normal request.</details>

---

## Submitting
In chat: `lab 5 task 1: <ip>`, `lab 5 task 2: /uploads/...`, `lab 5 task 6: T1505.003`, etc.

## Write it up
In `lab05-threat-hunt/report.md`, produce an **incident timeline** mapping each stage to its ATT&CK tactic:
Reconnaissance → Initial Access → Execution → Persistence → Exfiltration. For each: the timestamp, the evidence
(log line), and the recommended containment/remediation. This timeline-with-evidence format is exactly what a
SOC/DFIR analyst delivers, and it's strong portfolio material.

## Reset (new randomized incident)
```powershell
docker compose down -v; docker compose up -d --build
```
