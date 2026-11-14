# Lab 12: Digital Forensics & Incident Response (DFIR)

**Roadmap:** Phase 7 (Specialization — DFIR basics + malware analysis) · **Time:** 3–5 hours · **Points:** 14

## Scenario
Northwind's production server `prod-erp` was compromised overnight. It's been **seized** and handed to you,
the forensic analyst. Nobody knows how the attacker got in, what they left behind, or whether they can get
back. Your job: **investigate the host**, reconstruct what happened, analyse the malware they dropped, and
produce the indicators of compromise (IOCs) the SOC needs to hunt for it elsewhere.

This is the *defensive* counterpart to the attacks you've been running — now you read the evidence an attacker
leaves and turn it into findings.

## Start the lab
```powershell
cd "C:\Users\S I N O\Downloads\ciber security labs\labs\lab12-dfir"
docker compose up -d --build
docker exec -it lab12-host bash
```
You're on the seized host. Investigate **read-only, methodically**. Your toolkit: `find`, `stat`, `ls`,
`grep`, `strings`, `file`, `sha256sum`, `base64`, `xxd`, `less`, `cat`.

## Read first (about 45 min — all beginner-friendly)
1. What digital forensics is + the investigation steps, in plain English: https://www.blackpanda.com/ir1-resources/steps-to-digital-forensics
2. Incident response lifecycle — the 6 phases (PICERL) explained simply: https://cyberdefenders.org/cybersecurity-glossary/incident-response-steps/
3. Static malware analysis basics — `file`, `strings`, hashes (exactly what Tasks 3–5 use): https://andreafortuna.org/2023/01/25/static-malware-analysis-a-basic-workflow
4. Persistence: how attackers add backdoor accounts (maps to Task 6): https://attack.mitre.org/techniques/T1136/
5. *(Optional, skim)* DFIR cheat sheets for later: SANS posters — https://www.sans.org/posters/

## Investigator's cheat sheet
```bash
# Logins / brute force (who got in, from where)
grep -E 'Accepted|Failed' /var/log/auth.log

# What ran (attacker's shell history)
cat /root/.bash_history

# Timeline — recently changed files stand out against the system baseline
ls -la /dev/shm /tmp ; find / -xdev -newermt '2026-10-20' -type f 2>/dev/null | grep -v /proc

# Inspect a suspicious file
file <path> ; stat <path> ; strings <path> ; sha256sum <path>

# Persistence
cat /etc/passwd | awk -F: '$3==0'      # accounts with uid 0 (should be only root)
cat /etc/cron.d/* /etc/crontab 2>/dev/null
```

---

## Tasks (14 pts)
Submit each piece of evidence.

| # | Task | Skill | Pts |
|---|------|-------|-----|
| 1 | **Timeline / initial access.** From the logs, what is the **attacker's source IP** (brute-forced in, then logged in)? | Log forensics | 2 |
| 2 | **Locate the malware.** The attacker dropped an executable in an unusual place. Give its **full path**. | Timeline / triage | 3 |
| 3 | **Fingerprint it.** Compute the **SHA-256** of the malware (this is the IOC the SOC will hunt for). | Evidence hashing | 2 |
| 4 | **Static analysis — C2.** Without running it, find the **C2 server IP** the malware beacons to. | `strings` | 3 |
| 5 | **Static analysis — payload.** The malware hides a base64 "config". **Decode it** and submit what it reveals. | decoding | 2 |
| 6 | **Persistence.** The attacker added a hidden **backdoor account** (uid 0). What's its username? | Persistence hunting | 2 |

### Hints
<details><summary>Task 2</summary>Attackers favour world-writable, memory-backed dirs like <code>/dev/shm</code> (survives nothing, leaves little). Compare file timestamps — the attacker's file was created at the breach time (Oct 21), not when the OS was built.</details>
<details><summary>Task 4/5</summary><code>strings /dev/shm/.update</code> shows the source. <code>C2_HOST</code> is the C2 IP. The <code>CFG = "..."</code> value is base64 — pipe it to <code>base64 -d</code>.</details>
<details><summary>Task 6</summary><code>awk -F: '$3==0' /etc/passwd</code> lists every uid-0 account. One of them isn't <code>root</code>.</details>

**Bonus (not graded):** reconstruct the full attack timeline from `/root/.bash_history` and `/var/log/auth.log`,
and write the IOC list (attacker IP, C2 IP, file path + hash, backdoor account, cron persistence) the way a SOC
would consume it. Map each attacker action to MITRE ATT&CK.

---

## Submitting
In chat: `lab 12 task 1: 45.x.x.x`, `lab 12 task 3: <sha256>`, `lab 12 task 6: <username>`, etc.

## Write it up
In `lab12-dfir/report.md`, write an **incident / forensic report**: timeline of the compromise, root cause
(initial access), what the attacker did, the malware analysis (hash, C2, capability), all persistence
mechanisms, and the **IOC list** + containment/eradication steps (kill the process, remove `/dev/shm/.update`
and the cron, delete the `sysupdate` account, rotate credentials, block the IPs). Note the anti-forensic
angle: the attacker used `/dev/shm` precisely because it's volatile — which is why *order of volatility* matters.

## Reset (new evidence)
```powershell
docker compose down; docker compose up -d --build
```
