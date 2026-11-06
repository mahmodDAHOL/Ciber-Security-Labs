# Lab 04: Build a SOC — SIEM Detection, Detection-as-Code & Triage

**Roadmap:** Phase 2 (SOC / SIEM / detection, MITRE ATT&CK) · **Time:** 4–6 hours · **Points:** 12

## Scenario
You're now an L1 analyst in Northwind's new Security Operations Center. A small SIEM watches the
auth logs of a server (`victim`, `10.10.40.20`). An attacker (`10.10.40.5`) has already hit it. Your job:
**investigate the incident**, then **write detections** so the next one is caught automatically.

This is the defender's view of the exact attack you ran in Lab 02 (SSH brute force → login → sudo). Same attack, other side of the glass.

> You *may* read the SIEM's rules in `/opt/soc/rules/` — that's your tool. Don't read the attacker's `attack.sh` until you've finished Part A.

## How the lab is wired
```
 attacker (10.10.40.5)  --ssh-->  victim (10.10.40.20)  --auth.log-->  siem (10.10.40.10)
                                                                         ├─ engine.py  (parses logs, runs rules, raises alerts)
                                                                         ├─ dashboard  http://localhost:8080
                                                                         └─ soc        (query CLI)
```

## Read first (about 1.5 h)
1. What a SIEM is and what a SOC analyst does: https://www.ibm.com/topics/siem
2. Reading Linux auth logs (Failed/Accepted password, sudo): https://www.loggly.com/ultimate-guide/linux-logging-basics/
3. MITRE ATT&CK — browse these techniques: **T1110** (Brute Force), **T1078** (Valid Accounts), **T1548** (Abuse Elevation Control): https://attack.mitre.org/
4. Detection-as-code / Sigma idea (concept only): https://github.com/SigmaHQ/sigma#what-is-sigma
5. Alert triage basics (true vs false positive): https://www.crowdstrike.com/cybersecurity-101/security-operations-center-soc/

## Start the lab
```powershell
cd "C:\Users\S I N O\Downloads\ciber security labs\labs\lab04-soc"
docker compose up -d --build
```
Then open the dashboard: **http://localhost:8080** (refreshes every 5s). The attacker fires automatically ~8s after start,
so you should already see a **high-severity SSH Brute Force** alert.

Investigate from the SIEM container:
```powershell
docker exec -it lab04-siem bash
soc alerts                 # alerts raised so far
soc events --type failed_login   # raw parsed events
soc events --type accepted_login
soc rules                  # loaded detection rules
cat /logs/auth.log         # the raw source logs
```

---

## Part A: Investigate (4 pts)
Use the dashboard, `soc`, and `/logs/auth.log`.

| # | Task | Pts |
|---|------|-----|
| 1 | What **source IP** carried out the brute force? | 1 |
| 2 | Which **account** did the attacker eventually log in to? (A `Failed password` storm, then an `Accepted password`.) | 2 |
| 3 | Which **MITRE ATT&CK technique ID** describes SSH password brute forcing? | 1 |

---

## Part B: Detection engineering (8 pts)
The SIEM ships with only one rule (SSH Brute Force, `SOC-001`). You'll add three of your own.

**Write rules as `.yml` files in `/opt/soc/rules/custom/`** (on the siem container: `nano /opt/soc/rules/custom/myrule.yml`).
The engine reloads that folder every second — no restart. See `/opt/soc/rules/custom/README.txt` for the format.

| # | Task | Detect | Pts |
|---|------|--------|-----|
| 4 | Write a rule that fires on a **successful SSH login** (`accepted_login`). | T1078 Valid Accounts | 3 |
| 5 | Write a rule that fires on **sudo privilege escalation** (`sudo`). | T1548 | 3 |
| 6 | Write your **own brute-force rule** with a **threshold**: ≥10 `failed_login` from one IP within 60s. | T1110 | 2 |

Test your rules by replaying the attack and watching the dashboard / `soc alerts`:
```powershell
docker exec lab04-attacker sh /root/attack.sh
```
When you tell me a task is done, my checker replays the attack itself and confirms **a rule you wrote (source `custom`)** produced the right alert.

### Example rule (this is the format — now write your own for tasks 4–6)
```yaml
# /opt/soc/rules/custom/accepted.yml
id: MY-100
title: Successful SSH login
level: medium
mitre: [T1078]
match:
  event_type: accepted_login
```

### Hints
<details><summary>Task 6 threshold</summary>Copy the structure of the built-in <code>SOC-001</code> rule (<code>soc rules</code> shows it), but set <code>count: 10</code>. Group <code>by: source_ip</code> over a 60s <code>window</code>.</details>
<details><summary>Rule not firing?</summary><code>soc rules</code> shows a PARSE ERROR if your YAML is malformed (watch indentation). Confirm the event exists first with <code>soc events --type accepted_login</code>.</details>

---

## Submitting
In chat: `lab 4 task 1: 10.10.40.5`, `lab 4 task 3: T1110`, and for Part B `lab 4 task 4 done` (I'll replay and verify).

## Write it up
In `lab04-soc/report.md`, write a short **incident report**: timeline (brute force → compromise → escalation),
the indicators (source IP, targeted account), the ATT&CK techniques, and your three detection rules with the reasoning.
This is exactly the artifact a SOC analyst produces, and great interview material.

## Reset
```powershell
docker compose down -v; docker compose up -d --build
```
