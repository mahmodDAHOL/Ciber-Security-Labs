# Cybersecurity Labs

Hands-on labs that follow the 24-month plan in `../cybersecurity-roadmap.html`.
Each lab is a set of Docker containers on an isolated network on this PC. You attack (or defend) them,
submit flags and answers, and `check.py` checks them against the running lab and records your score.

## How it works
1. Claude builds a lab and assigns it to you.
2. You read the linked tutorials, then do the tasks.
3. You send your answers in chat. Claude runs `check.py` to verify them and update `PROGRESS.md`.
4. You write a short `report.md` for each lab. Claude reviews it and asks interview-style questions.
5. Once a lab is finished, tick the matching tasks in the roadmap tracker.

## Labs
| Lab | Topic | Phase | Status |
|-----|-------|-------|--------|
| [01](lab01-recon/README.md) | Network recon, anonymous FTP, sniffing cleartext credentials | 1 | Done 12/12 · report written (add Wireshark screenshot) · interview Qs pending |

Planned: Linux hardening (P1), TLS & crypto (P1), SIEM with Wazuh (P2), log investigation (P2),
OWASP Top 10 web app (P3), privilege escalation (P3), ERPNext pentest (P3), AD lab (P4), and more.

## Rules
- Attack only these lab containers, or platforms that authorize it (TryHackMe, HTB, PortSwigger).
- Don't read a lab's source files before finishing it. They contain spoilers.
- Progress: `python check.py status`
