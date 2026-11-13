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
| [02](lab02-linux-harden/README.md) | SSH brute force, sudo privilege escalation, then harden the server | 1 | Done 16/16 · report written |
| [03](lab03-crypto-tls/README.md) | Password cracking (John), TLS cert inspection, building a CA, mutual TLS | 1 | Done 12/12 · report written |
| [04](lab04-soc/README.md) | Build a mini-SOC: SIEM log pipeline, detection-as-code, ATT&CK triage | 2 | Done 12/12 · report written |
| [05](lab05-threat-hunt/README.md) | Threat hunt: reconstruct a multi-stage web intrusion from noisy logs | 2 | Done 12/12 · report written |
| [06](lab06-web-owasp/README.md) | Web app hacking: SQLi, IDOR, command injection, path traversal (OWASP Top 10) | 3 | Done 12/12 · report complete (review) |
| [07](lab07-privesc/README.md) | Linux privilege escalation: SUID, sudo/GTFOBins, cron, Linux capabilities | 3 | Done 14/14 · report complete (review) |
| [08](lab08-erpnext-pentest/README.md) | ERPNext/Frappe pentest: default creds, guest API, SQLi, BOLA/IDOR (OWASP API Top 10) | 3 | Done 14/14 · report complete (review) |
| [09](lab09-active-directory/README.md) | Active Directory: domain enumeration, password spraying, SMB/LDAP initial access | 4 | Done 14/14 · report complete (review) |
| [10](lab10-container-escape/README.md) | Container escape: mounted docker.sock, privileged, capabilities, secret exposure | 5 | Done 14/14 · report complete (review) |
| [11](lab11-devsecops/README.md) | DevSecOps: SAST (Bandit), secret scanning (gitleaks), dependency CVEs (pip-audit), code review | 6 | Done 14/14 · report complete (review) |

Planned: cloud IAM / AWS security (P5), Kubernetes security (P5), and more.

## Rules
- Attack only these lab containers, or platforms that authorize it (TryHackMe, HTB, PortSwigger).
- Don't read a lab's source files before finishing it. They contain spoilers.
- Progress: `python check.py status`
