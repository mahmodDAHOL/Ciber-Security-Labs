# Web Application Penetration Test: Northwind Shop Staff Portal

| | |
|---|---|
| **Engagement** | Lab 06 — Authorized web application penetration test |
| **Target** | Northwind Shop staff portal — `http://10.10.60.20` (`http://localhost:8081`) |
| **Tester** | Mahmod Aldahol |
| **Date** | 2026-11-08 |
| **Overall risk** | **Critical** — unauthenticated SQL injection and remote command execution |

> Lab exercise. Flags look like `FLAG{...}` and regenerate on reset — they are proof of exploitation, not
> secrets. The payloads below are the reproducible proof.

## 1. Executive summary
The Northwind staff portal contains multiple **critical** web vulnerabilities spanning five of the OWASP
Top 10 (2021) categories. An unauthenticated attacker can **bypass the login**, **extract the database** via
SQL injection, **run operating-system commands** on the server (full compromise), read **other users' private
data** by changing a URL parameter, and read **arbitrary files** off the server. Every finding is a classic
input-handling failure with a well-understood fix (§4). Immediate remediation is required.

**Overall posture.** The app is wide open — five of the OWASP Top 10 in one small portal, and most of it
reachable with no login. The posture is basically "no input is validated anywhere." I'd fix the command
injection (F-1) first, because it's the only one that gives full control of the server, not just the data.

## 2. Findings at a glance
| # | Finding | OWASP 2021 | Severity |
|---|---------|------------|----------|
| F-1 | OS command injection (ping tool) | A03 Injection | **Critical** |
| F-2 | SQL injection — UNION data exfiltration (search) | A03 Injection | **Critical** |
| F-3 | SQL injection — authentication bypass (login) | A03 Injection | **High** |
| F-4 | Broken access control / IDOR (account page) | A01 Broken Access Control | **High** |
| F-5 | Path traversal / arbitrary file read (download) | A05 (traversal) | Medium |
| F-6 | Reflected XSS (search) — *bonus* | A03 Injection | Medium |

## 3. Detailed findings

### F-1 — OS command injection · Critical · A03
**Description.** `/tools/ping?host=` passes the `host` parameter into a shell command without sanitisation, so
shell metacharacters let an attacker run arbitrary commands as the web user.
**PoC:**
```bash
curl "http://10.10.60.20/tools/ping?host=127.0.0.1;cat+/srv/flags/cmdinj.txt"   # -> FLAG{cmdinj_...}
curl "http://10.10.60.20/tools/ping?host=127.0.0.1;id"                           # proves arbitrary RCE
```
**Impact.** Full remote code execution on the server — read any file, pivot, persist. Highest-impact finding.
**Remediation.** Never build shell strings from user input. Call the binary without a shell
(`subprocess.run(["ping","-c","1",host], shell=False)`) and validate `host` as a hostname/IP.

**Why it's the worst one.** SQL injection gets me the data in the database; command injection gets me the
whole server. With the ping tool I'm running shell commands as the web user — I can read any file, add a user,
pivot to other machines, or drop a backdoor. SQLi is a data breach; command injection is a full system
compromise, which is why it's the one to fix first.

### F-2 — SQL injection (UNION) · Critical · A03
**Description.** `/search?q=` concatenates input into `... WHERE name LIKE '%<q>%'`. A UNION injection reads
arbitrary tables, including a hidden `secrets` table.
**PoC:** `/search?q=' UNION SELECT flag,NULL FROM secrets-- -` → `FLAG{sqli_union_...}`.
**Impact.** Full read of the database (credentials, secrets, customer data).
**Remediation.** Parameterised queries / prepared statements; never string-concatenate SQL; least-privilege DB user.

### F-3 — SQL injection (auth bypass) · High · A03
**Description.** The `/login` query is built by string concatenation, so a crafted username comments out the
password check.
**PoC:** POST `/login` with `username=admin' -- ` and any password → logged in as admin, dashboard flag
`FLAG{sqli_login_...}`.
**Impact.** Authentication bypass → administrative access without credentials.
**Remediation.** Parameterised queries; verify a password hash server-side (bcrypt/argon2); don't trust input in SQL.

### F-4 — Broken access control / IDOR · High · A01
**Description.** `/account?id=` returns a user record based solely on the URL `id`, with no check that it
belongs to the requester.
**PoC:** iterate `/account?id=1..4`; another user's private note holds `FLAG{idor_...}`.
**Impact.** Any user's private data is readable by changing a number — OWASP's #1 risk.
**Remediation.** Enforce object-level authorization: verify the logged-in user owns (or may access) the requested id.

### F-5 — Path traversal · Medium · A05
**Description.** `/download?file=` concatenates input into a file path, so `../` escapes the intended folder.
**PoC:** `/download?file=../flags/lfi.txt` → `FLAG{lfi_...}`; `/download?file=../../etc/passwd` reads system files.
**Impact.** Arbitrary file read (source, configs, credentials, `/etc/passwd`).
**Remediation.** Resolve the final path and confirm it stays within an allowed base dir (`os.path.realpath` +
prefix check); reject `..`; serve from a whitelist.

### F-6 — Reflected XSS (bonus) · Medium · A03
**Description.** `/search?q=` reflects input unescaped into the HTML response.
**PoC:** `/search?q=<script>alert(1)</script>` executes in the browser.
**Impact.** Session theft / actions in a victim's browser via a crafted link.
**Remediation.** Context-aware output encoding (HTML-escape reflected values); a strict Content-Security-Policy.

## 4. Remediation summary (priority order)
| Priority | Action | Finding |
|----------|--------|---------|
| 1 | Remove shell calls / validate input on the ping tool | F-1 |
| 2 | Parameterise all SQL (search + login) | F-2, F-3 |
| 3 | Enforce object-level authorization on `/account` | F-4 |
| 4 | Safe file handling (realpath + base-dir check) on `/download` | F-5 |
| 5 | Output-encode reflected input + add CSP | F-6 |
| — | **Ongoing:** input validation standard, SAST/DAST in CI, least-privilege DB user | all |

## 5. Lessons learned
- **One root cause, many symptoms:** F-1/F-2/F-3/F-6 are all "untrusted input treated as code/commands" —
  which is why OWASP merged them under A03 Injection. Parameterisation and encoding fix the whole class.
- **Access control is separate and must be explicit:** F-4 passes authentication but fails authorization.
- **Command injection is the crown jewel:** it jumps from "data breach" to "server compromise" — always
  prioritise it.

**Scanner vs. human.** A scanner like ZAP or Burp would reliably catch the injection ones — SQLi, command
injection, path traversal, and the reflected XSS — because it can fuzz inputs and watch the app behave
differently. The one it would likely miss is the IDOR (F-4): the app doesn't error, it just returns another
user's data, and the scanner has no idea that `id=3` isn't mine. That one needs a human who understands who
should access what. Same lesson as the detection side in Lab 04 — tools catch patterns, people catch logic.
