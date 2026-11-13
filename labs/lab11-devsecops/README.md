# Lab 11: DevSecOps — SAST, Secret Scanning & Dependency Analysis

**Roadmap:** Phase 6 (AppSec & DevSecOps) · **Time:** 3–5 hours · **Points:** 14

## Scenario
You're the security engineer reviewing Northwind's "internal tools API" before it ships. Instead of attacking
a running app, you do what a DevSecOps pipeline does: **scan the code and its supply chain** for vulnerabilities
before they reach production — "shift left." You'll use the real tools (**Bandit** for SAST, **gitleaks** for
secrets, **pip-audit** for vulnerable dependencies) plus your own manual code review.

> This plays to your Python background — it's secure code review, the skill behind auditing Frappe whitelisted
> methods and any Python service.

## Start the lab
```powershell
cd "C:\Users\S I N O\Downloads\ciber security labs\labs\lab11-devsecops"
docker compose up -d --build
docker exec -it lab11-scanner bash
```
The vulnerable project is at **`/opt/vulnapp`** (a git repo with history). Your tools: `bandit`, `pip-audit`,
`detect-secrets`, `gitleaks`, `git`, `grep`.

## Read first (about 1 h)
1. SAST vs DAST vs SCA (what each finds): https://owasp.org/www-community/Source_Code_Analysis_Tools
2. Bandit (Python SAST): https://bandit.readthedocs.io/en/latest/
3. gitleaks (secrets in git history): https://github.com/gitleaks/gitleaks
4. pip-audit (Python dependency CVEs): https://pypi.org/project/pip-audit/
5. OWASP secure code review: injection, deserialization, SSRF, secrets.

## Tool cheatsheet
```bash
cd /opt/vulnapp
bandit -r . -lll                      # SAST, high-severity only (-lll)
detect-secrets scan app.py            # secrets in a file
gitleaks detect --no-banner -v        # secrets across the whole git HISTORY
pip-audit -r requirements.txt         # known CVEs in pinned dependencies
git log --oneline ; git log -p        # review history (secrets hide in old commits)
```

---

## Tasks (14 pts)
Submit the answer each task asks for (a value, a package name, an ID, or a term).

| # | Task | Tool / skill | Pts |
|---|------|--------------|-----|
| 1 | **SAST triage.** Run Bandit. Several HIGH findings come up. Which **Bandit test ID** flags the `subprocess(..., shell=True)` command-injection call? | Bandit | 2 |
| 2 | **Hardcoded secret.** A credential is hardcoded in the **current** source. Find and submit its value. | detect-secrets / grep | 3 |
| 3 | **Secret in git history.** A different secret was committed and then "removed" — but it lives in history forever. Scan the history and submit it. | gitleaks | 3 |
| 4 | **Vulnerable dependency.** The app calls an unsafe `yaml.load`. Which pinned **package** does `pip-audit` flag for that (arbitrary code execution)? | pip-audit | 3 |
| 5 | **Manual code review.** Besides injection, one route has an **insecure deserialization** flaw (RCE). Name the dangerous function **or** its CWE ID. | code review | 2 |
| 6 | **Knowledge.** What does **SAST** stand for? | — | 1 |

### Hints
<details><summary>Task 1</summary>Run <code>bandit -r . -lll</code> and read the test IDs (like <code>B602</code>, <code>B605</code>). The one named for <code>subprocess_popen_with_shell_equals_true</code> is what you want.</details>
<details><summary>Task 3</summary><code>gitleaks detect -v</code> walks every commit. The secret isn't in the current files — <code>grep</code> won't find it, only a history scan will. It looks like a GitHub token (<code>ghp_...</code>).</details>
<details><summary>Task 5</summary>Look at the <code>/load</code> route — <code>pickle.loads</code> on attacker-controlled data is remote code execution. The CWE is 502.</details>

**Bonus (not graded):** Bandit finds more than injection — weak MD5 hashing, `requests(verify=False)`, Flask
`debug=True`, `eval()`. List them all in your report. Also try writing a **custom Semgrep rule** for one of them.

---

## Submitting
In chat: `lab 11 task 1: B602`, `lab 11 task 4: pyyaml`, `lab 11 task 6: static application security testing`, etc.

## Write it up
In `lab11-devsecops/report.md`, write a **code security review**: each finding with the file/line, the tool
that found it (or "manual"), severity, impact, and the fix — parameterised queries, no `shell=True`, safe
deserialization (`json`, not `pickle`), `yaml.safe_load`, strong hashing (bcrypt/argon2), TLS verification on,
secrets in a vault not source, and **pinning + patching dependencies**. Note which findings a pipeline would
catch automatically (SAST/SCA/secret-scan) vs. which needed a human — that's the core DevSecOps argument.

## Reset (new secrets)
```powershell
docker compose down; docker compose up -d --build
```
