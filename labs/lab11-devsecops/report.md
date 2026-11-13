# Code Security Review: Northwind Internal Tools API

| | |
|---|---|
| **Engagement** | Lab 11 — Pre-release code security review (DevSecOps) |
| **Target** | `vulnapp` — Python/Flask internal tools API (source + git history) |
| **Reviewer** | Mahmod Aldahol |
| **Date** | 2026-11-13 |
| **Method** | SAST (Bandit), secret scanning (gitleaks/detect-secrets), SCA (pip-audit), manual review |
| **Overall risk** | **Critical** — multiple RCE-class bugs plus leaked credentials |

> Lab exercise. Secret values shown as proof are from this run (they regenerate on rebuild).

## 1. Executive summary
The internal tools API should **not** ship. Automated and manual review found multiple **critical**
vulnerabilities: several routes allow **remote code execution** (command injection, `eval`, insecure
deserialization, unsafe YAML load), user input reaches **SQL** unparameterised, a **live credential is
hardcoded** in the source, and a **second secret is exposed in git history**. The dependencies are years out
of date with known CVEs. Each finding has a standard fix (§4), and most would be caught automatically by a
CI pipeline (SAST/SCA/secret-scan) — which is the core recommendation.

**Overall posture.** The code should not ship — there are four separate ways to get remote code execution plus
two leaked credentials. The posture is "no secure-coding discipline and no security pipeline." I'd block the
release on the RCE findings as a group (command injection, `eval`, `pickle`, `yaml.load`) — any one of them is
full server compromise.

## 2. Findings at a glance
| # | Finding | How found | CWE | Severity |
|---|---------|-----------|-----|----------|
| F-1 | OS command injection (`/exec` shell=True, `/ping` os.popen) | Bandit B602/B605 | CWE-78 | **Critical** |
| F-2 | Insecure deserialization (`/load` pickle) | manual | CWE-502 | **Critical** |
| F-3 | Code injection via `eval` (`/calc`) | Bandit B307 | CWE-95 | **Critical** |
| F-4 | Unsafe YAML load (`/config`) + vulnerable PyYAML | Bandit B506 + pip-audit | CWE-502 | **Critical** |
| F-5 | SQL injection (`/user`) | Bandit B608 | CWE-89 | **High** |
| F-6 | Hardcoded credential in source | detect-secrets | CWE-798 | **High** |
| F-7 | Secret committed to git history | gitleaks | CWE-540 | **High** |
| F-8 | Outdated dependencies with known CVEs | pip-audit | CWE-1104 | Medium |
| F-9 | Weak MD5 password hashing; TLS verify=False; Flask debug=True | Bandit B324/B501/B201 | — | Medium |

## 3. Detailed findings (selected)

### F-1 — OS command injection · Critical · CWE-78
`/exec` runs `subprocess.check_output(cmd, shell=True)` and `/ping` runs `os.popen("ping -c 1 " + host)` on
user input. **PoC class:** `?cmd=id`, `?host=127.0.0.1;id`. **Impact:** full RCE as the app user.
**Fix:** no `shell=True`; pass an argument list (`subprocess.run(["ping","-c","1",host])`); validate input.

**B602 vs B605.** Same bug — command injection — through two different functions. B602 is the `/exec` route
using `subprocess.check_output(cmd, shell=True)`; B605 is the `/ping` route using `os.popen("ping ... " +
host)`. Both hand user input to a shell, so both let me chain commands. Bandit gives them different IDs because
they're different APIs, but the fix is identical: don't pass user input to a shell.

### F-2 — Insecure deserialization · Critical · CWE-502
`/load` does `pickle.loads(base64.b64decode(data))` on attacker data. `pickle` can reconstruct arbitrary
objects → code execution. **Fix:** never unpickle untrusted data; use JSON; if unavoidable, sign + verify.

### F-3 — `eval` code injection · Critical · CWE-95
`/calc` does `eval(expr)` on user input → arbitrary Python. **Fix:** never `eval` input; use `ast.literal_eval`
or a real expression parser.

### F-4 — Unsafe YAML + vulnerable library · Critical · CWE-502
`/config` calls `yaml.load(blob)` (the unsafe loader), and the pinned **PyYAML 5.1** has a code-execution CVE.
This is a code bug **and** a supply-chain bug. **Fix:** `yaml.safe_load`, and upgrade PyYAML.

### F-5 — SQL injection · High · CWE-89
`/user` builds SQL with `"... WHERE id = %s" % uid`. **Fix:** parameterised queries (`execute(sql, (uid,))`).

### F-6 — Hardcoded credential · High · CWE-798
`AWS_SECRET_ACCESS_KEY = "AKIA3091A4EF95304D7C"` in `app.py`. **Fix:** remove, **rotate**, load from a secrets
manager / env at runtime.

### F-7 — Secret in git history · High · CWE-540
A GitHub token `ghp_c64c03b8dee8af3fc1b1072c772898bb0889` was committed in `config.py`, then removed in a later
commit — but gitleaks found it in history. **Deleting it from the file did not un-leak it.** **Fix:** **rotate
the token** (assume compromised), purge history if needed, and run gitleaks in CI on every commit.

### F-8 — Outdated dependencies · Medium · CWE-1104
`pip-audit` flagged Flask 0.12.2, Jinja2 2.10, PyYAML 5.1, requests 2.19.1, Werkzeug 0.14.1 with known CVEs.
**Fix:** upgrade/pin to patched versions; run SCA in CI; enable Dependabot; produce an SBOM.

## 4. Remediation summary (priority order)
| Priority | Action | Finding |
|----------|--------|---------|
| 1 | Remove all RCE sinks: no `shell=True`, no `eval`, no `pickle`/`yaml.load` on input | F-1, F-2, F-3, F-4 |
| 2 | Parameterise SQL | F-5 |
| 3 | Remove + **rotate** both secrets; move to a vault | F-6, F-7 |
| 4 | Upgrade dependencies; add SCA to CI | F-4, F-8 |
| 5 | Strong hashing, TLS verify on, debug off | F-9 |
| — | **Pipeline:** SAST (Bandit/Semgrep) + SCA (pip-audit) + secret scan (gitleaks) on every PR | all |

## 5. Lessons learned
- **The same root cause repeats:** F-1/F-3/F-2/F-4 are all "untrusted input becomes code." Recognising the
  sink (`eval`, `pickle`, `shell=True`, `yaml.load`) is the core code-review skill.
- **Secrets must be rotated, not just deleted:** F-7 is the one everyone gets wrong — history and clones keep
  the secret alive.
- **Your dependencies are your attack surface too:** clean code on top of a vulnerable library is still
  vulnerable — SCA is not optional.

**What a pipeline catches vs. what needs a human.**
Automated tools are good at the pattern-based stuff. SAST like Bandit finds dangerous functions — `eval`,
`pickle.loads`, `subprocess(..., shell=True)`, `yaml.load`, hardcoded-secret patterns (F-1, F-2, F-3, F-4,
F-5, F-6, F-9). SCA like pip-audit finds dependencies with known CVEs from their versions (F-8). Secret
scanners like gitleaks find keys by shape and entropy, even in old commits (F-7). All of that is fast and
cheap, so you run it on every pull request and catch the easy 80% early.

But tools don't understand context or intent, so a human finds the logic bugs. The big one is access control —
a scanner can't know that user A shouldn't read user B's record, because that's a business rule, not a code
pattern (this is why the IDOR in Lab 06/08 wouldn't show up in SAST). A tool flags `pickle.loads` as
dangerous, but only a person confirms the data really comes from the user and the route is reachable.

The distinction matters because you use automation to scale — catch the known, obvious issues on every commit
with no human in the loop — and save expensive human review for the design and authorization flaws machines
can't see. You need both, and a human triages the tools' false positives anyway.
