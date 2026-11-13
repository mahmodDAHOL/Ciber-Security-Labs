# Interview Prep — Q&A in my own words

Answers to the questions an interviewer is likely to ask about the hands-on labs I did.
Written the way I'd actually say them out loud. Read them, then say them in my own words — not memorised.

---

## Web (Lab 06 / Lab 08)

**Q: Explain SQL injection — what it is, how you exploited it, and how to fix it.**
SQL injection is when my input goes straight into a SQL query, so the input becomes part of the query instead
of just data. In my lab the login ran `SELECT ... WHERE username='<input>' AND password='<input>'`. I put
`admin' --` as the username. The `'` closes the string early and `--` comments out the rest, so the
`AND password=...` check is gone and I log in as admin with no password. The fix is parameterised queries —
you send the query and the values separately so input can't change the query. Plus hash passwords in code and
use a low-privilege database user.

**Q: What's a UNION-based SQL injection?**
It's using injection to pull data out, not just bypass a check. I break out of the original query and bolt on
my own `UNION SELECT` to read a different table. The two selects have to return the same number of columns, so
first I match the column count, then I `UNION SELECT` the columns I want from the secret table. In my lab that
dumped a hidden `secrets` table.

**Q: What is IDOR / broken access control?**
IDOR is when the app decides what I can see based only on an ID in the request, and never checks if that record
is actually mine. In my lab `/account?id=2` just changed to `?id=3` and I read someone else's data. The app
checked that I was logged in, but not that I was allowed to see *that* object. Fix is an object-level
authorization check on every request — does this user own or have rights to this id. It's OWASP's number one
risk, and in the API lab it maps to API1 (BOLA).

**Q: OS command injection — how is it different and why is it worse?**
It's when my input gets passed into a shell command. In the ping tool I added `127.0.0.1; cat /srv/flags/...`
and the `;` let me run my own command. It's worse than SQL injection because it's not just reading data — it's
running code on the server. That's full server compromise, not just a database leak. Fix is to never build a
shell string from input — call the program directly without a shell and validate the input.

**Q: What is XSS?**
Cross-site scripting is when my input gets reflected back into the page without being escaped, so the browser
runs it as script. I tested `<script>alert(1)</script>` in the search box and it ran. The danger is stealing
another user's session or doing actions as them. Fix is to HTML-encode output and add a Content-Security-Policy.

---

## Linux privilege escalation (Lab 02 / Lab 07)

**Q: You land a low-priv shell on Linux. What do you check first?**
Four things fast: `sudo -l` to see what I can run as root, `find / -perm -4000` for SUID binaries, `getcap -r /`
for dangerous capabilities, and cron jobs plus any world-writable scripts they run. Tools like linPEAS
automate all of that. In my lab each of those was a separate path to root.

**Q: Give an example of a privesc you did.**
A few. SUID on `find` — I ran `find . -exec /bin/sh -p \;` and the shell kept root's privileges. A sudo rule
let me run `awk` as root, so `sudo awk 'BEGIN{system("/bin/sh")}'` gave a root shell. A root cron job ran a
world-writable script, so I added my command to it and waited a minute. And a copy of python had
`cap_setuid`, so `os.setuid(0)` made me root. All of it is least-privilege gone wrong — GTFOBins is the
reference.

---

## Crypto & hashing (Lab 03)

**Q: How do you crack a password hash?**
First I identify the hash type (length, `$6$` = sha512crypt, 32 hex = MD5, etc.). Then I run a wordlist against
it with John or hashcat — the tool hashes each guess the same way and compares. Weak or common passwords fall
fast. The defence is strong, slow hashing (bcrypt/argon2) with a salt, and good password policy.

**Q: What's mutual TLS?**
Normal TLS the client checks the server's certificate. Mutual TLS both sides check each other — the client also
presents a certificate that the server validates against a CA. In my lab I had to create a client cert signed
by the right CA before the API would talk to me. It's used for service-to-service auth where you don't want
passwords.

---

## Blue team — SIEM & threat hunting (Lab 04 / Lab 05)

**Q: How would you detect an SSH brute force?**
Count failed logins per source IP in a time window. If one IP has a lot of failures in a short time — say ten
in a minute — that's a brute force, and a success right after is worse. In my lab I built that as a threshold
rule in a mini-SIEM that tails auth.log, parses the events, and fires an alert. ATT&CK calls it T1110.

**Q: Walk me through reconstructing an intrusion from logs.**
I line the logs up on a timeline and follow the kill chain. I find the attacker IP by who did recon then a
successful action — scanning noise is constant, so what matters is recon followed by a real hit. Then I track
it forward: web shell upload, commands run through it, a sensitive file read, a new account for persistence,
and finally a big outbound transfer for exfiltration. The lesson I learned is deleting the web shell isn't
enough — they'd made a separate SSH account, so containment means finding every foothold.

**Q: What's the MITRE ATT&CK framework?**
It's a catalogue of attacker tactics and techniques — tactics are the goal (persistence, exfiltration),
techniques are the how, each with an ID like T1110 for brute force. I use it to tag what I see so detection and
reporting speak a common language.

---

## Active Directory (Lab 09)

**Q: You're on an internal network with no creds. What do you do in AD?**
Enumerate first. I can list valid domain users with no creds using Kerberos — the KDC answers differently for a
real username vs a fake one, so a tool like kerbrute tells me who exists. Then I password-spray: one likely
password against all users, which avoids lockouts. One weak account gives me a foothold, and from there I
enumerate SMB shares and LDAP for more.

**Q: What's password spraying and why not brute force?**
Brute force is many passwords against one account — that locks the account out fast. Spraying is one password
against many accounts, so I stay under the lockout threshold. In a big org someone always uses something weak
like `Spring2025!`. In my lab that's exactly how I got in.

**Q: What's AS-REP roasting?**
Some accounts are set to not require Kerberos pre-authentication. For those, I can ask the DC for auth data and
get back a hash I can crack offline, without even having credentials. I find them with an LDAP filter on the
`DONT_REQ_PREAUTH` bit. The fix is to require pre-auth and use strong passwords. (Kerberoasting is the related
one — cracking service-account tickets found by their SPN.)

---

## Cloud / containers (Lab 10)

**Q: How do you escape a Docker container?**
It depends on the misconfig. The classic one is the host Docker socket mounted inside the container —
`/var/run/docker.sock`. That socket is the host's Docker API, so from inside I can tell the host to run a new
container that mounts the host's whole filesystem, and now I read any file on the host. That's full host
compromise. `--privileged` is the other one — full capabilities, no seccomp, so I can mount the host disk
directly. ATT&CK calls it T1611, Escape to Host.

**Q: How do you prevent that?**
Never mount docker.sock into a container. Drop `--privileged` and only add the capabilities the app actually
needs. Run rootless, read-only root filesystem, keep secrets out of images and environment variables, and run
the CIS Docker Benchmark in CI to catch this automatically.

---

## DevSecOps (Lab 11)

**Q: Which vulnerabilities can automated tools catch, and which need a human?**
Automated tools are good at the pattern-based stuff. SAST like Bandit finds dangerous functions — `eval`,
`pickle.loads`, `shell=True`, `yaml.load`, hardcoded secrets. SCA like pip-audit finds dependencies with known
CVEs from their versions. Secret scanners like gitleaks find keys by shape and entropy, even in old commits.
That's fast and cheap, so you run it on every commit. But tools don't understand context, so a human finds the
logic bugs — especially access control, where a scanner can't know user A shouldn't read user B's data. You use
automation to scale and save human review for what machines can't see.

**Q: SAST vs DAST vs SCA?**
SAST is static — it reads the source code without running it (Bandit). DAST is dynamic — it tests the running
app from the outside (ZAP, like attacking the web lab). SCA is software composition analysis — it checks your
dependencies for known CVEs (pip-audit). You want all three in a pipeline because they catch different things.

---

## General

**Q: Walk me through your methodology on an engagement.**
Recon and enumeration first — find the attack surface before touching anything. Then exploit the weakest thing
I found to get a foothold. Then escalate — privesc on the box or move laterally. Then I document everything:
each finding with proof, impact, and a fix, mapped to OWASP or ATT&CK. The report is the real deliverable, not
the shell.

**Q: What's the difference between a vulnerability, an exploit, and a payload?**
A vulnerability is the weakness (SQL built from input). An exploit is the technique that abuses it
(`admin' --`). A payload is what I actually run through it (the command, the UNION select, the shell). Same
idea across all the labs.
