# Lab 02: Linux Server, Break In, Then Harden

**Roadmap:** Phase 1 (Linux hardening, security fundamentals) · **Time:** 3–5 hours · **Points:** 16

## Scenario
Northwind's Linux server **srv01** (`10.10.20.10`) runs SSH. A leaked deployment script shows that a
service account named **`deploy`** exists. Your job has two parts:

- **Part A (red team):** prove the server can be taken over. Get in as `deploy`, then become root.
- **Part B (blue team):** you're now the server's admin. Fix every weakness you used, without locking yourself out.

> Don't read the lab's source files (Dockerfiles, `entrypoint.sh`, `sshd_config` in this folder). They contain spoilers.

## Read first (about 2 h)
1. SSH and key-based authentication: https://www.ssh.com/academy/ssh/public-key-authentication
2. Hydra, an online password attack tool: https://github.com/vanhauser-thc/thc-hydra (read the README usage section)
3. Linux file permissions (`rwx`, octal like 640): https://linuxjourney.com/lesson/file-permissions
4. `sudo` and the sudoers file: https://www.digitalocean.com/community/tutorials/how-to-edit-the-sudoers-file
5. GTFOBins, how ordinary binaries become privilege escalation: https://gtfobins.github.io/ (read the intro, then look up `find`)
6. SSH server hardening: https://www.ssh.com/academy/ssh/sshd_config

## Start the lab
```powershell
cd "C:\Users\S I N O\Downloads\ciber security labs\labs\lab02-linux-harden"
docker compose up -d --build
docker exec -it lab02-attacker bash      # your attack box (10.10.20.5)
```
Your attack box has `nmap`, `hydra`, `ssh` and a wordlist at `/root/wordlists/common-passwords.txt`.

---

## Part A: Attack (7 pts)

| # | Task | Pts |
|---|------|-----|
| 1 | **Password attack.** Scan srv01, then use `hydra` with the wordlist to find **deploy's SSH password**. Log in as `deploy`. | 3 |
| 2 | **Privilege escalation.** As `deploy`, find a way to become **root** and read `/root/flag.txt`. | 3 |
| 3 | **Enumeration.** One sensitive system file is readable by every user, and it shouldn't be. Which file? Submit its full path. | 1 |

### Hints (only if you're stuck for more than 20 minutes)
<details><summary>Task 1</summary><code>hydra -l deploy -P &lt;wordlist&gt; ssh://10.10.20.10 -t 4</code>. <code>-l</code> is one username, <code>-P</code> is a password file, <code>-t</code> is parallel tasks.</details>
<details><summary>Task 2</summary>First command on any Linux box you land on: <code>sudo -l</code>. Then search GTFOBins for what it shows, in the "Sudo" section.</details>
<details><summary>Task 3</summary>Which file stores password <i>hashes</i>? Check its permissions with <code>ls -l</code>. Should "others" be able to read it?</details>

---

## Part B: Harden (9 pts)

You're root on srv01 now. Get a root shell from Windows with `docker exec -it lab02-srv01 bash`.
**Do the steps in this order**, or you'll lock yourself out.

| # | Task | Pts |
|---|------|-----|
| 4 | **Key login.** On your attack box, generate an SSH key pair. Install the public key for `deploy` on srv01. Confirm `ssh deploy@10.10.20.10` works **without a password**. | 2 |
| 5 | **Disable password login.** Turn off SSH password authentication, then reload sshd. Hydra must now fail. | 2 |
| 6 | **Disable root login over SSH.** | 1 |
| 7 | **Limit guessing.** Allow at most **3** authentication attempts per connection. | 1 |
| 8 | **Fix sudo.** Remove the rule that let you escalate in task 2. | 2 |
| 9 | **Fix permissions** on the file from task 3 (Debian's default is `640`, owner `root`, group `shadow`). | 1 |

**Reloading sshd** after editing `/etc/ssh/sshd_config`:
```bash
sshd -t                         # test the config first. No output means OK
kill -HUP $(cat /run/sshd.pid)  # reload without dropping your session
```
Always keep one session open while you change SSH settings. That's how real admins avoid locking themselves out.

<details><summary>Hint for task 4</summary>On the attacker: <code>ssh-keygen -t ed25519</code>, then <code>ssh-copy-id deploy@10.10.20.10</code>. This uses the password one last time. On srv01, check the permissions: <code>~/.ssh</code> must be 700 and <code>authorized_keys</code> 600.</details>
<details><summary>Hint for task 8</summary>Rules live in <code>/etc/sudoers</code> and <code>/etc/sudoers.d/</code>. Always edit them with <code>visudo</code>, or delete the drop-in file.</details>

---

## Submitting
Tell Claude in chat: `lab 2 task 1: <password>`, `lab 2 task 2: FLAG{...}`, `lab 2 task 3: <path>`.
For Part B, just say `lab 2 task 4 done`. The checker tests the live server, for example by trying a key login and a password login from your attack box.

## Write it up
In `lab02-linux-harden/report.md`, for each finding: the attack step that used it, then the fix you applied, with the exact command or config line.
Include before/after evidence for at least one, such as hydra succeeding and then failing.

## Reset
```powershell
docker compose down -v; docker compose up -d --build   # brand-new vulnerable server, new password and flag
```
