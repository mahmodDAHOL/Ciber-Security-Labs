# Container Security Review: `web-prod-07` Breakout

| | |
|---|---|
| **Engagement** | Lab 10 — Container escape assessment |
| **Target** | `web-prod-07` (`lab10-victim`) — a containerised web app, and its Docker host |
| **Starting access** | A shell inside the container (post-exploitation foothold) |
| **Tester** | Mahmod Aldahol |
| **Date** | 2026-11-12 |
| **Overall risk** | **Critical** — trivial, reliable escape from the container to full host compromise |

> Lab exercise. Flag values quoted as proof are from this run (they regenerate on reset — proof of
> access, not secrets).

## 1. Executive summary
The `web-prod-07` container is configured in a way that makes the container boundary meaningless: it runs
**`--privileged`** and has the **host's Docker socket bind-mounted inside it**. From an unprivileged foothold
in the container, I escaped to the **host filesystem** and could read or modify any file on the host — i.e.
full compromise of the host and, through it, every other container it runs. The container also exposed
**secrets** in a config file and an environment variable. None of this required an exploit; these are
configuration mistakes, each with a simple fix (§4).

**Container popped vs. host owned.** "A container got popped" should mean the blast radius is one container —
that's the whole point of isolation. Here it's "the host is owned" because the container can reach the host's
Docker socket, so from one popped container I control the entire host and every other container on it. Either
the mounted `docker.sock` or `--privileged` alone is game-over — each one on its own breaks the boundary
completely.

## 2. Findings at a glance
| # | Finding | MITRE ATT&CK | Severity |
|---|---------|--------------|----------|
| F-1 | Host Docker socket (`/var/run/docker.sock`) mounted into the container | T1611 Escape to Host | **Critical** |
| F-2 | Container runs `--privileged` (full capabilities, no seccomp/AppArmor) | T1611 | **High** |
| F-3 | Credential stored in a config file in the image | T1552.001 | Medium |
| F-4 | Cloud API key exposed in an environment variable | T1552.007 | Medium |

## 3. Detailed findings

### F-1 — Mounted Docker socket → host compromise · Critical · T1611
**Description.** `/var/run/docker.sock` — the host Docker daemon's API — is bind-mounted into the container.
Any process in the container can command the host's Docker, which is equivalent to **root on the host**.

**Proof of concept.** From inside the container:
```bash
docker ps                                   # lists EVERY container on the host — confirms host-daemon control
docker run --rm -v /:/host debian:bookworm-slim cat /host/opt/lab10/host_flag
# -> FLAG{esc_host_aa5e978cae9a4fee}   (a file that exists only on the HOST)
```
`-v /:/host` mounts the host's root filesystem into a throwaway container; the flag read from `/host/...`
lives on the host, not in the original container — proof of escape.
**Impact.** Full host compromise: read/modify any host file, read every other container's data and secrets,
launch privileged containers, persist. In a cluster this is lateral movement to the whole node.
**Remediation.** **Never mount `docker.sock` into a container.** If a workload truly needs Docker API access,
use a brokered, least-privilege proxy (e.g. a socket-proxy restricting the API surface) — never the raw
socket. The same applies to the container runtime socket in Kubernetes pods.

**One detection.** Watch the Docker daemon / audit logs for a container-create or container-run event that
originates from *inside* a workload container — a web app spawning a new container that mounts the host
filesystem is not normal and is a huge red flag. Runtime tools like Falco do exactly this (alert on a shell or
`docker` command inside a container, or a host-path mount). Same idea as Lab 04: define "normal" and alert on
the anomaly.

### F-2 — `--privileged` container · High · T1611
**Description.** The container runs with `--privileged`, which grants the **full Linux capability set** and
disables seccomp/AppArmor and device restrictions. Confirmed with `capsh --print` (all capabilities present)
and `CapEff: 000001ffffffffff` in `/proc/self/status`.
**Impact.** Even without the Docker socket, `--privileged` enables escape — e.g. mounting the host's disk
device directly, or abusing the cgroup `release_agent`. It removes every runtime safety at once.
**Remediation.** Drop `--privileged`. Grant only the specific capabilities the app needs (`--cap-drop=ALL`
then `--cap-add` the minimum), keep the default seccomp profile, and add `--security-opt=no-new-privileges`.

### F-3 — Credential in a config file · Medium · T1552.001
**Description.** `/etc/app/database.conf` contains a `backup_token` baked into the image.
**PoC:** `grep -ri token /etc/app/` → `FLAG{esc_config_fd24ff1ec9146f71}`.
**Impact.** Anyone with image or container access gets the credential; it also persists in image layers.
**Remediation.** Keep secrets out of images. Inject at runtime via a secrets manager (Vault, AWS/GCP secrets)
or orchestrator secrets mounted as tmpfs files with tight permissions; rotate anything that shipped in an image.

### F-4 — Cloud API key in an environment variable · Medium · T1552.007
**Description.** The container's environment holds a cloud API key.
**PoC:** `env | grep -i key` → `APP_CLOUD_KEY=FLAG{esc_envkey_9f2c71a4d6}`.
**Impact.** Env vars leak readily — into `docker inspect`, logs, crash dumps, child processes, and `/proc`.
A cloud key here can mean pivoting from the container into the cloud account.
**Remediation.** Don't put secrets in environment variables. Use mounted secret files from a secrets manager,
and scope cloud credentials to least privilege with short lifetimes.

## 4. Remediation summary (priority order)
| Priority | Action | Finding |
|----------|--------|---------|
| 1 | Remove the `docker.sock` mount from the container | F-1 |
| 2 | Drop `--privileged`; least-privilege capabilities + seccomp + no-new-privileges | F-2 |
| 3 | Move the config credential to a secrets manager; rotate it | F-3 |
| 4 | Remove the API key from the environment; use mounted secrets, scoped + short-lived | F-4 |
| — | **Ongoing:** run the **CIS Docker Benchmark** (docker-bench-security) in CI; run containers rootless; read-only root FS | all |

## 5. Lessons learned
- **A container is not a security boundary when it's misconfigured.** Socket mount or `--privileged` each
  collapse the boundary entirely — the "isolation" is gone.
- **Defense in depth matters even for "internal" workloads.** This container had *four* independent problems;
  fixing only the socket still leaves `--privileged` as a full escape.
- **Secrets management is a container-security problem.** Images and env vars are the two worst places for
  secrets, and both are the default path of least resistance — which is why they're so commonly abused.

**First control across the fleet.** Removing the `docker.sock` mount — nothing else gives that much return. A
mounted socket is a direct path to host root from any container, so banning it fleet-wide (and scanning for it
in CI with the CIS Docker Benchmark / docker-bench-security) closes the worst door everywhere at once. Dropping
`--privileged` is a close second.
