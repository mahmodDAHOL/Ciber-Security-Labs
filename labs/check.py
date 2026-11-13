"""Verify lab answers against the running containers and record progress.

Usage:
    python check.py <lab> <task> "<answer>"    e.g.  python check.py 01 3 "FLAG{web_...}"
    python check.py status
"""
import json
import subprocess
import sys
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).parent
PROGRESS_JSON = ROOT / "progress.json"
PROGRESS_MD = ROOT / "PROGRESS.md"
PROGRESS_JS = ROOT / "progress.js"


def run(container, *cmd):
    """Run a command in a container; a non-zero exit from the command itself is allowed."""
    r = subprocess.run(["docker", "exec", container, *cmd], capture_output=True, text=True)
    if "No such container" in r.stderr or "is not running" in r.stderr:
        sys.exit(f"Could not reach {container}. Is the lab running?")
    return r


def docker_exec(container, *cmd):
    r = run(container, *cmd)
    if r.returncode != 0:
        sys.exit(f"Command failed in {container}: {r.stderr.strip()}")
    return r.stdout.strip()


def flag_in(container, path="/flag"):
    return lambda answer: answer == docker_exec(container, "cat", path)


def fixed(*accepted):
    return lambda answer: answer.lower() in accepted


def intranet_login(password):
    code = docker_exec("lab01-attacker", "curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
                       "-u", f"alice:{password}", "http://10.10.10.50:8080/status")
    return code == "200"


SSH = ["ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=5"]
SRV01 = "deploy@10.10.20.10"


def key_login(_):
    return run("lab02-attacker", *SSH, SRV01, "true").returncode == 0


def password_auth_off(_):
    # Asking for the "none" method makes sshd list the methods it currently accepts
    err = run("lab02-attacker", *SSH, "-o", "PreferredAuthentications=none", SRV01, "true").stderr
    return "Permission denied (" in err and "password" not in err.split("Permission denied (")[1]


def sshd_option(name, ok):
    def check(_):
        opts = dict(line.split(" ", 1) for line in docker_exec("lab02-srv01", "sshd", "-T").splitlines() if " " in line)
        return ok(opts.get(name, ""))
    return check


def sudo_find_removed(_):
    return "find" not in docker_exec("lab02-srv01", "sudo", "-l", "-U", "deploy")


def shadow_private(_):
    return docker_exec("lab02-srv01", "stat", "-c", "%a", "/etc/shadow")[-1] == "0"


import time as _time


def lab04_alerts():
    out = run("lab04-siem", "cat", "/opt/soc/alerts.jsonl").stdout
    alerts = []
    for line in out.splitlines():
        line = line.strip()
        if line:
            try:
                alerts.append(json.loads(line))
            except ValueError:
                pass
    return alerts


def lab04_replay_then(predicate):
    """Replay the intrusion, then check a new custom alert satisfies predicate."""
    marker = run("lab04-siem", "date", "-u", "+%Y-%m-%dT%H:%M:%SZ").stdout.strip()
    run("lab04-attacker", "sh", "/root/attack.sh")
    for _ in range(12):
        _time.sleep(2)
        fresh = [a for a in lab04_alerts()
                 if a.get("source") == "custom" and a.get("detected_at", "") >= marker]
        if any(predicate(a) for a in fresh):
            return True
    return False


def custom_accepted_login(_):
    return lab04_replay_then(lambda a: a.get("event_type") == "accepted_login")


def custom_sudo(_):
    return lab04_replay_then(lambda a: a.get("event_type") == "sudo")


def custom_bruteforce_threshold(_):
    return lab04_replay_then(lambda a: a.get("event_type") == "failed_login"
                             and isinstance(a.get("count"), int) and a["count"] >= 10)


def hash_is(*accepted):
    def check(answer):
        a = answer.lower().replace("-", "").replace(" ", "").replace("_", "")
        return a in accepted
    return check


def lab05_key():
    return json.loads(docker_exec("lab05-evidence", "cat", "/root/.answers.json"))


def lab08_flags():
    return json.loads(docker_exec("lab08-backend", "cat",
                                  "/home/frappe/frappe-bench/sites/frontend/lab08_flags.json"))


def lab08_flag(key):
    return lambda answer: answer.strip() == lab08_flags().get(key, "\x00").strip()


def lab09_ans():
    return json.loads(docker_exec("lab09-dc01", "cat", "/var/lib/samba/.lab09_answers.json"))


def lab09_field(field, ci=False):
    def check(answer):
        want = lab09_ans().get(field, "\x00")
        a, w = answer.strip(), want.strip()
        return a.lower() == w.lower() if ci else a == w
    return check


def lab10_flags():
    return json.loads(docker_exec("lab10-victim", "cat", "/root/.lab10_answers.json"))


def lab10_flag(key):
    return lambda answer: answer.strip() == lab10_flags().get(key, "\x00").strip()


def lab11_ans():
    return json.loads(docker_exec("lab11-scanner", "cat", "/opt/.lab11_answers.json"))


def lab11_secret(key):
    return lambda answer: answer.strip() == lab11_ans().get(key, "\x00").strip()


def key_equals(field):
    def check(answer):
        return answer.strip().lower() == lab05_key()[field].strip().lower()
    return check


def key_path(field):
    # Accept the full path or just the file's basename, with or without a leading slash
    def check(answer):
        want = lab05_key()[field].strip().lower()
        a = answer.strip().lower().lstrip("/")
        return a == want.lstrip("/") or a == want.rsplit("/", 1)[-1]
    return check


# lab id -> (title, roadmap phase, {task id: (description, checker, points)})
LABS = {
    "01": ("Network Recon & Cleartext Protocols", 1, {
        "1": ("Host discovery: number of target hosts", fixed("4"), 1),
        "2": ("Port scan: intranet portal port", fixed("8080", "8080/tcp"), 1),
        "3": ("Web enumeration flag", flag_in("lab01-web"), 2),
        "4": ("Anonymous FTP flag", flag_in("lab01-ftp"), 2),
        "5": ("Sniffed alice's password", intranet_login, 3),
        "6": ("Intranet admin flag", flag_in("lab01-intranet"), 3),
    }),
    "02": ("Linux Server: Break In, Then Harden", 1, {
        "1": ("Brute-forced deploy's SSH password", flag_in("lab02-srv01", "/root/.lab/deploy_pw"), 3),
        "2": ("Privilege escalation: root flag", flag_in("lab02-srv01", "/root/flag.txt"), 3),
        "3": ("Found the world-readable sensitive file", fixed("/etc/shadow"), 1),
        "4": ("Harden: SSH key login works for deploy", key_login, 2),
        "5": ("Harden: SSH password login disabled (live)", password_auth_off, 2),
        "6": ("Harden: root SSH login disabled", sshd_option("permitrootlogin", lambda v: v == "no"), 1),
        "7": ("Harden: MaxAuthTries 3 or less", sshd_option("maxauthtries", lambda v: v.isdigit() and int(v) <= 3), 1),
        "8": ("Harden: dangerous sudo rule removed", sudo_find_removed, 2),
        "9": ("Harden: /etc/shadow not world-readable", shadow_private, 1),
    }),
    "03": ("Cryptography: Hashing, Cracking & TLS/PKI", 1, {
        "1": ("Identify the hash type in hashes.txt ($6$)", hash_is("sha512crypt", "sha512", "crypt"), 1),
        "2": ("Identify a 32-hex-char hash", hash_is("md5"), 1),
        "3": ("Cracked admin's password", flag_in("lab03-intranet", "/root/.lab/admin_pw"), 3),
        "4": ("Cracked svc-backup's password", flag_in("lab03-intranet", "/root/.lab/svc_pw"), 2),
        "5": ("Flag hidden in the intranet's self-signed cert", flag_in("lab03-intranet", "/flag"), 2),
        "6": ("mTLS: client cert signed by the CA, API flag", flag_in("lab03-secure-api", "/flag"), 3),
    }),
    "04": ("Build a SOC: SIEM Detection & Triage", 2, {
        "1": ("Triage: source IP of the brute force", fixed("10.10.40.5"), 1),
        "2": ("Triage: the compromised account", fixed("webadmin"), 2),
        "3": ("ATT&CK technique for SSH brute force", hash_is("t1110", "t1110.001"), 1),
        "4": ("Detection rule fires on a successful SSH login", custom_accepted_login, 3),
        "5": ("Detection rule fires on sudo privilege escalation", custom_sudo, 3),
        "6": ("Your own brute-force threshold rule (>=10 in window)", custom_bruteforce_threshold, 2),
    }),
    "05": ("Threat Hunt: Reconstruct a Web Intrusion", 2, {
        "1": ("Attacker's source IP (recon + exploit)", key_equals("attacker_ip"), 2),
        "2": ("Path of the uploaded web shell", key_path("webshell_path"), 2),
        "3": ("Sensitive file read through the web shell", key_path("secret_file"), 2),
        "4": ("Persistence account the attacker created", key_equals("persist_user"), 2),
        "5": ("Exfiltration destination IP", key_equals("exfil_ip"), 2),
        "6": ("ATT&CK technique for the web shell", hash_is("t1505.003", "t1505"), 1),
        "7": ("ATT&CK technique for data exfiltration", hash_is("t1041"), 1),
    }),
    "06": ("Web App Hacking: OWASP Top 10", 3, {
        "1": ("SQLi auth bypass -> admin flag", flag_in("lab06-web", "/srv/flags/sqli_login.txt"), 2),
        "2": ("SQLi UNION -> secret flag from DB", flag_in("lab06-web", "/srv/flags/sqli_union.txt"), 3),
        "3": ("Broken access control (IDOR) -> other user's flag", flag_in("lab06-web", "/srv/flags/idor.txt"), 2),
        "4": ("OS command injection -> flag", flag_in("lab06-web", "/srv/flags/cmdinj.txt"), 3),
        "5": ("Path traversal -> flag", flag_in("lab06-web", "/srv/flags/lfi.txt"), 1),
        "6": ("OWASP Top 10 2021 category for injection", hash_is("a03", "a032021", "a03:2021"), 1),
    }),
    "07": ("Linux Privilege Escalation", 3, {
        "1": ("Enumerate: the odd-one-out SUID binary", fixed("/usr/bin/find", "find", "/bin/find"), 1),
        "2": ("SUID privesc -> root flag", flag_in("lab07-target", "/root/flags/suid.txt"), 3),
        "3": ("sudo (GTFOBins) privesc -> root flag", flag_in("lab07-target", "/root/flags/sudo.txt"), 3),
        "4": ("Cron world-writable script -> root flag", flag_in("lab07-target", "/root/flags/cron.txt"), 3),
        "5": ("Linux capability (cap_setuid) -> root flag", flag_in("lab07-target", "/root/flags/caps.txt"), 3),
        "6": ("ATT&CK technique for SUID/SGID abuse", hash_is("t1548.001", "t1548001"), 1),
    }),
    "08": ("ERPNext / Frappe Penetration Test", 3, {
        "1": ("Recon: ERPNext version", fixed("16.54.0", "16.54", "16"), 2),
        "2": ("Default admin credentials -> admin secret flag", lab08_flag("admin"), 3),
        "3": ("Unauthenticated guest Server Script -> flag", lab08_flag("guest"), 2),
        "4": ("SQL injection in guest Server Script -> flag", lab08_flag("sqli"), 3),
        "5": ("Broken object-level auth (IDOR) via REST -> flag", lab08_flag("bola"), 3),
        "6": ("OWASP API Top 10 (2023) category for BOLA", hash_is("api1", "api1:2023", "api12023", "api012023"), 1),
    }),
    "09": ("Active Directory: Enumeration, Spraying & Initial Access", 4, {
        "1": ("Unauth enumeration: the service account's username", lab09_field("svc_user", ci=True), 2),
        "2": ("Password spraying: the user with the weak reused password", lab09_field("spray_user", ci=True), 3),
        "3": ("SMB share loot with recovered creds -> flag", lab09_field("loot_flag"), 3),
        "4": ("Secret stashed in an LDAP description attribute -> flag", lab09_field("desc_flag"), 3),
        "5": ("Attack-path recon: the AS-REP-roastable user", lab09_field("asrep_user", ci=True), 2),
        "6": ("ATT&CK sub-technique for Password Spraying", hash_is("t1110.003", "t1110003", "t1110"), 1),
    }),
    "10": ("Container Escape & Security", 5, {
        "1": ("Recon: the critical host mount inside the container", fixed("/var/run/docker.sock", "docker.sock", "/run/docker.sock", "var/run/docker.sock"), 2),
        "2": ("Docker-socket escape to the host filesystem -> flag", lab10_flag("host_flag"), 5),
        "3": ("Exposed secret in a container config file -> flag", lab10_flag("config_flag"), 2),
        "4": ("Exposed secret in an environment variable -> flag", lab10_flag("env_flag"), 2),
        "5": ("The run flag that gives the container full host privileges", fixed("privileged", "--privileged", "privileged mode"), 2),
        "6": ("ATT&CK technique for Escape to Host", hash_is("t1611"), 1),
    }),
    "11": ("DevSecOps: SAST, Secret Scanning & Dependency Analysis", 6, {
        "1": ("SAST: Bandit test ID for the subprocess shell=True call", fixed("b602", "b605"), 2),
        "2": ("Hardcoded secret in the current source code", lab11_secret("code_secret"), 3),
        "3": ("Secret removed from code but still in git history", lab11_secret("history_secret"), 3),
        "4": ("Vulnerable dependency behind the unsafe yaml.load", fixed("pyyaml", "py-yaml", "pyyaml==5.1"), 3),
        "5": ("Manual review: the insecure deserialization vuln (function/CWE)", hash_is("pickle", "pickleloads", "deserialization", "insecuredeserialization", "cwe502"), 2),
        "6": ("What does SAST stand for?", hash_is("staticapplicationsecuritytesting", "sast"), 1),
    }),
}

# Roadmap tracker task ids (p<phase index>t<task index>, 0-based) ticked when a lab is fully solved
ROADMAP = {
    "02": ["p0t7"],  # Phase 1: Harden a Linux server
    "03": ["p0t4"],  # Phase 1: Cryptography (hashing, PKI, certificates)
    "04": ["p1t0", "p1t1"],  # Phase 2: log sources + ATT&CK/Kill Chain frameworks
    "05": ["p1t5"],  # Phase 2: Incident response lifecycle / triage
    "06": ["p2t2"],  # Phase 3: OWASP Top 10
    "07": ["p2t5"],  # Phase 3: Linux & Windows privilege escalation
    "08": ["p2t7"],  # Phase 3: Pentest a local ERPNext/Frappe instance (project)
    "09": ["p3t1"],  # Phase 4: Build & attack a vulnerable AD lab
    "10": ["p4t3"],  # Phase 5: Docker security (capabilities, escapes, CIS)
    "11": ["p5t1", "p5t3"],  # Phase 6: SAST (Bandit) + supply chain (gitleaks, pip-audit)
}


def load():
    if PROGRESS_JSON.exists():
        return json.loads(PROGRESS_JSON.read_text())
    return {"solved": {}, "attempts": {}}


def write_md(p):
    lines = ["# Lab Progress", "", "_Generated by check.py. Do not edit by hand._", ""]
    total = got = 0
    labs_js, roadmap = [], []
    for lab_id, (title, phase, tasks) in LABS.items():
        solved = p["solved"].get(lab_id, {})
        pts = sum(t[2] for t in tasks.values())
        have = sum(tasks[k][2] for k in solved if k in tasks)
        total, got = total + pts, got + have
        labs_js.append({"id": lab_id, "title": title, "phase": phase, "score": have, "max": pts,
                        "done": len(solved), "tasks": len(tasks),
                        "last": max(solved.values()) if solved else None})
        if len(solved) == len(tasks):
            roadmap += ROADMAP.get(lab_id, [])
        lines += [f"## Lab {lab_id}: {title} (Roadmap phase {phase})",
                  f"Score: **{have}/{pts}** · {len(solved)}/{len(tasks)} tasks", "",
                  "| Task | Description | Points | Solved |", "|---|---|---|---|"]
        for k, (desc, _, pt) in tasks.items():
            when = solved.get(k)
            lines.append(f"| {k} | {desc} | {pt} | {'✅ ' + when if when else '⬜'} |")
        lines.append("")
    lines.insert(3, f"**Total: {got}/{total} points**\n")
    PROGRESS_MD.write_text("\n".join(lines), encoding="utf-8")
    # Loaded by ../cybersecurity-roadmap.html via <script>, which works from file:// where fetch() doesn't
    data = {"labs": labs_js, "score": got, "max": total, "roadmap": roadmap,
            "updated": datetime.now().strftime("%Y-%m-%d %H:%M")}
    PROGRESS_JS.write_text(f"window.LAB_PROGRESS = {json.dumps(data, indent=2)};\n", encoding="utf-8")


def main():
    sys.stdout.reconfigure(encoding="utf-8")
    p = load()
    if len(sys.argv) == 2 and sys.argv[1] == "status":
        write_md(p)
        print(PROGRESS_MD.read_text(encoding="utf-8"))
        return
    if len(sys.argv) != 4:
        sys.exit(__doc__)
    lab_id, task, answer = sys.argv[1].zfill(2), sys.argv[2], sys.argv[3].strip()
    if lab_id not in LABS or task not in LABS[lab_id][2]:
        sys.exit(f"Unknown lab/task: {lab_id}/{task}")
    desc, check, pts = LABS[lab_id][2][task]
    key = f"{lab_id}.{task}"
    p["attempts"][key] = p["attempts"].get(key, 0) + 1
    if check(answer):
        p["solved"].setdefault(lab_id, {}).setdefault(task, datetime.now().strftime("%Y-%m-%d %H:%M"))
        print(f"CORRECT: Lab {lab_id} task {task} ({desc}), +{pts} pts")
    else:
        print(f"WRONG: Lab {lab_id} task {task}. Attempts so far: {p['attempts'][key]}")
    PROGRESS_JSON.write_text(json.dumps(p, indent=2))
    write_md(p)


if __name__ == "__main__":
    main()
